use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::time::{Duration, Instant};
use std::vec;

use futures::{Future, Stream, StreamExt};
use parking_lot::RwLock;
use priority_queue::PriorityQueue;
use simple_dns::{Name, Packet, Question, CLASS, TYPE};
use tokio::net::UdpSocket;
use tokio::select;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;

const QUERY_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Service {
    /// Instance name e.g. MacBouk Pro._sam-server._tcp.local
    pub instance_name: String,

    /// Service name e.g. _sam-server._tcp.local
    pub service_name: String,

    /// Hostname e.g. MacBouk-Pro.local
    pub hostname: String,

    /// Port
    pub port: u16,

    /// Resolved addresses for hostname
    pub addresses: Vec<IpAddr>,

    /// TXT record
    pub metadata: HashMap<String, Option<String>>,
}

impl Service {
    /// Friendly instance name e.g. MacBouk Pro
    pub fn user_friendly_name(&self) -> &str {
        &self
            .instance_name
            .split_once('.')
            .map(|(name, _)| name)
            .unwrap_or(&self.instance_name)
    }
}

impl ToSocketAddrs for Service {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let addr: Vec<_> = self
            .addresses
            .iter()
            .map(|addr| SocketAddr::new(*addr, self.port))
            .collect();

        Ok(addr.into_iter())
    }
}

struct Subscription<'a, Fut, F> {
    browser: &'a Browser,
    service_name: String,
    stream: futures::stream::Chain<
        futures::stream::Iter<vec::IntoIter<Change>>,
        futures::stream::FilterMap<tokio_stream::wrappers::BroadcastStream<Change>, Fut, F>,
    >,
}

impl<'a, Fut, F> Drop for Subscription<'a, Fut, F> {
    fn drop(&mut self) {
        let mut inner = self.browser.inner.write();
        let entry = inner
            .active_queries
            .get_mut(&self.service_name)
            .expect("Needs to be at least one (this subscription)");
        *entry -= 1;
        if *entry == 0 {
            inner.active_queries.remove(&self.service_name);
            inner
                .query_queue
                .remove(&self.service_name)
                .expect("Should've been in the queue");
        }
    }
}

impl<'a, Fut, F> Stream for Subscription<'a, Fut, F>
where
    F: FnMut(Result<Change, BroadcastStreamRecvError>) -> Fut,
    Fut: Future<Output = Option<Change>> + std::marker::Unpin,
{
    type Item = Change;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Change {
    Added(Service),
    Removed(Service),
    Updated(Service),
}

impl Change {
    pub fn service(&self) -> &Service {
        match self {
            Change::Added(service) => &service,
            Change::Removed(service) => &service,
            Change::Updated(service) => &service,
        }
    }
}

pub struct Browser {
    notify: tokio::sync::Notify,
    inner: RwLock<InnerBrowser>,
}

impl Browser {
    pub fn new() -> Self {
        Browser {
            notify: tokio::sync::Notify::new(),
            inner: RwLock::new(InnerBrowser::new()),
        }
    }

    pub fn subscribe(&self, service_name: impl Into<String>) -> impl Stream<Item = Change> + '_ {
        let service_name = service_name.into();
        let mut inner = self.inner.write();
        let services: Vec<_> = inner
            .services_by_name(service_name.clone())
            .map(Change::Added)
            .collect();
        let amount = inner.active_queries.entry(service_name.clone()).or_default();
        *amount += 1;
        if *amount == 1 {
            inner.query_queue.push(service_name.clone(), Reverse(Instant::now()));
            self.notify.notify_one();
        }

        let service_name2 = service_name.clone();
        let broadcast = BroadcastStream::new(inner.sender.subscribe()).filter_map(move |r| {
            futures::future::ready(match r {
                Ok(change) =>
                    if change.service().service_name == service_name2 {
                        Some(change)
                    } else {
                        None
                    },
                Err(_) => None,
            })
        });
        Subscription {
            browser: self,
            service_name,
            stream: futures::stream::iter(services.into_iter()).chain(broadcast),
        }
    }

    /// Returns a stream of all changes observed
    pub fn firehose(&self) -> impl Stream<Item = Change> {
        self.inner.read().subscribe()
    }

    pub async fn listen(&self, socket: &UdpSocket, target: SocketAddr) -> std::io::Result<()> {
        let mut buf = [0u8; 9000];
        loop {
            let next_deadline;
            let next_query;
            {
                let inner = self.inner.read();

                next_deadline = inner
                    .deadline_queue
                    .peek()
                    .map(|(_, deadline)| deadline.0)
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

                next_query = inner
                    .query_queue
                    .peek()
                    .map(|(_, deadline)| deadline.0)
                    .unwrap_or_else(|| Instant::now() + QUERY_INTERVAL);
            }

            select! {
                _ = tokio::time::sleep_until(next_deadline.into()) => {
                    self.inner.write().flush_deadlines(Instant::now());
                }
                _ = tokio::time::sleep_until(next_query.into()) => {
                    self.inner.write().run_queries(Instant::now(), socket, target).await;
                }
                res = socket.recv_from(&mut buf) => {
                    let (len, _addr) = res?;
                    // We just ignore invalid packets
                    let Ok(packet) = Packet::parse(&buf[..len]) else { continue; };
                    self.inner.write().handle_packet(packet);
                }

                // Notify is used to wake up the loop when a new subscription is added
                _ = self.notify.notified() => {}
            }
        }
    }
}

struct ServiceInfo {
    deadline: Instant,
}

#[derive(Clone, Debug)]
struct InstanceInfo {
    hostname: String,
    port: u16,
    deadline: Instant,
    metadata: HashMap<String, Option<String>>,
}

struct AddressInfo {
    received: Instant,
    deadline: Instant,
}

#[derive(Hash, PartialEq, Eq)]
enum DeadlineItem {
    Service(String, String),
    Instance(String),
    Address(String, IpAddr),
}

struct InnerBrowser {
    /// Mapping of service name to instance names with associated deadlines
    /// Corresponds to PTR records
    services: HashMap<String, HashMap<String, ServiceInfo>>,

    /// Mapping of instance name to services
    services_by_instance: HashMap<String, HashSet<String>>,

    /// Mapping of instance name to Service
    /// Corresponds to SRV records
    instances: HashMap<String, InstanceInfo>,

    /// Mapping of hostname to instances
    instances_by_hostname: HashMap<String, HashSet<String>>,

    /// Mapping of hostname to addresses
    addresses_by_hostname: HashMap<String, BTreeMap<IpAddr, AddressInfo>>,

    /// Mapping of active queries to the number of times they've been requested
    active_queries: HashMap<String, usize>,

    /// Queue of items that need to be removed at a certain deadline
    deadline_queue: PriorityQueue<DeadlineItem, Reverse<Instant>>,

    /// Queue of queries
    query_queue: PriorityQueue<String, Reverse<Instant>>,

    /// Broadcast sender for changes
    sender: tokio::sync::broadcast::Sender<Change>,
}

impl InnerBrowser {
    fn new() -> Self {
        InnerBrowser {
            services: HashMap::new(),
            services_by_instance: HashMap::new(),
            instances: HashMap::new(),
            instances_by_hostname: HashMap::new(),
            addresses_by_hostname: HashMap::new(),
            active_queries: HashMap::new(),
            deadline_queue: PriorityQueue::new(),
            query_queue: PriorityQueue::new(),
            sender: tokio::sync::broadcast::Sender::new(16),
        }
    }

    fn handle_packet(&mut self, packet: Packet<'_>) {
        // This is the 'meat': one mega state processing machine
        let now = Instant::now();

        // TODO: would be nice if these could be re-used but then handle_packet would need to store that in self or something?
        let mut new_service_instance = HashSet::new(); // tuple of (service name, instance name)
        let mut updated_instances = HashSet::new();
        let mut new_instances = HashSet::new();
        let mut updated_hostnames = HashSet::new();
        for answer in packet.answers.into_iter().chain(packet.additional_records) {
            // RFC6762 8.4
            // Queriers receiving a Multicast DNS response with a TTL of zero SHOULD NOT immediately delete the record from the cache, but instead record a TTL of 1 and then delete the record one second later.
            // BUT we must make sure not to insert a new record if we receive a TTL 0 zero and we've already deleted it
            let delete = answer.ttl == 0;
            let deadline = if delete {
                now + Duration::from_secs(1)
            } else {
                now + Duration::from_secs(answer.ttl as u64)
            };

            use simple_dns::rdata::RData::*;
            match answer.rdata {
                SRV(srv) => {
                    use std::collections::hash_map::Entry;
                    let instance_name = answer.name.to_string();
                    let hostname = srv.target.to_string();
                    match self.instances.entry(instance_name.clone()) {
                        Entry::Occupied(entry) => {
                            let i = entry.into_mut();
                            let mut updated = false;
                            if i.hostname != hostname {
                                // This is because TXT records also insert into instances with an empty hostname
                                self.instances_by_hostname
                                    .get_mut(&i.hostname)
                                    .expect("Should have existing hostname")
                                    .remove(&instance_name);
                                // Would be weird to have an empty target but just a safeguard for the above case
                                self.instances_by_hostname
                                    .entry(hostname.clone())
                                    .or_default()
                                    .insert(instance_name.clone());
                                i.hostname = hostname;
                                updated = true
                            }
                            if i.port != srv.port {
                                i.port = srv.port;
                                updated = true
                            }
                            i.deadline = deadline;
                            self.push_deadline(DeadlineItem::Instance(instance_name.clone()), deadline);
                            if updated {
                                updated_instances.insert(instance_name);
                            }
                        }
                        Entry::Vacant(entry) => {
                            if delete {
                                continue;
                            }
                            entry.insert(InstanceInfo {
                                hostname: hostname.clone(),
                                port: srv.port,
                                deadline,
                                metadata: HashMap::new(),
                            });
                            self.push_deadline(DeadlineItem::Instance(instance_name.clone()), deadline);

                            self.instances_by_hostname
                                .entry(hostname.clone())
                                .or_default()
                                .insert(instance_name.clone());
                            new_instances.insert(instance_name);
                        }
                    }
                }
                PTR(ptr) => {
                    let service_name = answer.name.to_string();
                    let instance_name = ptr.0.to_string();
                    use std::collections::hash_map::Entry;
                    match self
                        .services
                        .entry(service_name.clone())
                        .or_default()
                        .entry(instance_name.clone())
                    {
                        Entry::Occupied(entry) => {
                            let entry = entry.into_mut();
                            entry.deadline = deadline;
                            self.push_deadline(
                                DeadlineItem::Service(service_name.clone(), instance_name.clone()),
                                deadline,
                            );
                        }
                        Entry::Vacant(entry) => {
                            if delete {
                                continue;
                            }

                            entry.insert(ServiceInfo { deadline });
                            self.push_deadline(
                                DeadlineItem::Service(service_name.clone(), instance_name.clone()),
                                deadline,
                            );
                            self.services_by_instance
                                .entry(instance_name.clone())
                                .or_default()
                                .insert(service_name.clone());
                            new_service_instance.insert((service_name, instance_name));
                        }
                    }
                }
                TXT(txt) => {
                    use std::collections::hash_map::Entry;
                    let instance_name = answer.name.to_string();
                    match self.instances.entry(instance_name.clone()) {
                        Entry::Occupied(entry) => {
                            let entry = entry.into_mut();
                            let attr = txt.attributes();
                            if attr != entry.metadata {
                                entry.metadata = attr;
                                updated_instances.insert(instance_name.clone());
                            }
                            entry.deadline = deadline;
                            self.push_deadline(DeadlineItem::Instance(instance_name), deadline);
                        }
                        Entry::Vacant(entry) => {
                            if delete {
                                continue;
                            }

                            entry.insert(InstanceInfo {
                                hostname: String::new(),
                                port: 0,
                                deadline,
                                metadata: txt.attributes(),
                            });
                            self.instances_by_hostname
                                .entry(String::new())
                                .or_default()
                                .insert(instance_name.clone());
                            self.push_deadline(DeadlineItem::Instance(instance_name.clone()), deadline);
                            new_instances.insert(instance_name);
                        }
                    }
                }
                A(a) => {
                    use std::collections::btree_map::Entry;
                    let ip = IpAddr::V4(a.address.into());
                    let hostname = answer.name.to_string();
                    match self
                        .addresses_by_hostname
                        .entry(hostname.clone())
                        .or_default()
                        .entry(ip)
                    {
                        Entry::Occupied(entry) => {
                            let entry = entry.into_mut();
                            entry.received = now;
                            entry.deadline = deadline;
                            self.push_deadline(DeadlineItem::Address(hostname.clone(), ip), deadline);
                        }
                        Entry::Vacant(entry) => {
                            if delete {
                                continue;
                            }
                            entry.insert(AddressInfo {
                                received: now,
                                deadline,
                            });
                            self.push_deadline(DeadlineItem::Address(hostname.clone(), ip), deadline);
                            updated_hostnames.insert(hostname.clone());
                        }
                    }
                    if answer.cache_flush {
                        self.flush_addresses(now, &hostname);
                    }
                }
                AAAA(aaaa) => {
                    use std::collections::btree_map::Entry;
                    let ip = IpAddr::V6(aaaa.address.into());
                    let hostname = answer.name.to_string();
                    match self
                        .addresses_by_hostname
                        .entry(hostname.clone())
                        .or_default()
                        .entry(ip)
                    {
                        Entry::Occupied(entry) => {
                            let entry = entry.into_mut();
                            entry.received = now;
                            entry.deadline = deadline;
                            self.push_deadline(DeadlineItem::Address(hostname.clone(), ip), deadline);
                        }
                        Entry::Vacant(entry) => {
                            if delete {
                                continue;
                            }
                            entry.insert(AddressInfo {
                                received: now,
                                deadline,
                            });
                            self.push_deadline(DeadlineItem::Address(hostname.clone(), ip), deadline);
                            updated_hostnames.insert(hostname.clone());
                        }
                    }
                    if answer.cache_flush {
                        self.flush_addresses(now, &hostname);
                    }
                }
                _ => {}
            }
        }

        for hostname in updated_hostnames.drain() {
            if let Some(instances) = self.instances_by_hostname.get(&hostname) {
                for instance in instances.iter() {
                    updated_instances.insert(instance.clone());
                }
            }
        }

        for instance_name in new_instances.drain() {
            updated_instances.remove(&instance_name);
            let Some(services) = self.services_by_instance.get(&instance_name) else { continue; };
            let Some(instance) = self.instances.get(&instance_name) else { continue; };
            debug_assert!(instance.deadline > now);

            for service_name in services.iter() {
                // TODO: this clone seems unneeded
                new_service_instance.remove(&(service_name.clone(), instance_name.clone()));
                // Could add an expect() here
                let Some(service_deadline) = self.services.get(service_name).and_then(|m| m.get(&instance_name)) else { continue; };
                if service_deadline.deadline < now {
                    continue;
                }

                let service = self.build_service(service_name, instance_name.clone(), instance.clone());

                _ = self.sender.send(Change::Added(service));
            }
        }

        for (service_name, instance_name) in new_service_instance.drain() {
            updated_instances.remove(&instance_name);
            let Some(instance) = self.instances.get(&instance_name) else { continue; };
            if instance.deadline < now {
                continue;
            }

            // Could add an expect() here
            let Some(service_deadline) = self.services.get(&service_name).and_then(|m| m.get(&instance_name)) else { continue; };
            if service_deadline.deadline < now {
                continue;
            }

            let service = self.build_service(service_name, instance_name, instance.clone());

            _ = self.sender.send(Change::Added(service));
        }

        for instance_name in updated_instances.drain() {
            let Some(services) = self.services_by_instance.get(&instance_name) else { continue; };
            let Some(instance) = self.instances.get(&instance_name) else { continue; };
            if instance.deadline < now {
                continue;
            }

            for service_name in services.iter() {
                // Could add an expect() here
                let Some(service_deadline) = self.services.get(service_name).and_then(|m| m.get(&instance_name)) else { continue; };
                if service_deadline.deadline < now {
                    continue;
                }

                let service = self.build_service(service_name, instance_name.clone(), instance.clone());

                _ = self.sender.send(Change::Updated(service));
            }
        }
    }

    fn addresses_by_hostname(&self, hostname: &str) -> impl Iterator<Item = IpAddr> + '_ {
        self.addresses_by_hostname.get(hostname).into_iter().flat_map(|m| {
            m.iter()
                .filter(|(_, info)| info.deadline > Instant::now())
                .map(|(ip, _)| *ip)
        })
    }

    fn flush_addresses(&mut self, now: Instant, hostname: &str) {
        let Some(addresses) = self.addresses_by_hostname.get_mut(hostname) else { return; };
        // https://datatracker.ietf.org/doc/html/rfc6762#section-14
        let one_second_ago = now - Duration::from_secs(1);
        let one_second_from_now = now + Duration::from_secs(1);
        for (ip, info) in addresses.iter_mut() {
            if info.received >= one_second_ago || info.deadline <= one_second_from_now {
                continue;
            }
            info.deadline = one_second_from_now;
            self.deadline_queue
                .push(DeadlineItem::Address(hostname.to_string(), *ip), Reverse(info.deadline));
        }
    }

    fn flush_deadlines(&mut self, now: Instant) {
        while let Some((_, deadline)) = self.deadline_queue.peek() {
            if deadline.0 >= now {
                break;
            }

            let (item, Reverse(deadline)) = self.deadline_queue.pop().unwrap();
            match item {
                DeadlineItem::Service(service_name, instance_name) => {
                    let instances = self.services.get_mut(&service_name).expect("Should have services");
                    let info = instances.remove(&instance_name).expect("Should have service instance");
                    if instances.is_empty() {
                        self.services.remove(&service_name);
                    }

                    debug_assert_eq!(info.deadline, deadline);

                    let services = self
                        .services_by_instance
                        .get_mut(&instance_name)
                        .expect("Should have instance");
                    services.remove(&service_name);
                    if services.is_empty() {
                        self.services_by_instance.remove(&instance_name);
                    }

                    if let Some(instance) = self.instances.get(&instance_name) {
                        let service = self.build_service(service_name, instance_name, instance.clone());
                        _ = self.sender.send(Change::Removed(service));
                    }
                }
                DeadlineItem::Instance(instance_name) => {
                    let info = self.instances.remove(&instance_name).expect("Should have instance");
                    debug_assert_eq!(info.deadline, deadline);
                    let instances = self
                        .instances_by_hostname
                        .get_mut(&info.hostname)
                        .expect("Should have instance by hostname");
                    instances.remove(&instance_name);
                    if instances.is_empty() {
                        self.instances_by_hostname.remove(&info.hostname);
                    }

                    for service_name in self
                        .services_by_instance
                        .get(&instance_name)
                        .into_iter()
                        .flat_map(|i| i.iter())
                    {
                        let service = self.build_service(service_name, instance_name.clone(), info.clone());
                        _ = self.sender.send(Change::Removed(service));
                    }
                }
                DeadlineItem::Address(hostname, ip) => {
                    let addresses = self
                        .addresses_by_hostname
                        .get_mut(&hostname)
                        .expect("Should have hostname");
                    let info = addresses.remove(&ip).expect("Should have address");
                    debug_assert_eq!(info.deadline, deadline);
                    if addresses.is_empty() {
                        self.addresses_by_hostname.remove(&hostname);
                    }
                    for instance in self
                        .instances_by_hostname
                        .get(&hostname)
                        .into_iter()
                        .flat_map(|i| i.iter())
                    {
                        let Some(instance_info) = self.instances.get(instance) else { continue; };
                        for service_name in self
                            .services_by_instance
                            .get(instance)
                            .into_iter()
                            .flat_map(|i| i.iter())
                        {
                            let service = self.build_service(service_name, instance.clone(), instance_info.clone());
                            _ = self.sender.send(Change::Updated(service));
                        }
                    }
                }
            }
        }
    }

    async fn run_queries(&mut self, now: Instant, socket: &UdpSocket, target: SocketAddr) {
        while let Some((_, deadline)) = self.query_queue.peek() {
            if deadline.0 > now {
                break;
            }

            let (service_name, _) = self.query_queue.pop().unwrap();

            let mut packet = Packet::new_query(0);
            packet.questions.push(Question::new(
                Name::new_unchecked(&service_name),
                TYPE::PTR.into(),
                CLASS::IN.into(),
                false,
            ));
            let ptr_packet = packet.build_bytes_vec_compressed().unwrap();

            _ = socket.send_to(&ptr_packet, target).await;
            self.query_queue.push(service_name, Reverse(now + QUERY_INTERVAL));
        }
    }

    fn services_by_name(&self, service_name: impl Into<String>) -> impl Iterator<Item = Service> + '_ {
        let now = Instant::now();
        let service_name = service_name.into();
        self.services
            .get(&service_name)
            .into_iter()
            .flat_map(|m| m.iter())
            .filter(move |(_, info)| info.deadline >= now)
            .flat_map(move |(instance_name, info)| {
                if info.deadline < now {
                    return None;
                }

                let instance = self.instances.get(instance_name).expect("Should have instance");
                Some(self.build_service(&service_name, instance_name.clone(), instance.clone()))
            })
    }

    fn build_service(
        &self,
        service_name: impl Into<String>,
        instance_name: impl Into<String>,
        instance_info: InstanceInfo,
    ) -> Service {
        Service {
            instance_name: instance_name.into(),
            service_name: service_name.into(),
            port: instance_info.port,
            addresses: self.addresses_by_hostname(&instance_info.hostname).collect(),
            hostname: instance_info.hostname,
            metadata: instance_info.metadata,
        }
    }

    fn push_deadline(&mut self, item: DeadlineItem, deadline: Instant) {
        self.deadline_queue.push(item, Reverse(deadline));
    }

    fn subscribe(&self) -> impl Stream<Item = Change> {
        BroadcastStream::new(self.sender.subscribe()).filter_map(|r| futures::future::ready(r.ok()))
    }
}
