use dns_sd_browser::Browser;
use futures::{FutureExt, StreamExt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const MDNS_PORT: u16 = 5353;
const MDNS_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_SOCKET_ADDR_IPV4: SocketAddr = SocketAddr::new(IpAddr::V4(MDNS_ADDR_IPV4), MDNS_PORT);
// const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    socket.join_multicast_v4(&MDNS_ADDR_IPV4, &Ipv4Addr::UNSPECIFIED)?;
    socket.bind(&SockAddr::from(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        MDNS_PORT,
    )))?;
    socket.set_nonblocking(true)?;

    let socket = UdpSocket::from_std(socket.into())?;

    let browser = Browser::new();
    let f2 = browser.listen(&socket, MDNS_SOCKET_ADDR_IPV4);
    let f3 = browser
        .subscribe("_sonos._tcp.local")
        .for_each(|change| {
            println!("Sonos: {:?}", change);
            futures::future::ready(())
        })
        .map(Ok);
    futures::try_join!(f2, f3).map(|_| ())
}
