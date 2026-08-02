use crate::Result;

#[cfg(unix)]
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

#[cfg(unix)]
const RTMGRP_LINK: u32 = 1;
#[cfg(unix)]
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
#[cfg(unix)]
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
#[cfg(unix)]
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
#[cfg(unix)]
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

pub(super) struct RouteEventSocket {
    #[cfg(unix)]
    socket: Socket,
    #[cfg(unix)]
    buffer: Vec<u8>,
}

#[cfg(unix)]
pub(super) fn open_route_event_socket() -> Result<RouteEventSocket> {
    let mut socket = Socket::new(NETLINK_ROUTE)
        .map_err(|err| format!("open route netlink socket failed: {err}"))?;
    let groups = RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV6_ROUTE;
    socket
        .bind(&SocketAddr::new(0, groups))
        .map_err(|err| format!("bind route netlink socket failed: {err}"))?;
    Ok(RouteEventSocket {
        socket,
        buffer: Vec::with_capacity(32 * 1024),
    })
}

#[cfg(not(unix))]
pub(super) fn open_route_event_socket() -> Result<RouteEventSocket> {
    Err("route netlink monitoring requires a Unix-like target".to_string())
}

#[cfg(unix)]
pub(super) fn wait_for_route_event(socket: &mut RouteEventSocket) -> Result<()> {
    socket.buffer.clear();
    socket
        .socket
        .recv_from(&mut socket.buffer, 0)
        .map(|_| ())
        .map_err(|err| format!("read route netlink event failed: {err}"))
}

#[cfg(not(unix))]
pub(super) fn wait_for_route_event(_socket: &mut RouteEventSocket) -> Result<()> {
    Err("route netlink monitoring requires a Unix-like target".to_string())
}
