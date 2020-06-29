extern crate tcp_stack;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use tun_tap::{self, Iface};

use tcp_stack::net_types::EtherType;
use tcp_stack::tcp::connection::TcpConnection;

pub const TUN_SIZE: usize = 4;
// is a MTU of the interface (usually 1500, unless reconfigured) + 4 for the header in case that packet info is prepended
pub const MUT_SIZE: usize = 1500 + TUN_SIZE;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Quad {
    src: Addr,
    dest: Addr,
}

impl Quad {
    pub fn new(src: Addr, dest: Addr) -> Self {
        Self {
            src,
            dest,
        }
    }
}


#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Addr {
    ip: Ipv4Addr,
    port: u16,
}

impl Addr {
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
        }
    }
}


fn main() -> tcp_stack::result::Result<()> {
    let mut status: HashMap<Quad, TcpConnection> = HashMap::new();

    let mut iface = Iface::new("tcp0", tun_tap::Mode::Tun)?;
    // MTU 1500
    let mut mtu_buf = [0_u8; MUT_SIZE];
    loop {
        let n = iface.recv(&mut mtu_buf)?;
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/tuntap.rst
        // check tuntap.rst 3.2 Frame format
        let flags = u16::from_be_bytes([mtu_buf[0], mtu_buf[1]]);
        // ether type
        let proto = EtherType::from([mtu_buf[2], mtu_buf[3]]);
        if proto != EtherType::IPv4 {
            continue;
        }
        let ip_header = Ipv4HeaderSlice::from_slice(&mtu_buf[TUN_SIZE..n])?;
        let iph_len = ip_header.slice().len();
        let tcp_header = TcpHeaderSlice::from_slice(&mtu_buf[TUN_SIZE + iph_len..])?;
        let tcph_len = tcp_header.slice().len();
        let data_index = TUN_SIZE + iph_len + tcph_len;
        let quad = Quad::new(
            Addr::new(ip_header.source_addr(), tcp_header.source_port()),
            Addr::new(ip_header.destination_addr(), tcp_header.destination_port()),
        );
        status
            .entry(quad);
        //todo:
        // .or_default()
        // .packet(&mut iface, &ip_header, &tcp_header, &mtu_buf[data_index..n])?;
    }
}

pub fn handle_connection() {}