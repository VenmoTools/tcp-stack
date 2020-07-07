extern crate tcp_stack;

use std::collections::HashMap;
use std::env;

use tun_tap::{self, Iface};

use tcp_stack::meta::{ETHERNET_MTU, TUN_SIZE};
use tcp_stack::reader_writer::{Quad, RawReader};
use tcp_stack::result;
use tcp_stack::tcp::connection::TcpConnection;

fn main() -> result::Result<()> {
    env::set_var("RUST_LOG", "debug");
    tcp_stack::init_log();
    // let mut status: HashMap<Quad, TcpConnection> = HashMap::new();
    // do we need IFF_NO_PI?
    let mut iface = Iface::new("tcp0", tun_tap::Mode::Tun)?;
    // MTU 1500
    let mut mtu_buf = [0_u8; ETHERNET_MTU];
    loop {
        let n = iface.recv(&mut mtu_buf)?;
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/tuntap.rst
        // check tuntap.rst 3.2 Frame format
        let mut raw = RawReader::from_slice(&mtu_buf, n, TUN_SIZE);
        if !raw.is_ipv4_packet() {
            continue;
        }
        let (ip_header, tcp_header) = match raw.tcp_ip_header() {
            Ok((ip, tcp)) => { (ip, tcp) }
            Err(e) => {
                println!("{:?}", e);
                continue;
            }
        };
        let buf = &mtu_buf[TUN_SIZE + ip_header.slice().len() + tcp_header.slice().len()..n];
        TcpConnection::accept(&mut iface, &ip_header, &tcp_header, buf)?;
        // let quad = Quad::from_tcpip_header(&ip_header, &tcp_header);
    }
}


pub fn handle_connection() {}