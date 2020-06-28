use std::io;

pub const TIME_TO_LIVE: u8 = 64;


#[derive(Default)]
pub enum TcpState {
	Closed,
	Listen,
	//SynReceived,
	//SynSent,
	//Established,
}

impl Default for TcpState {
	fn default() -> Self {
		TcpState::Listen
	}
}

impl TcpState {
	pub fn packet<'a>(
		&mut self,
		iface: &mut tun_tap::Iface,
		ip: &'a etherparse::Ipv4HeaderSlice<'a>,
		tcp: &'a etherparse::TcpHeaderSlice<'a>,
		data: &'a [u8]
	) -> io::Result<usize> {
		use TcpState::*;
		let mut resp_data = [0_u8; 1500];
		match self {
			Closed => {
				return Ok(0);
			}
			Listen => {
				// only accepted SYN packet
				if !tcp.syn() {
					return Ok(0);
				}

				// send response
				let mut resp_header = etherparse::TcpHeader::new(
					tcp.destination_port(),
					tcp.source_port(),
					1, 0
				);
				// recv SYN snd SYN,ACK
				resp_header.syn = true;
				resp_header.ack = true;
				let resp_ip = etherparse::Ipv4Header::new(
					resp_header.header_len(),
					TIME_TO_LIVE,
					etherparse::IpTrafficClass::IPv4,
					ip.destination_addr().octets(),
					ip.source_addr().octets(),
				);

				let end_index = {
					let mut buf = &mut resp_data[..];
					resp_ip.write(&mut buf);
					resp_header.write(&mut buf);
					buf.len()
				};

				iface.send(&resp_data[..end_index])?;
			}
		}

		Ok(0)
	}
}