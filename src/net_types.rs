#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EtherType {
	IPv4,
	IPv6,
	Arp,
	IEEE8021Q,
	WakeOnLAN,
	IetfTrillProtocol,
	DECnetPhaseIV,
	ReverseAddressResolutionProtocol,
	Ethertalk,
	AARP,
	IPX,
	EthernetFlowControl,
	Unknown(u16),
}

impl From<u16> for EtherType {
	fn from(data: u16) -> Self {
		use EtherType::*;
		match data {
			0x0800 => IPv4,
			0x86DD => IPv6,
			0x0806 => Arp,
			0x8100 => IEEE8021Q,
			0x0842 => WakeOnLAN,
			0x22F3 => IetfTrillProtocol,
			0x6003 => DECnetPhaseIV,
			0x8035 => ReverseAddressResolutionProtocol,
			0x809B => Ethertalk,
			0x80F3 => AARP,
			0x8137 => IPX,
			0x8808 => EthernetFlowControl,
			uk => Unknown(uk)
		}
	}
}

impl From<[u8; 2]> for EtherType {
	fn from(data: [u8; 2]) -> Self {
		Self::from(u16::from_be_bytes(data))
	}
}


// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum Protocol {
	ICMP,
	IGMP,
	IPv4,
	TCP,
	UDP,
	TRUNK1,
	TRUNK2,
	IPv6ICMP,
	IPv6NoNxt,
	IPv6Opts,
	IPv6Route,
	IPv6Frag,
	IPv6,
	UnSupport(u8)
}


impl From<u8> for Protocol {
	fn from(data: u8) -> Self {
		use Protocol::*;
		match data {
			1 => ICMP,
			2 => IGMP,
			4 => IPv4,
			6 => TCP,
			17 => UDP,
			23 => TRUNK1,
			24 => TRUNK2,
			43 => IPv6Route,
			44 => IPv6Frag,
			58 => IPv6ICMP,
			59 => IPv6NoNxt,
			60 => IPv6Opts,
			other => UnSupport(other)
		}
	}
}