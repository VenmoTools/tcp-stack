pub const ETHERNET_MTU: usize = 1500;
pub const FDDI_MTU: usize = 4352;
pub const PPP_MTU: usize = 296;
pub const TUN_SIZE: usize = 4;
pub const TCP_HEADER_MAXIMUM_SIZE: usize = 20;
pub const IP_HEADER_MAXIMUM_SIZE: usize = 20;
pub const TCP_IP_PAYLOAD_MAXIMUM_SIZE: usize =
    ETHERNET_MTU - TCP_HEADER_MAXIMUM_SIZE - IP_HEADER_MAXIMUM_SIZE;
