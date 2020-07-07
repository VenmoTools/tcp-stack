#[macro_use]
extern crate log;
extern crate pretty_env_logger;

pub mod net_types;
pub mod tcp;
pub mod data_link;
pub mod result;
pub mod reader_writer;
pub mod meta;

pub fn init_log() {
    pretty_env_logger::init();
}