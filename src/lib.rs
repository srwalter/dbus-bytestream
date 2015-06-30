//! Native rust implementation of the D-Bus wire protocol.  Supports TCP and UDS transports, as
//! well as the EXTERNAL and ANONYMOUS authentication types.

extern crate dbus_serialize;
extern crate rustc_serialize;
extern crate unix_socket;
extern crate libc;

pub mod demarshal;
pub mod marshal;
pub mod message;
pub mod connection;
