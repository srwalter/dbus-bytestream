//! Functions for creating and modifying messages to send across the message bus.
use std::mem::transmute;
use std::collections::HashMap;

use dbus_serialize::types::{Path,Variant,Value,BasicValue,Signature};

use marshal::{Marshal,pad_to_multiple};

#[derive(Debug,Default)]
pub struct MessageType(pub u8);
pub const MESSAGE_TYPE_INVALID : MessageType        = MessageType(0);
pub const MESSAGE_TYPE_METHOD_CALL : MessageType    = MessageType(1);
pub const MESSAGE_TYPE_METHOD_RETURN : MessageType  = MessageType(2);
pub const MESSAGE_TYPE_ERROR : MessageType          = MessageType(3);
pub const MESSAGE_TYPE_SIGNAL : MessageType         = MessageType(4);

#[derive(Copy,Clone)]
pub enum HeaderFieldName {
    Invalid = 0,
    Path = 1,
    Interface = 2,
    Member = 3,
    ErrorName = 4,
    ReplySerial = 5,
    Destination = 6,
    Sender = 7,
    Signature = 8
}

struct HeaderField (
    HeaderFieldName,
    Variant
);

impl Marshal for HeaderField {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        pad_to_multiple(buf, 8);
        let start_len = buf.len();
        let code = self.0 as u8;
        code.dbus_encode(buf);
        self.1.dbus_encode(buf);
        buf.len() - start_len
    }
    fn get_type(&self) -> String {
        "(yv)".to_string()
    }
}

fn encode_header (msg_type: MessageType, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();

    let endian = 'l' as u8;
    endian.dbus_encode(&mut buf);
    msg_type.0.dbus_encode(&mut buf);
    (0 as u8).dbus_encode(&mut buf);
    (1 as u8).dbus_encode(&mut buf);
    (0 as u32).dbus_encode(&mut buf);
    serial.dbus_encode(&mut buf);
    buf
}

/// Container for the header of a D-Bus message.  Arguments can be added with add_arg()
pub struct MessageBuf(pub Vec<u8>);

/// Create a MessageBuf for a D-Bus method call.  Once a MessageBuf object is created, arguments
/// can be added to the object with MessageBuf.add_arg
pub fn create_method_call (dest: &str, path: &str, iface: &str, method: &str) -> MessageBuf {
    let mut msg = encode_header(MESSAGE_TYPE_METHOD_CALL, 0);
    let mut headers : Vec<HeaderField> = Vec::new();
    let mut v = Variant::new(Value::from(dest), "s");
    headers.push(HeaderField(HeaderFieldName::Destination, v));
    v = Variant::new(Value::BasicValue(BasicValue::ObjectPath(Path(path.to_string()))), "o");
    headers.push(HeaderField(HeaderFieldName::Path, v));
    v = Variant::new(Value::from(iface), "s");
    headers.push(HeaderField(HeaderFieldName::Interface, v));
    v = Variant::new(Value::from(method), "s");
    headers.push(HeaderField(HeaderFieldName::Member, v));
    headers.dbus_encode(&mut msg);
    pad_to_multiple(&mut msg, 8);

    // Store the length of the header so we can easily compute body length later
    let len = msg.len() as u32;
    let mut lenbuf = Vec::new();
    len.dbus_encode(&mut lenbuf);
    set_length(&mut msg, &lenbuf);
    MessageBuf(msg)
}

/// Create a MessageBuf for a D-Bus method return.  Once created, return values can be added to the
/// object with MessageBuf.add_arg
pub fn create_method_return(reply_serial: u32) -> MessageBuf {
    let mut msg = encode_header(MESSAGE_TYPE_METHOD_RETURN, 0);
    let mut headers : Vec<HeaderField> = Vec::new();
    let v = Variant::new(Value::from(reply_serial), "u");
    headers.push(HeaderField(HeaderFieldName::ReplySerial, v));
    pad_to_multiple(&mut msg, 8);

    // Store the length of the header so we can easily compute body length later
    let len = msg.len() as u32;
    let mut lenbuf = Vec::new();
    len.dbus_encode(&mut lenbuf);
    set_length(&mut msg, &lenbuf);
    MessageBuf(msg)
}

impl MessageBuf {
    /// Add the given argument to the MessageBuf.  Accepts anything that implements the Marshal
    /// trait, which is most basic types, as well as the general-purpose
    /// dbus_serialize::types::Value enum.
    ///
    /// Note that these calls can be chained together to add multiple arguments, see the example
    ///
    /// # Examples
    /// ```
    /// dbus_bytestream::message::create_method_call("foo", "/bar", "baz", "bloop")
    ///     .add_arg(&1)
    ///     .add_arg(&"string");
    /// ```
    pub fn add_arg(mut self, arg: &Marshal) -> MessageBuf {
        arg.dbus_encode(&mut self.0);
        self
    }
}

const LEN_OFFSET : usize = 4;

pub fn set_length (msg: &mut [u8], buf: &[u8]) {
    for i in 0..buf.len() {
        msg[i+LEN_OFFSET] = buf[i];
    }
}

pub fn get_length (msg: &[u8]) -> u32 {
    assert!(msg.len() >= LEN_OFFSET+4);
    let mut lenbuf = [0; 4];
    for i in 0..4 {
        lenbuf[i] = msg[i+LEN_OFFSET];
    }
    let len : u32 = unsafe { transmute(lenbuf) };
    // len is already LE, so this is a no-op except on BE systems
    len.to_le()
}

/// Represents a received message from the message bus
#[derive(Debug,Default)]
pub struct Message {
    pub big_endian: bool,
    pub message_type: MessageType,
    pub flags: u8,
    pub version: u8,
    pub serial: u32,
    pub headers: HashMap<u8,Value>,
    pub body: Vec<Value>
}

#[test]
fn test_header () {
    let buf = encode_header(MESSAGE_TYPE_METHOD_CALL, 12);
    println!("{:?}", buf);
}

#[test]
fn test_msg () {
    create_method_call("foo", "bar", "baz", "floob")
        .add_arg(&1)
        .add_arg(&2);
}
