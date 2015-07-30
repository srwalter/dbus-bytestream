//! Functions for creating and modifying messages to send across the message bus.
use std::ops::DerefMut;

use dbus_serialize::types::{Path,Variant,Value,BasicValue,Signature};

use marshal::{Marshal,pad_to_multiple};
use demarshal::{demarshal,DemarshalError};

#[derive(Debug,Default,PartialEq)]
pub struct MessageType(pub u8);
pub const MESSAGE_TYPE_INVALID : MessageType        = MessageType(0);
pub const MESSAGE_TYPE_METHOD_CALL : MessageType    = MessageType(1);
pub const MESSAGE_TYPE_METHOD_RETURN : MessageType  = MessageType(2);
pub const MESSAGE_TYPE_ERROR : MessageType          = MessageType(3);
pub const MESSAGE_TYPE_SIGNAL : MessageType         = MessageType(4);

pub const HEADER_FIELD_INVALID : u8     = 0;
pub const HEADER_FIELD_PATH: u8         = 1;
pub const HEADER_FIELD_INTERFACE: u8    = 2;
pub const HEADER_FIELD_MEMBER: u8       = 3;
pub const HEADER_FIELD_ERROR_NAME: u8   = 4;
pub const HEADER_FIELD_REPLY_SERIAL: u8 = 5;
pub const HEADER_FIELD_DESTINATION: u8  = 6;
pub const HEADER_FIELD_SENDER: u8       = 7;
pub const HEADER_FIELD_SIGNATURE: u8    = 8;

pub const FLAGS_NO_REPLY_EXPECTED : u8  = 1;

#[derive(Debug)]
pub struct HeaderField (
    pub u8,
    pub Variant
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

/// Represents a received message from the message bus
#[derive(Debug,Default)]
pub struct Message {
    pub big_endian: bool,
    pub message_type: MessageType,
    pub flags: u8,
    pub version: u8,
    pub serial: u32,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>
}

impl Marshal for Message {
    fn dbus_encode (&self, buf: &mut Vec<u8>) -> usize {
        let endian = if self.big_endian { 'B' as u8 } else { 'l' as u8 };
        endian.dbus_encode(buf);
        self.message_type.0.dbus_encode(buf);
        self.flags.dbus_encode(buf);
        self.version.dbus_encode(buf);
        let len : u32 = self.body.len() as u32;
        len.dbus_encode(buf);
        self.serial.dbus_encode(buf);
        self.headers.dbus_encode(buf);
        pad_to_multiple(buf, 8);
        0
    }

    fn get_type (&self) -> String {
        panic!("Don't do that.")
    }
}

/// Create a Message for a D-Bus method call.  Once a Message is created, arguments
/// can be added with Message.add_arg
pub fn create_method_call (dest: &str, path: &str, iface: &str, method: &str) -> Message {
    Message {
        big_endian: false,
        message_type: MESSAGE_TYPE_METHOD_CALL,
        flags: 0,
        version: 1,
        serial: 0,
        headers: Vec::new(),
        body: Vec::new(),
    }.add_destination_header(dest)
     .add_path_header(Path(path.to_string()))
     .add_interface_header(iface)
     .add_member_header(method)
}

/// Create a Message for a D-Bus method return.  Once created, return values can be added
/// with Message.add_arg
pub fn create_method_return(reply_serial: u32) -> Message {
    Message {
        big_endian: false,
        message_type: MESSAGE_TYPE_METHOD_RETURN,
        flags: 0,
        version: 1,
        serial: 0,
        headers: Vec::new(),
        body: Vec::new(),
    }.add_reply_header(reply_serial)
}

/// Create a Message for a D-Bus error.  Once created, return values can be added
/// with Message.add_arg
pub fn create_error(error_name: &str, reply_serial: u32) -> Message {
    Message {
        big_endian: false,
        message_type: MESSAGE_TYPE_ERROR,
        flags: 0,
        version: 1,
        serial: 0,
        headers: Vec::new(),
        body: Vec::new(),
    }.add_reply_header(reply_serial)
     .add_error_header(error_name)
}

/// Create a Message for a D-Bus signal.  Once created, return values can be added
/// with Message.add_arg
pub fn create_signal(path: &str, interface: &str, member: &str) -> Message {
    Message {
        big_endian: false,
        message_type: MESSAGE_TYPE_SIGNAL,
        flags: 0,
        version: 1,
        serial: 0,
        headers: Vec::new(),
        body: Vec::new(),
    }.add_path_header(Path(path.to_string()))
     .add_interface_header(interface)
     .add_member_header(member)
}

impl Message {
    /// Add the given argument to the Message.  Accepts anything that implements the Marshal
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
    pub fn add_arg(mut self, arg: &Marshal) -> Message {
        match self.get_header(HEADER_FIELD_SIGNATURE) {
            None => {
                let value = Value::BasicValue(BasicValue::Signature(Signature("".to_string())));
                let variant = Variant::new(value, "g");
                self = self.add_header(HEADER_FIELD_SIGNATURE, variant);
            },
            _ => ()
        };
        {
            let b : &mut Box<Value> = &mut self.get_header(HEADER_FIELD_SIGNATURE).unwrap().object;
            let val : &mut Value = b.deref_mut();
            match val {
                &mut Value::BasicValue(BasicValue::Signature(ref mut s)) => s.0.push_str(&arg.get_type()),
                _ => panic!("Garbage in signature field")
            };
        }
        arg.dbus_encode(&mut self.body);
        self
    }

    pub fn get_header(&mut self, name: u8) -> Option<&mut Variant> {
        match self.headers.iter().position(|x| { x.0 == name }) {
            Some(idx) => Some(&mut self.headers[idx].1),
            _ => None
        }
    }

    pub fn get_path (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_PATH) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::ObjectPath(Path(ref x))) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_interface (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_INTERFACE) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::String(ref x)) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_member (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_MEMBER) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::String(ref x)) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_error_name (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_ERROR_NAME) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::String(ref x)) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_reply_serial (&mut self) -> Option<u32> {
        let b = match self.get_header(HEADER_FIELD_REPLY_SERIAL) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::Uint32(x)) => Some(x),
            _ => return None
        }
    }

    pub fn get_destination (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_DESTINATION) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::String(ref x)) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_sender (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_SENDER) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::String(ref x)) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn get_signature (&mut self) -> Option<String> {
        let b = match self.get_header(HEADER_FIELD_SIGNATURE) {
            Some(x) => x,
            _ => return None
        };
        match *b.object {
            Value::BasicValue(BasicValue::Signature(Signature(ref x))) => Some(x.to_string()),
            _ => return None
        }
    }

    pub fn add_header(mut self, name: u8, val: Variant) -> Message {
        self.headers.push(HeaderField (name, val));
        self
    }

    pub fn add_destination_header(self, destination: &str) -> Message {
        self.add_header(HEADER_FIELD_DESTINATION,
                        Variant::new(Value::from(destination), "s"))
    }

    pub fn add_interface_header(self, interface: &str) -> Message {
        self.add_header(HEADER_FIELD_INTERFACE,
                        Variant::new(Value::from(interface), "s"))
    }

    pub fn add_member_header(self, member: &str) -> Message {
        self.add_header(HEADER_FIELD_MEMBER,
                        Variant::new(Value::from(member), "s"))
    }

    pub fn add_path_header(self, path: Path) -> Message {
        self.add_header(HEADER_FIELD_PATH,
                        Variant::new(Value::BasicValue(BasicValue::ObjectPath(path)), "o"))
    }

    pub fn add_error_header(self, error_name: &str) -> Message {
        self.add_header(HEADER_FIELD_ERROR_NAME,
                        Variant::new(Value::from(error_name), "s"))
    }

    pub fn add_reply_header(self, reply_serial: u32) -> Message {
        self.add_header(HEADER_FIELD_REPLY_SERIAL,
                        Variant::new(Value::from(reply_serial), "u"))
    }

    /// Get the sequence of Values from out of a Message.  Returns None if the message doesn't have
    /// a body.
    pub fn get_body(&mut self) -> Result<Option<Vec<Value>>,DemarshalError> {
        if self.body.len() == 0 {
            return Ok(None);
        }

        let sigval = match self.get_signature() {
            Some(sig) => sig,
            _ => return Err(DemarshalError::CorruptedMessage)
        };

        let mut sig = "(".to_string() + &sigval + ")";
        let mut offset = 0;
        match try!(demarshal(&mut self.body, &mut offset, &mut sig)) {
            Value::Struct(x) => Ok(Some(x.objects)),
            x => panic!("Didn't get a struct: {:?}", x)
        }
    }
}

#[test]
fn test_msg () {
    create_method_call("foo", "bar", "baz", "floob")
        .add_arg(&1)
        .add_arg(&2);
}
