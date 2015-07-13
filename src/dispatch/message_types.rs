//! Specific struct representations of DBus message types
use dbus_serialize::types::Value;
use message;
use message::Message;

#[derive(Debug)]
pub enum MessageDecodeError {
    BadMessageType,
    BadPath,
    BadInterface,
    BadMember,
    BadErrorName,
    BadReplySerial,
    BadBody,
}

/// Unpacked, optional header fields that may be present in any message
#[derive(Debug)]
pub struct OptionalHeaderFields {
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: Option<String>,
}

impl OptionalHeaderFields {
    fn new(msg: &mut Message) -> Self {
        OptionalHeaderFields {
            destination: msg.decode_header_field(message::HEADER_FIELD_DESTINATION),
            sender: msg.decode_header_field(message::HEADER_FIELD_SENDER),
            signature: msg.decode_header_field(message::HEADER_FIELD_SIGNATURE),
        }
    }
}

/// An unpacked, validated DBus method call
#[derive(Debug)]
pub struct MethodCall {
    pub path: String,
    pub interface: String,
    pub member: String,
    pub opt: OptionalHeaderFields,
    pub body: Option<Vec<Value>>
}

impl MethodCall {
    pub fn new(msg: &mut Message) -> Result<Self, MessageDecodeError> {
        Ok(MethodCall {
            path: try!(msg.decode_header_field(message::HEADER_FIELD_PATH)
                            .ok_or(MessageDecodeError::BadPath)),
            interface: msg.decode_header_field(message::HEADER_FIELD_INTERFACE)
                            .unwrap_or("".to_owned()),
            member: try!(msg.decode_header_field(message::HEADER_FIELD_MEMBER)
                            .ok_or(MessageDecodeError::BadMember)),
            opt: OptionalHeaderFields::new(msg),
            body: try!(msg.get_body()
                            .map_err(|_| MessageDecodeError::BadBody)),
        })
    }
}

/// An unpacked, validated DBus method call
#[derive(Debug)]
pub struct MethodReturn {
    pub reply_serial: u32,
    pub opt: OptionalHeaderFields,
    pub body: Option<Vec<Value>>
}

impl MethodReturn {
    pub fn new(msg: &mut Message) -> Result<Self, MessageDecodeError> {
        Ok(MethodReturn {
            reply_serial: try!(msg.decode_header_field(message::HEADER_FIELD_REPLY_SERIAL)
                            .ok_or(MessageDecodeError::BadReplySerial)),
            opt: OptionalHeaderFields::new(msg),
            body: try!(msg.get_body()
                            .map_err(|_| MessageDecodeError::BadBody)),
        })
    }
}

/// An unpacked, validated DBus signal
#[derive(Debug)]
pub struct Signal {
    pub path: String,
    pub interface: String,
    pub member: String,
    pub opt: OptionalHeaderFields,
    pub body: Option<Vec<Value>>
}

impl Signal {
    pub fn new(msg: &mut Message) -> Result<Self, MessageDecodeError> {
        Ok(Signal {
            path: try!(msg.decode_header_field(message::HEADER_FIELD_PATH)
                            .ok_or(MessageDecodeError::BadPath)),
            interface: try!(msg.decode_header_field(message::HEADER_FIELD_INTERFACE)
                            .ok_or(MessageDecodeError::BadInterface)),
            member: try!(msg.decode_header_field(message::HEADER_FIELD_MEMBER)
                            .ok_or(MessageDecodeError::BadMember)),
            opt: OptionalHeaderFields::new(msg),
            body: try!(msg.get_body()
                            .map_err(|_| MessageDecodeError::BadMember)),
        })
    }
}

/// An unpacked, validated DBus error
#[derive(Debug)]
pub struct Error {
    pub error_name: String,
    pub reply_serial: u32,
    pub opt: OptionalHeaderFields,
    pub body: Option<Vec<Value>>
}

impl Error {
    pub fn new(msg: &mut Message) -> Result<Self, MessageDecodeError> {
        Ok(Error {
            error_name: try!(msg.decode_header_field(message::HEADER_FIELD_ERROR_NAME)
                            .ok_or(MessageDecodeError::BadErrorName)),
            reply_serial: try!(msg.decode_header_field(message::HEADER_FIELD_REPLY_SERIAL)
                            .ok_or(MessageDecodeError::BadReplySerial)),
            opt: OptionalHeaderFields::new(msg),
            body: try!(msg.get_body()
                            .map_err(|_| MessageDecodeError::BadBody)),
        })
    }
}

#[derive(Debug)]
pub enum MessageType {
    Method(MethodCall),
    MethodReturn(MethodReturn),
    Signal(Signal),
    Error(Error),
}

/// Converts a generic Message to a specific validated MessageType
pub fn decode_message(msg: &mut Message) -> Result<MessageType, MessageDecodeError> {
    match msg.message_type {
        message::MESSAGE_TYPE_METHOD_CALL =>
            Ok(MessageType::Method(try!(MethodCall::new(msg)))),

        message::MESSAGE_TYPE_METHOD_RETURN =>
            Ok(MessageType::MethodReturn(try!(MethodReturn::new(msg)))),

        message::MESSAGE_TYPE_SIGNAL =>
            Ok(MessageType::Signal(try!(Signal::new(msg)))),

        message::MESSAGE_TYPE_ERROR =>
            Ok(MessageType::Error(try!(Error::new(msg)))),

        _ => Err(MessageDecodeError::BadMessageType),
    }
}
