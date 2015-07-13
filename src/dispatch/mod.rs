//! Routes incoming messages to registered handlers
//!
//! A message handler can be invoked in an application's main loop to consume
//! messages and route them to registered callbacks. Callbacks are routed based on
//! their object, interface, and member paths used when registered.
//!
//! Some basic validation is performed to guarantee that all required parts for the
//! message for a given message type are valid and present.  Error messages to
//! deliver to the bus are generated when validation fails.
//!
//! This currently only handles signals and method calls. It should be extended to
//! support method returns and errors to be dispatched by reply_serial.  There is
//! also not yet a deregistration interface.
//!
//! # Examples
//! Dispatching a method call to a closure
//!
//! ```
//! use std::cell::Cell;
//! use dbus_bytestream::connection::{Connection, MessageSender};
//! use dbus_bytestream::dispatch::{MessageDispatcher, MessageHandler};
//! use dbus_bytestream::dispatch::MethodRetVal::EmptyReply;
//! use dbus_bytestream::message;
//!
//! // Simulated incoming method call
//! let mth_msg = message::create_method_call("dest", "path", "interface", "method");
//! let mth_called = Cell::new(false);
//!
//! let mut conn = Connection::connect_system().unwrap();
//! let mut dis = MessageDispatcher::new();
//!
//! // Register a boxed closure with a method call
//! dis.add_method("path".into(), "interface".into(), "method".into(),
//!                 Box::new(|_sender, mth| {
//!                     mth_called.set(true);
//!                     assert_eq!(mth.path, "path");
//!                     assert_eq!(mth.interface, "interface");
//!                     assert_eq!(mth.member, "method");
//!                     Ok(EmptyReply)
//!                 } ));
//!
//! /* Handle one method call */
//! assert_eq!(mth_called.get(), false);
//! dis.handle_message(&mut conn, mth_msg).unwrap().unwrap();
//! assert_eq!(mth_called.get(), true);
//! ```
//! Chaining multiple message handlers
//!
//! Messages that are not handled by a MessageHandler can be passed to another.
//! Putting a NoMatchHandler at the end of the chain will consume the message and
//! send an UnknownObject error back to the bus.
//!
//! ```
//! use dbus_bytestream::connection::{Connection, MessageSender};
//! use dbus_bytestream::dispatch::{HandlerChain, MessageDispatcher,
//!                                 MessageHandler, NoMatchHandler};
//! use dbus_bytestream::message;
//!
//! let msg = message::create_method_call("dest", "path", "interface", "method");
//! let mut conn = Connection::connect_system().unwrap();
//! // Three dispatchers with no methods registered. Each will pass the msg to the next
//! let mut dis1 = MessageDispatcher::new();
//! let mut dis2 = MessageDispatcher::new();
//! let mut dis3 = MessageDispatcher::new();
//!
//! // The NoMatchHandler will consume the msg and send an error over the connection.
//! dis1.handle_message(&mut conn, msg)
//!     .chain(&mut conn, &mut dis2)
//!     .chain(&mut conn, &mut dis3)
//!     .chain(&mut conn, &mut NoMatchHandler).unwrap().unwrap();
//! ```

use std::collections::HashMap;
use dbus_serialize::decoder;
use dbus_serialize::types::Value;

use connection;
use connection::MessageSender;
use message;
use message::Message;

pub mod message_types;
use self::message_types::*;

#[test]
fn test_decode_message() {
    /* Method call */
    let mut msg = message::create_method_call("dest", "path", "interface", "method");
    if let MessageType::Method(mth) = decode_message(&mut msg).unwrap() {
        assert_eq!(mth.path, "path");
        assert_eq!(mth.interface, "interface");
        assert_eq!(mth.member, "method");
    }

    /* Signal */
    let mut msg = message::create_signal("path", "interface", "method");
    if let MessageType::Signal(sig) = decode_message(&mut msg).unwrap() {
        assert_eq!(sig.path, "path");
    }

}

#[derive(Debug)]
pub enum DispatchError {
    MessageDecodeError(MessageDecodeError),
    InvalidArguments,
    UnhandledMessage,
    OtherError(String),
}

impl From<MessageDecodeError> for DispatchError {
    fn from(e: MessageDecodeError) -> Self {
        DispatchError::MessageDecodeError(e)
    }
}

impl From<decoder::DecodeError> for DispatchError {
    fn from(_e: decoder::DecodeError) -> Self {
        DispatchError::InvalidArguments
    }
}

impl From<String> for DispatchError {
    fn from(s: String) -> Self {
        DispatchError::OtherError(s)
    }
}

/// Wrapper around a MessageSender trait object to work around a compiler bug
///
/// Provides the same interface as MessageSender
pub struct MessageSenderWrapper<'a>(pub &'a mut connection::MessageSender);

impl<'a> MessageSenderWrapper<'a> {
    pub fn send(&mut self, mbuf: &mut Message) -> Result<u32, connection::Error> {
        self.0.send(mbuf)
    }

    pub fn call_sync(&mut self, mbuf: &mut Message) -> Result<Option<Vec<Value>>, connection::Error> {
        self.0.call_sync(mbuf)
    }
}

#[derive(Debug, PartialEq)]
pub enum MethodRetVal {
    NoReply,
    EmptyReply,
    Reply(Vec<Value>),
}

pub type DispatchResult = Result<(), DispatchError>;
pub type MethodHandlerResult = Result<MethodRetVal, DispatchError>;
pub type MethodHandler<'a> = Box<FnMut(MessageSenderWrapper, MethodCall) -> MethodHandlerResult + 'a>;
pub type SignalHandlerResult = DispatchResult;
pub type SignalHandler<'a> = Box<FnMut(MessageSenderWrapper, Signal) -> SignalHandlerResult + 'a>;

// TODO: possibly make a ConnectionError value for DispatchError
fn connection_err_string(e: connection::Error) -> String {
    format!("Connection send error {:?}", e)
}

pub type HandlerResult = Result<Result<(), String>, Message>;

/// Dispatches messages. Multiple message handlers can be chained.
pub trait MessageHandler {
    /// Dispatches one message
    ///
    /// Handled messages are consumed and Ok(Ok(())) is returned.
    /// Invalid messages that fail to decode push a DBus error message to the sender and return Ok(Err(String)).
    /// Unhandled but valid messages are returned as Err(Message) to allow chaining dispatchers.
    fn handle_message<T: MessageSender>(&mut self, sender: &mut T, mut msg: Message) -> HandlerResult;
}

use std::borrow::Cow;
#[derive(Hash, PartialEq, Eq)]
struct DBusMatch<'a> {
    path: Cow<'a, str>,
    interface: Cow<'a, str>,
    member: Cow<'a, str>,
}

impl<'a> DBusMatch<'a> {
    fn new(path: Cow<'a, str>, interface: Cow<'a, str>, member: Cow<'a, str>) -> Self {
        DBusMatch {
            path: path,
            interface: interface,
            member: member
        }
    }
}

/// Dispatches incoming signals and method calls
#[derive(Default)]
pub struct MessageDispatcher<'k, 'v> {
    mth_handlers: HashMap<DBusMatch<'k>, MethodHandler<'v>>,
    sig_handlers: HashMap<DBusMatch<'k>, SignalHandler<'v>>,
}

// Signals and methods have the same implementation but with two different
// collections and different message and handler types. This could be done with
// one generic implementation, but since there are only two this is clearer.
impl<'k, 'v> MessageDispatcher<'k, 'v> {
    pub fn new() -> Self {
        Default::default()
    }

    fn dispatch_sig<T: MessageSender>(&mut self, sender: &mut T, sig: Signal) -> DispatchResult {
        let handler = {
            // XXX copying the strings here.
            // The argument to HashMap::get_mut() must have the same type as the
            // key, which in the case of MessageDispatcher includes a lifetime
            // bound. I can't find a way to get around the K: Borrow<Q> constraint.
            let s = DBusMatch::new(sig.path.clone().into(),
                                   sig.interface.clone().into(),
                                   sig.member.clone().into());
            self.sig_handlers.get_mut(&s)
        };
        handler.ok_or(DispatchError::UnhandledMessage)
            .and_then(|h| { h(MessageSenderWrapper(sender), sig) })
    }

    fn dispatch_mth<T: MessageSender>(&mut self, sender: &mut T, mth: MethodCall,
                                      reply_serial: u32, reply_expected: bool) -> DispatchResult {
        let handler = {
            // XXX copying the strings here.
            // The argument to HashMap::get_mut() must have the same type as the
            // key, which in the case of MessageDispatcher includes a lifetime
            // bound. I can't find a way to get around the K: Borrow<Q> constraint.
            let s = DBusMatch::new(mth.path.clone().into(),
                                   mth.interface.clone().into(),
                                   mth.member.clone().into());
            self.mth_handlers.get_mut(&s)
        };
        handler.ok_or(DispatchError::UnhandledMessage)
            .and_then(|h| { h(MessageSenderWrapper(sender), mth) })
            .and_then(|val| {
                if val == MethodRetVal::NoReply || !reply_expected {
                    return Ok(())
                }
                let mut reply = message::create_method_return(reply_serial);
                if let MethodRetVal::Reply(r) = val {
                    for arg in r.into_iter() {
                        reply = reply.add_arg(&arg);
                    }
                }
                sender.send(&mut reply)
                    .map(|_| ()) // Remove serial number
                    .map_err(connection_err_string) // Convert connection error to string
                    .map_err(From::from) // From String to DispatchError::OtherError
            })
    }

    pub fn add_signal(&mut self, path: Cow<'k, str>, interface: Cow<'k, str>, member: Cow<'k, str>, cl: SignalHandler<'v>) {
        self.sig_handlers.insert(DBusMatch::new(path, interface, member), cl);
    }

    pub fn add_method(&mut self, path: Cow<'k, str>, interface: Cow<'k, str>, member: Cow<'k, str>, cl: MethodHandler<'v>) {
        self.mth_handlers.insert(DBusMatch::new(path, interface, member), cl);
    }
}

impl<'k, 'v> MessageHandler for MessageDispatcher<'k, 'v> {
    fn handle_message<T: MessageSender>(&mut self, sender: &mut T, mut msg: Message) -> HandlerResult {
        let r = decode_message(&mut msg).map_err(From::from)
            /* Dispatch based on message type */
            .and_then(|msgtype| {
                match msgtype {
                    MessageType::Signal(s) =>
                        self.dispatch_sig(sender, s),
                    MessageType::Method(s) =>
                        self.dispatch_mth(sender, s, msg.serial,
                                          (msg.flags & message::FLAGS_NO_REPLY_EXPECTED) == 0),
                    MessageType::MethodReturn(_) =>
                        Err(DispatchError::UnhandledMessage), // Unimplemented
                    MessageType::Error(_) =>
                        Err(DispatchError::UnhandledMessage), // Unimplemented
                }
            });
        match r {
            Ok(ok) => Ok(Ok(ok)),
            Err(dispatch_err) => match dispatch_err {
                /* MessageDecodeError generates a dbus error message and returns Ok(Err(String)) */
                DispatchError::MessageDecodeError(err) => {
                    let err_msg = format!("{:?}", err);
                    let r = sender.send(&mut message::create_error("org.freedesktop.DBus.Error.InconsistentMessage", msg.serial)
                                            .add_arg(&err_msg))
                        .map(|_| ()) // Remove serial number
                        .map_err(connection_err_string) // Convert connection error to string
                        .and(Err(err_msg)); // Return decode error if message send successful
                    Ok(r)
                },
                DispatchError::InvalidArguments => {
                    let r = sender.send(&mut message::create_error("org.freedesktop.DBus.Error.InvalidSignature", msg.serial))
                        .map(|_| ()) // Remove serial number
                        .map_err(connection_err_string) // Convert connection error to string
                        .and(Err("Invalid arguments".to_owned())); // Return decode error if message send successful
                    Ok(r)
                },
                DispatchError::OtherError(s) => {
                    let r = sender.send(&mut message::create_error(s.as_ref(), msg.serial))
                        .map(|_| ()) // Remove serial number
                        .map_err(connection_err_string) // Convert connection error to string
                        .and(Err(s)); // Return decode error if message send successful
                    Ok(r)
                },
                DispatchError::UnhandledMessage => Err(msg),
            },
        }
    }
}

/// A Handler that consumes a message and sends an error DBus message to the sender
pub struct NoMatchHandler;

impl MessageHandler for NoMatchHandler {
    /// Consumes a message and sends a "org.freedesktop.DBus.Error.UnknownObject" reply
    ///
    /// May return Ok(Err()) for a connection failure. Otherwise returns Ok(Ok()).
    fn handle_message<T: MessageSender>(&mut self, sender: &mut T, msg: Message) -> HandlerResult {
        /* TODO handle different message types with different error responses. This assumes method call */
        Ok(sender.send(&mut message::create_error("org.freedesktop.DBus.Error.UnknownObject", msg.serial))
            .map(|_| ()) // Remove serial number
            .map_err(connection_err_string))
    }
}

/// Allows chaining together message handlers
pub trait HandlerChain {
    fn chain<H: MessageHandler, S: MessageSender>(self, sender: &mut S, handler: &mut H) -> Self;
}

impl HandlerChain for HandlerResult {
    /// Calls handle_message on the handler if HandlerResult contains a
    /// message, otherwise passes the Ok() through.
    fn chain<H: MessageHandler, S: MessageSender>(self, sender: &mut S, handler: &mut H) -> Self {
        self.or_else(|e| handler.handle_message(sender, e))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::message_types::{decode_message, MessageType};
    use connection;
    use connection::MessageSender;
    use message;
    use message::Message;
    use dbus_serialize::types::Value;

    #[derive(Default)]
    struct DummySender {
        msgs: Vec<MessageType>,
    }

    impl DummySender {
        fn new() -> Self {
            Default::default()
        }
    }

    impl MessageSender for DummySender {
        fn send(&mut self, mbuf: &mut Message) -> Result<u32, connection::Error> {
            self.msgs.push(decode_message(mbuf).unwrap());
            Err(connection::Error::Disconnected)
        }

        fn call_sync(&mut self, _mbuf: &mut Message) -> Result<Option<Vec<Value>>,connection::Error> {
            Err(connection::Error::Disconnected)
        }
    }

    #[test]
    fn test_chained() {
        let msg = message::create_signal("path", "interface", "method");
        let mut sender = DummySender::new();
        let mut mth_dis = MessageDispatcher::new();
        mth_dis.handle_message(&mut sender, msg)
            .chain(&mut sender, &mut mth_dis).unwrap_err();
    }

    #[test]
    fn test_dispatcher_method() {
        use std::cell::Cell;

        let mth_msg = message::create_method_call("dest", "path", "interface", "method");
        let sig_msg = message::create_signal("path", "interface", "method");
        let mth_called = Cell::new(false);
        let sig_called = Cell::new(false);

        let mut mth_dis = MessageDispatcher::new();
        let mut sig_dis = MessageDispatcher::new();

        let mut sender = DummySender::new();

        mth_dis.add_method("path".into(), "interface".into(), "method".into(),
                        Box::new(|_sender, mth| {
                            mth_called.set(true);
                            assert_eq!(mth.path, "path");
                            assert_eq!(mth.interface, "interface");
                            assert_eq!(mth.member, "method");
                            Ok(MethodRetVal::Reply(vec![Value::from(10)]))
                        } ));

        sig_dis.add_signal("path".into(), "interface".into(), "method".into(),
                        Box::new(|_sender, sig| {
                            sig_called.set(true);
                            assert_eq!(sig.path, "path");
                            assert_eq!(sig.interface, "interface");
                            assert_eq!(sig.member, "method");
                            Ok(())
                        } ));


        /* Handle one method call */
        assert_eq!(mth_called.get(), false);
        let err = mth_dis.handle_message(&mut sender, mth_msg).unwrap().unwrap_err();
        /* Dummy sender should return a connection error */
        assert_eq!(err, "Connection send error Disconnected");
        assert_eq!(mth_called.get(), true);
        /* Pop the connection error reply. Probably doesn't make sense to return errors for failed connections. */
        sender.msgs.pop().unwrap();
        /* Sender should have sent a MethodReturn message */
        match sender.msgs.pop().unwrap() {
            MessageType::MethodReturn(r) => assert_eq!(r.body.unwrap().get(0).unwrap(), &Value::from(10)),
            _ => panic!("MethodReturn to be generated"),
        }

        /* Test chaining */
        assert_eq!(sig_called.get(), false);
        let msg = mth_dis.handle_message(&mut sender, sig_msg).unwrap_err();
        assert_eq!(sig_called.get(), false);

        sig_dis.handle_message(&mut sender, msg).unwrap().unwrap();
        assert_eq!(sig_called.get(), true);
    }

    #[test]
    fn test_no_match_handler() {
        let mut sender = DummySender::new();
        let sig_msg = message::create_signal("path", "interface", "method");
        let mut dis1 = MessageDispatcher::new();
        let mut dis2 = MessageDispatcher::new();

        let err = dis1.handle_message(&mut sender, sig_msg)
            .chain(&mut sender, &mut dis2)
            .chain(&mut sender, &mut NoMatchHandler).unwrap().unwrap_err();
        /* Dummy sender should return a connection error */
        assert_eq!(err, "Connection send error Disconnected");

        /* Sender should have sent an UnknownObject message */
        match sender.msgs.pop().unwrap() {
            MessageType::Error(e) => assert_eq!(e.error_name, "org.freedesktop.DBus.Error.UnknownObject"),
            _ => panic!("Expected error to be generated"),
        }
        assert_eq!(sender.msgs.len(), 0);
    }
}
