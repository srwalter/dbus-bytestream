//! Deals with creating and using connections to dbus-daemon.  The primary
//! type of interest is the Connection struct
//! 
//! # Examples
//! ```
//! use dbus_bytestream::connection::{Connection, MessageSender};
//! use dbus_bytestream::message;
//!
//! let mut conn = Connection::connect_system().unwrap();
//! let mut msg = message::create_method_call(
//!     "org.freedesktop.DBus", // destination
//!     "/org/freedesktop/DBus", // path
//!     "org.freedesktop.DBus", //interface
//!     "ListNames" // method
//! );
//! let reply = conn.call_sync(&mut msg);
//! println!("{:?}", reply);
//! ```
//!

use std::env;
use std::net::{TcpStream,ToSocketAddrs};
use std::io;
use std::io::{Read,Write};
use std::fs::File;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::string;
use std::num::ParseIntError;
use rand::Rand;
use rand;
use libc;
use crypto::digest::Digest;
use crypto;

use unix_socket::UnixStream;
use rustc_serialize::hex::{ToHex,FromHex,FromHexError};
use dbus_serialize::types::Value;
use dbus_serialize::decoder::DBusDecoder;

use address;
use address::ServerAddress;
use message;
use message::{Message,HeaderField};
use demarshal::{demarshal,DemarshalError};
use marshal::Marshal;

trait StreamSocket : Read + Write { }
impl<T: Read + Write> StreamSocket for T {}

enum Socket {
    Tcp(TcpStream),
    Uds(UnixStream)
}

pub struct Connection {
    sock: Socket,
    next_serial: u32,
    queue: Vec<Message>,
}

#[derive(Debug)]
pub enum Error {
    Disconnected,
    IOError(io::Error),
    DemarshalError(DemarshalError),
    AddressError(address::ServerAddressError),
    BadData,
    AuthFailed,
    NoEnvironment,
}

impl From<io::Error> for Error {
    fn from(x: io::Error) -> Self {
        Error::IOError(x)
    }
}

impl From<DemarshalError> for Error {
    fn from(x: DemarshalError) -> Self {
        Error::DemarshalError(x)
    }
}

impl From<address::ServerAddressError> for Error {
    fn from(x: address::ServerAddressError) -> Self {
        Error::AddressError(x)
    }
}

impl From<FromHexError> for Error {
    fn from(_x: FromHexError) -> Self {
        Error::AuthFailed
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(_x: string::FromUtf8Error) -> Self {
        Error::AuthFailed
    }
}

impl From<ParseIntError> for Error {
    fn from(_x: ParseIntError) -> Self {
        Error::AuthFailed
    }
}

fn read_exactly(sock: &mut StreamSocket, buf: &mut Vec<u8>, len: usize) -> Result<(),Error> {
    buf.truncate(0);
    buf.reserve(len);
    if try!(sock.take(len as u64).read_to_end(buf)) != len {
        return Err(Error::Disconnected);
    }
    Ok(())
}

fn read_line(sock: &mut StreamSocket) -> Result<String,Error> {
    let mut line = "".to_string();
    let mut last = '\0';

    loop {
        let mut buf = vec![0];
        match sock.read(&mut buf) {
            Ok(x) if x > 0 => (),
            _ => return Err(Error::Disconnected)
        };
        let chr = buf[0] as char;
        line.push(chr);
        if chr == '\n' && last == '\r' {
            break;
        }
        last = chr;
    }
    Ok(line)
}

fn get_cookie(context: &str, cookie_id: &str) -> Result<String,Error> {
    let hd = match env::home_dir() {
        Some(x) => x,
        None => return Err(Error::AuthFailed)
    };
    let filename = hd.join(".dbus-keyrings").join(context);
    let mut f = try!(File::open(filename));
    let mut contents = String::new();
    try!(f.read_to_string(&mut contents));
    let lines : Vec<&str> = contents.split('\n').collect();
    for line in lines {
        if !line.starts_with(cookie_id) {
            continue;
        }
        let words : Vec<&str> = line.split(' ').collect();
        if words.len() != 3 {
            break;
        }
        return Ok(words[2].to_string());
    }

    Err(Error::AuthFailed)
}

impl Connection {
    fn get_sock(&mut self) -> &mut StreamSocket {
        match self.sock {
            Socket::Tcp(ref mut x) => x,
            Socket::Uds(ref mut x) => x
        }
    }

    fn send_nul_byte(&mut self) -> Result<(),Error> {
        // Send NUL byte
        let sock = self.get_sock();
        let buf = vec![0];
        try!(sock.write_all(&buf));
        Ok(())
    }

    fn auth_anonymous(&mut self) -> Result<(),Error> {
        let sock = self.get_sock();

        try!(sock.write_all(b"AUTH ANONYMOUS 6c69626462757320312e382e3132\r\n"));

        // Read response
        let resp = try!(read_line(sock));
        if !resp.starts_with("OK ") {
            return Err(Error::AuthFailed);
        }

        // Ready for action
        try!(sock.write_all(b"BEGIN\r\n"));
        Ok(())
    }

    fn auth_external(&mut self) -> Result<(),Error> {
        let sock = self.get_sock();

        let uid = unsafe {
            libc::funcs::posix88::unistd::getuid()
        };
        let uid_str = uid.to_string();
        let uid_hex = uid_str.into_bytes().to_hex();
        let cmd = "AUTH EXTERNAL ".to_string() + &uid_hex + "\r\n";
        try!(sock.write_all(&cmd.into_bytes()));

        // Read response
        let resp = try!(read_line(sock));
        if !resp.starts_with("OK ") {
            return Err(Error::AuthFailed);
        }

        // Ready for action
        try!(sock.write_all(b"BEGIN\r\n"));
        Ok(())
    }

    fn auth_cookie(&mut self) -> Result<(),Error> {
        let sock = self.get_sock();

        let uid = unsafe {
            libc::funcs::posix88::unistd::getuid()
        };
        let uid_str = uid.to_string();
        let uid_hex = uid_str.into_bytes().to_hex();
        let cmd = "AUTH DBUS_COOKIE_SHA1 ".to_string() + &uid_hex + "\r\n";
        try!(sock.write_all(&cmd.into_bytes()));

        // Read response
        let resp = try!(read_line(sock));
        let words : Vec<&str> = resp.split(' ').collect();
        if words.len() != 2 {
            return Err(Error::AuthFailed);
        }
        if words[0] != "DATA" {
            return Err(Error::AuthFailed);
        }

        let bytes = try!(words[1].from_hex());
        let challenge = try!(String::from_utf8(bytes));
        let words : Vec<&str> = challenge.split(' ').collect();
        if words.len() != 3 {
            return Err(Error::AuthFailed);
        }

        let cookie = try!(get_cookie(words[0], words[1]));

        let mut my_challenge = Vec::new();
        for _ in 0..16 {
            my_challenge.push(u8::rand(&mut rand::thread_rng()));
        }
        let hex_challenge = my_challenge.to_hex();

        let my_cookie = words[2].to_string() + ":" + &hex_challenge + ":" + &cookie;
        let mut hasher = crypto::sha1::Sha1::new();
        hasher.input_str(&my_cookie);
        let hash = hasher.result_str();

        let my_resp = hex_challenge + " " + &hash;
        let hex_resp = my_resp.into_bytes().to_hex();
        let buf = "DATA ".to_string() + &hex_resp + "\r\n";
        try!(sock.write_all(&buf.into_bytes()));

        // Read response
        let resp = try!(read_line(sock));
        if !resp.starts_with("OK ") {
            return Err(Error::AuthFailed);
        }

        // Ready for action
        try!(sock.write_all(b"BEGIN\r\n"));
        Ok(())
    }

    fn authenticate(&mut self) -> Result<(),Error> {
        try!(self.send_nul_byte());
        try!(self.auth_external()
              .or_else(|_x| { self.auth_cookie() })
              .or_else(|_x| { self.auth_anonymous() }));
        self.say_hello()
    }

    fn say_hello(&mut self) -> Result<(),Error> {
        let mut msg = message::create_method_call("org.freedesktop.DBus",
                                                  "/org/freedesktop/DBus",
                                                  "org.freedesktop.DBus",
                                                  "Hello");
        try!(self.call_sync(&mut msg));
        Ok(())
    }

    fn connect_addr(addr: ServerAddress) -> Result<Connection,Error> {
        match addr {
            ServerAddress::Unix(unix) => Self::connect_uds(unix.path()),
            ServerAddress::Tcp(tcp) => Self::connect_tcp(tcp),
        }
    }

    /// Connects to a DBus address string.
    pub fn connect(addr: &str) -> Result<Connection, Error> {
        Self::connect_addr(try!(ServerAddress::from_str(addr)))
    }

    /// Connects to the system bus.
    ///
    /// The address is specified by the environment variable
    /// DBUS_SYSTEM_BUS_ADDRESS or "unix:path=/var/run/dbus/system_bus_socket" if unset.
    pub fn connect_system() -> Result<Connection, Error> {
        let default = "unix:path=/var/run/dbus/system_bus_socket";
        if let Ok(e) = env::var("DBUS_SYSTEM_BUS_ADDRESS") {
            Self::connect(&e)
        } else {
            Self::connect(default)
        }
    }

    /// Connects to the session bus.
    ///
    /// The address is specified by the environment variable DBUS_SESSION_BUS_ADDRESS.
    pub fn connect_session() -> Result<Connection, Error> {
        if let Ok(e) = env::var("DBUS_SESSION_BUS_ADDRESS") {
            Self::connect(&e)
        } else {
            Err(Error::NoEnvironment)
        }
    }

    /// Creates a Connection object using a UNIX domain socket as the transport.  The addr is the
    /// path to connect to.  Abstract paths can be used by passing a NUL byte as the first byte of
    /// addr.
    pub fn connect_uds<P: AsRef<Path>>(addr: P) -> Result<Connection,Error> {
        let sock = try!(UnixStream::connect(addr));
        let mut conn = Connection {
            sock: Socket::Uds(sock),
            queue: Vec::new(),
            next_serial: 1
        };

        try!(conn.authenticate());
        Ok(conn)
    }

    /// Creates a Connection object using a TCP socket as the transport.  The addr is the host and
    /// port to connect to.
    pub fn connect_tcp<T: ToSocketAddrs>(addr: T) -> Result<Connection,Error> {
        let sock = try!(TcpStream::connect(addr));
        let mut conn = Connection {
            sock: Socket::Tcp(sock),
            queue: Vec::new(),
            next_serial: 1
        };

        try!(conn.authenticate());
        Ok(conn)
    }

    /// Blocks until a message comes in from the message bus.  The received message is returned.
    pub fn read_msg(&mut self) -> Result<Message,Error> {
        match self.queue.get(0) {
            Some(_) => return Ok(self.queue.remove(0)),
            _ => ()
        };
        let mut buf = Vec::new();
        let sock = self.get_sock();

        // Read and demarshal the fixed portion of the header
        try!(read_exactly(sock, &mut buf, 12));
        let mut offset = 0;
        let mut sig = "(yyyyuu)".to_string();
        let header = match try!(demarshal(&mut buf, &mut offset, &mut sig)) {
            Value::Struct(x) => x,
            x => panic!("Demarshal didn't return what we asked for: {:?}", x)
        };

        let mut v = header.objects;
        let mut msg : Message = Default::default();
        let endian : u8 = DBusDecoder::decode(v.remove(0)).unwrap();
        if endian == 'B' as u8 {
            msg.big_endian = true;
        }
        msg.message_type = message::MessageType(DBusDecoder::decode(v.remove(0)).unwrap());
        msg.flags = DBusDecoder::decode::<u8>(v.remove(0)).unwrap();
        msg.version = DBusDecoder::decode::<u8>(v.remove(0)).unwrap();
        let body_len = DBusDecoder::decode::<u32>(v.remove(0)).unwrap();
        msg.serial = DBusDecoder::decode::<u32>(v.remove(0)).unwrap();

        // Read array length
        try!(read_exactly(sock, &mut buf, 4));
        // demarshal consumes the buf, so save a copy for when we demarshal the entire array
        let mut buf_copy = buf.clone();
        offset = 12;
        sig = "u".to_string();
        let data = demarshal(&mut buf, &mut offset, &mut sig).ok().unwrap();
        let arr_len = DBusDecoder::decode::<u32>(data).unwrap() as usize;

        // Make buf_copy big enough for the entire array, and fill it
        buf_copy.reserve(arr_len);
        if try!(sock.take(arr_len as u64).read_to_end(&mut buf_copy)) != arr_len {
            return Err(Error::Disconnected);
        };

        offset = 12;
        sig = "a(yv)".to_string();
        let header_fields = match try!(demarshal(&mut buf_copy, &mut offset, &mut sig)) {
            Value::Array(x) => x,
            x => panic!("Demarshal didn't return what we asked for: {:?}", x)
        };

        msg.headers = Vec::new();
        for i in header_fields.objects {
            let mut st = match i {
                Value::Struct(x) => x,
                x => panic!("Demarshal didn't return what we asked for: {:?}", x)
            };
            let val = st.objects.remove(1);
            let code = DBusDecoder::decode::<u8>(st.objects.remove(0)).unwrap();
            let variant = match val {
                Value::Variant(x) => x,
                x => panic!("Demarshal didn't return what we asked for: {:?}", x)
            };
            msg.headers.push(HeaderField(code, variant));
        }

        // Read the padding, if any
        let trailing_pad = 8 - (offset % 8);
        if trailing_pad % 8 != 0 {
            try!(read_exactly(sock, &mut buf, trailing_pad));
        }

        // Finally, read the entire body
        if body_len > 0 {
            try!(read_exactly(sock, &mut msg.body, body_len as usize));
        }

        Ok(msg)
    }
}

pub trait MessageSender {
    fn send(&mut self, mbuf: &mut Message) -> Result<u32, Error>;
    fn call_sync(&mut self, mbuf: &mut Message) -> Result<Option<Vec<Value>>,Error>;
}

impl MessageSender for Connection {
    /// Sends a message over the connection.  The Message can be created by one of the functions
    /// from the message module, such as message::create_method_call .  On success, returns the
    /// serial number of the outgoing message so that the reply can be identified.
    fn send(&mut self, mbuf: &mut Message) -> Result<u32, Error> {
        let this_serial = self.next_serial;
        self.next_serial += 1;
        mbuf.serial = this_serial;

        let mut msg = Vec::new();
        mbuf.dbus_encode(&mut msg);

        let sock = self.get_sock();
        try!(sock.write_all(&msg));
        try!(sock.write_all(&mbuf.body));
        Ok(this_serial)
    }

    /// Sends a message over a connection and block until a reply is received.  This is only valid
    /// for method calls.  Returns the sequence of Value objects that is the body of the method
    /// return.
    ///
    /// # Panics
    /// Calling this function with a Message for other than METHOD_CALL or with the
    /// NO_REPLY_EXPECTED flag set is a programming error and will panic.
    fn call_sync(&mut self, mbuf: &mut Message) -> Result<Option<Vec<Value>>,Error> {
        assert_eq!(mbuf.message_type, message::MESSAGE_TYPE_METHOD_CALL);
        assert_eq!(mbuf.flags & message::FLAGS_NO_REPLY_EXPECTED, 0);
        let serial = try!(self.send(mbuf));
        // We need a local queue so that read_msg doesn't just give us
        // the same one over and over
        let mut queue = Vec::new();
        loop {
            let mut msg = try!(self.read_msg());
            match msg.headers.iter().position(|x| { x.0 == message::HEADER_FIELD_REPLY_SERIAL }) {
                Some(idx) => {
                    let obj = {
                        let x = &msg.headers[idx].1;
                        x.object.deref().clone()
                    };
                    let reply_serial : u32 = DBusDecoder::decode(obj).unwrap();
                    if reply_serial == serial {
                        // Move our queued messages into the Connection's queue
                        for _ in 0..queue.len() {
                            self.queue.push(queue.remove(0));
                        }
                        return Ok(try!(msg.get_body()))
                    };
                }
                _ => ()
            };
            queue.push(msg);
        }
    }
}

#[cfg(test)]
fn validate_connection(conn: &mut Connection) {
    let mut msg = message::create_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "ListNames");
    let resp = conn.call_sync(&mut msg).unwrap();
    println!("ListNames: {:?}", resp);
}

#[test]
fn test_connect_system() {
    let mut conn = Connection::connect_system().unwrap();
    validate_connection(&mut conn);
}

#[test]
fn test_connect_session() {
    let mut conn = Connection::connect_session().unwrap();
    validate_connection(&mut conn);
    let mut msg = message::create_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                              "org.freedesktop.DBus", "RequestName");
    msg = msg.add_arg(&"com.test.foobar")
             .add_arg(&(0 as u32));
    println!("{:?}", msg);
    let mut resp = conn.call_sync(&mut msg).unwrap().unwrap();
    println!("RequestName: {:?}", resp);
    let value = resp.remove(0);
    assert_eq!(value, Value::from(1 as u32));
}

#[test]
fn test_tcp() {
    let mut conn = Connection::connect(&env::var("DBUS_TCP_BUS_ADDRESS").unwrap()).unwrap();
    let mut msg = message::create_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "ListNames");
    conn.send(&mut msg).ok();
    let msg = conn.read_msg().unwrap();
    println!("{:?}", msg.body);
    //loop {
    //    conn.read_msg().unwrap();
    //}
}
