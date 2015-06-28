use std::net::TcpStream;
use std::collections::HashMap;
use std::io;
use std::io::{Read,Write};
use std::ops::Deref;

use dbus_serialize::types::{Value,BasicValue};

use message;
use message::{Message,HeaderFieldName,MessageBuf};
use demarshal::{demarshal,DemarshalError};
use marshal::Marshal;

pub struct Connection {
    sock: TcpStream,
    next_serial: u32
}

#[derive(Debug)]
pub enum Error {
    Disconnected,
    IOError(io::Error),
    DemarshalError(DemarshalError),
    BadData
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

macro_rules! read_exactly {
    ( $sock:ident, $buf:ident, $len:expr ) => {{
        $buf.truncate(0);
        $buf.reserve($len);
        if try!($sock.take($len as u64).read_to_end(&mut $buf)) != $len {
            return Err(Error::Disconnected);
        }
    }};
}

impl Connection {
    pub fn connect(addr: &str) -> Result<Connection,Error> {
        let sock = try!(TcpStream::connect(addr));
        let mut conn = Connection{sock: sock, next_serial: 1};

        // Authenticate to the daemon
        let buf = vec![0];
        try!(conn.sock.write_all(&buf));
        try!(conn.sock.write_all(b"AUTH ANONYMOUS 6c69626462757320312e382e3132\r\n"));

        // Read response
        // XXX: do a proper line-oriented read...
        let mut buf2 = vec![0; 128];
        conn.sock.read(&mut buf2).unwrap();

        // Ready for action
        try!(conn.sock.write_all(b"BEGIN\r\n"));

        // Say Hello
        let mut msg = message::create_method_call("org.freedesktop.DBus",
                                                  "/org/freedesktop/DBus",
                                                  "org.freedesktop.DBus",
                                                  "Hello");
        try!(conn.send(&mut msg));

        // XXX: validate Hello reply
        conn.read_msg().unwrap();
        Ok(conn)
    }

    pub fn send(&mut self, mbuf: &mut MessageBuf) -> Result<(),Error> {
        let mut msg = &mut mbuf.0;
        // A minimum header with no body is 16 bytes
        let mut len = msg.len() as u32;
        if len < 16 {
            return Err(Error::BadData);
        }

        // Get the current length from the message, which only include the length of the header.
        // That field should actually be the length of only the body, so update that now
        let old_len = message::get_length(msg);
        len -= old_len;
        let mut buf = Vec::new();
        len.dbus_encode(&mut buf);
        // Update the message with a correct serial number, as well
        self.next_serial.dbus_encode(&mut buf);
        self.next_serial += 1;
        message::set_length(msg, &buf);

        try!(self.sock.write_all(msg));
        Ok(())
    }

    pub fn read_msg(&mut self) -> Result<Message,Error> {
        let mut buf = Vec::new();
        let sock = &self.sock;

        // Read and demarshal the fixed portion of the header
        read_exactly!(sock, buf, 12);
        let mut offset = 0;
        let mut sig = "(yyyyuu)".to_string();
        let header = match try!(demarshal(&mut buf, &mut offset, &mut sig)) {
            Value::Struct(x) => x,
            x => panic!("Demarshal didn't return what we asked for: {:?}", x)
        };

        let v = header.objects;
        let mut msg : Message = Default::default();
        let endian = u8::from(&v[0]);
        if endian == 'B' as u8 {
            msg.big_endian = true;
        }
        msg.message_type = message::MessageType(u8::from(&v[1]));
        msg.flags = u8::from(&v[2]);
        msg.version = u8::from(&v[3]);
        let body_len = u32::from(&v[4]);
        msg.serial = u32::from(&v[5]);

        // Read array length
        read_exactly!(sock, buf, 4);
        // demarshal consumes the buf, so save a copy for when we demarshal the entire array
        let mut buf_copy = buf.clone();
        offset = 12;
        sig = "u".to_string();
        let data = demarshal(&mut buf, &mut offset, &mut sig).ok().unwrap();
        let arr_len = u32::from(&data) as usize;

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

        msg.headers = HashMap::new();
        for i in header_fields {
            let mut st = match i {
                Value::Struct(x) => x,
                x => panic!("Demarshal didn't return what we asked for: {:?}", x)
            };
            let val = st.objects.remove(1);
            let code = u8::from(&st.objects[0]);
            msg.headers.insert(code, val);
        }

        // Read the padding, if any
        let trailing_pad = 8 - (offset % 8);
        if trailing_pad % 8 != 0 {
            read_exactly!(sock, buf, trailing_pad);
        }

        // Finally, read the entire body
        if body_len > 0 {
            let v = match msg.headers.get(&(HeaderFieldName::Signature as u8)) {
                Some(&Value::Variant(ref x)) => x,
                _ => return Err(Error::DemarshalError(DemarshalError::BadSignature))
            };

            let sigval = match v.object.deref() {
                &Value::BasicValue(BasicValue::Signature(ref x)) => x,
                _ => return Err(Error::DemarshalError(DemarshalError::BadSignature))
            };

            let mut body = Vec::new();
            read_exactly!(sock, body, body_len as usize);

            let mut sig = "(".to_string() + &sigval.0 + ")";
            offset = 0;
            let objs = match try!(demarshal(&mut body, &mut offset, &mut sig)) {
                Value::Struct(x) => x.objects,
                x => panic!("Didn't get a struct: {:?}", x)
            };
            for x in objs {
                msg.body.push(x);
            }
        }

        Ok(msg)
    }
}

#[test]
fn test_connect () {
    let mut conn = Connection::connect("localhost:12345").ok().unwrap();
    let mut msg = message::create_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                          "org.freedesktop.DBus", "ListNames");
    conn.send(&mut msg).ok();
    let msg = conn.read_msg().unwrap();
    println!("{:?}", msg.body);
    //loop {
    //    conn.read_msg().unwrap();
    //}
}
