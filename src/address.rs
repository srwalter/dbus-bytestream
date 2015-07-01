use std::path::{Path, PathBuf};
use std::string;
use std::str::FromStr;
use std::str::Split;

use rustc_serialize::hex::{FromHex,FromHexError};

#[derive(Debug, PartialEq)]
pub enum UnescapeError {
    ShortEscapeSequence,
    EscapeNotUtf8,
    HexConversionError
}

impl From<FromHexError> for UnescapeError {
    fn from(_: FromHexError) -> Self {
        UnescapeError::HexConversionError
    }
}

impl From<string::FromUtf8Error> for UnescapeError {
    fn from(_: string::FromUtf8Error) -> Self {
        UnescapeError::EscapeNotUtf8
    }
}

fn dbus_unescape(buf: &[u8]) -> Result<Vec<u8>, UnescapeError> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = buf.iter();
    while let Some(c) = i.next() {
        if *c == b'%' {
            let c1 = *try!(i.next().ok_or(UnescapeError::ShortEscapeSequence));
            let c2 = *try!(i.next().ok_or(UnescapeError::ShortEscapeSequence));
            let x = try!(String::from_utf8(vec!(c1, c2)));
            out.push(*try!(x.from_hex()).get(0).unwrap());
        } else {
            out.push(*c);
        }
    }
    Ok(out)
}

fn dbus_unescape_str(s: &str) -> Result<String, UnescapeError> {
    let vec = try!(dbus_unescape(s.as_bytes()));
    String::from_utf8(vec).map_err(From::from)
}

#[derive(Debug, PartialEq)]
pub enum Error {
    UnescapeError(UnescapeError),
    BadTransportSeparator,
    MalformedKeyValue,
    UnknownTransport,
    UnknownOption,
    MissingOption,
    ConflictingOptions,
}

pub type ServerAddressError = (Error, String);

impl From<UnescapeError> for ServerAddressError {
    fn from(e: UnescapeError) -> Self {
        (Error::UnescapeError(e), "".to_string())
    }
}


/// Iterator over key value pairs of the form "key=val,key=val"
struct AddrKeyVals<'a> {
    str: Split<'a, char>,
}

impl<'a> AddrKeyVals<'a> {
    fn new(s: &'a str) -> Self {
        AddrKeyVals { str: s.split(',') }
    }

    fn get_next(&mut self) -> Option<&'a str> {
        loop {
            let kvs = self.str.next();
            if kvs.is_none() || kvs.unwrap() != "" {
                return kvs;
            }
        }
    }
}

impl<'a> Iterator for AddrKeyVals<'a> {
    type Item = Result<(String, String), ServerAddressError>;

    fn next(&mut self) -> Option<Self::Item> {
        let kvs = self.get_next();
        if kvs.is_none() {
            return None;
        }
        let mut keyval = kvs.unwrap().split('=');
        if keyval.clone().count() != 2 {
            return Some(Err((Error::MalformedKeyValue, kvs.unwrap().to_string())));
        }

        let key = dbus_unescape_str(keyval.next().unwrap());
        if let Err(e) = key {
            return Some(Err(From::from(e)));
        }
        let val = dbus_unescape_str(keyval.next().unwrap());
        if let Err(e) = val {
            return Some(Err(From::from(e)));
        }
        // Unwrap is ok because we just checked that there are two elements
        Some(Ok((key.unwrap(), val.unwrap())))
    }
}

/// A DBus Unix address
#[derive(Debug)]
pub struct UnixAddress {
    path: PathBuf,
}

impl<'a> UnixAddress {
    /// Returns the Unix path
    pub fn path(&'a self) -> &'a Path {
        self.path.as_path()
    }
}

impl FromStr for UnixAddress {
    type Err = ServerAddressError;

    /// Constructs a UnixAddress from a key=value option string
    fn from_str(opts: &str) -> Result<Self, ServerAddressError> {
        let keyvals = AddrKeyVals::new(opts);
        let mut path = None;
        let mut abs = false;
        for kv in keyvals {
            let kv = try!(kv);

            match kv.0.as_ref() {
                "path" | "abstract" => {
                    if path.is_none() {
                        path = Some(kv.1);
                    } else {
                        return Err((Error::ConflictingOptions,
                                    "Duplicate path/abstract specified".to_string()));
                    }
                },
                "guid" => {}, // Ignore for now
                _ => return Err((Error::UnknownOption, kv.0))
            }
            if kv.0 == "abstract" {
                abs = true;
            }
        }
        if path == None {
            Err((Error::MissingOption, "No path for unix socket".to_string()))
        } else {
            let mut path = path.unwrap();
            if abs {
                path = "\0".to_string() + &path;
            }
            Ok(UnixAddress { path: PathBuf::from(path) })
        }
    }
}

#[derive(Debug)]
pub enum ServerAddress {
    Unix(UnixAddress),
}

impl FromStr for ServerAddress {
    type Err = ServerAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut sp = s.split(':');
        if sp.clone().count() != 2 {
            return Err((Error::BadTransportSeparator, s.to_string()));
        }
        // Unwrap is ok because we just checked that there are two elements
        let transport = sp.next().unwrap();
        let opts = sp.next().unwrap();

        match transport {
            "unix" => Ok(ServerAddress::Unix(try!(UnixAddress::from_str(opts)))),
            _ => Err((Error::UnknownTransport, transport.to_string())),
        }
    }
}

#[test]
fn test_unescape() {
    assert_eq!(dbus_unescape(b"hello").unwrap(), b"hello");
    assert_eq!(dbus_unescape(b"\\").unwrap(), b"\\");
    assert_eq!(dbus_unescape(b"%61").unwrap(), b"a");
    assert_eq!(dbus_unescape(b"%5c").unwrap(), b"\\");
    assert_eq!(dbus_unescape(b"%").unwrap_err(), UnescapeError::ShortEscapeSequence);
    assert_eq!(dbus_unescape(b"%1").unwrap_err(), UnescapeError::ShortEscapeSequence);
}

#[test]
fn test_key_vals() {
    let mut a = AddrKeyVals::new("one=two").map(Result::unwrap);
    assert_eq!(a.next().unwrap(), ("one".to_string(), "two".to_string()));
    assert_eq!(a.next(), None);

    let mut a = AddrKeyVals::new("foo=bar,").map(Result::unwrap);
    assert_eq!(a.next().unwrap(), ("foo".to_string(), "bar".to_string()));
    assert_eq!(a.next(), None);

    let mut a = AddrKeyVals::new("foo=bar,a=b").map(Result::unwrap);
    assert_eq!(a.next().unwrap(), ("foo".to_string(), "bar".to_string()));
    assert_eq!(a.next().unwrap(), ("a".to_string(), "b".to_string()));
    assert_eq!(a.next(), None);

    let mut a = AddrKeyVals::new("foobar,a=b");
    assert_eq!(a.next().unwrap().unwrap_err().0, Error::MalformedKeyValue);
}

#[test]
fn test_server_address() {
    assert_eq!(ServerAddress::from_str("unix").unwrap_err().0, Error::BadTransportSeparator);
    ServerAddress::from_str("unix:path=/var/run/dbus/system_bus_socket").unwrap();
    assert_eq!(ServerAddress::from_str("unix:path=/var/run/dbus/system_bus_socket,foo=bar").unwrap_err().0, Error::UnknownOption);
    assert_eq!(ServerAddress::from_str("unix:").unwrap_err().0, Error::MissingOption);
}
