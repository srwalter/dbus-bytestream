use std::mem::transmute;
use std::hash::Hash;
use std::collections::HashMap;

use dbus_serialize::types::{Value,BasicValue,Path,Signature,Struct,Variant};

pub trait Marshal {
    /// Encodes itself into buf, and returns the number of bytes written excluding leading padding
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize;

    /// Returns the D-Bus type signature for this object
    fn get_type(&self) -> String;
}

// Saying a type implements BasicMarshal is a promise to the type system that it can be used as the
// key to a DICT_ENTRY
pub trait BasicMarshal : Marshal { }

pub fn pad_to_multiple (buf: &mut Vec<u8>, len: usize) -> () {
    let pad = (len - (buf.len() % len)) % len;
    for _ in 0..pad {
        buf.push(0);
    }
}

fn marshal_int (x: u64, len: usize, buf: &mut Vec<u8>) -> usize {
    pad_to_multiple(buf, len);

    // We always encode in little endian so that the interesting bytes are at the beginning of the
    // byte array.  This lets us use a fixed size buffer to transmute into, otherwise we couldn't
    // have this nice generic function.  However, that also means if we somehow get a type that's
    // larger than a u64, we'll get undefined behavior from the unsafe code.  assert that doesn't
    // happen.
    assert!(len <= 8);
    let bytes : [u8; 8] = unsafe { transmute(x.to_le()) };
    for i in 0..len {
        buf.push(bytes[i]);
    }
    len
}

// Same as above except we don't convert to little-endian
fn marshal_double (x: f64, buf: &mut Vec<u8>) -> usize {
    let len = 8;
    pad_to_multiple(buf, len);

    let bytes : [u8; 8] = unsafe { transmute(x) };
    for i in 0..len {
        buf.push(bytes[i]);
    }
    len
}

fn marshal_string (x: String, buf: &mut Vec<u8>) -> usize {
    let bytes = x.into_bytes();
    let len = bytes.len() as u32;
    let total_len = len.dbus_encode(buf);
    for i in 0..len {
        buf.push(bytes[i as usize]);
    }
    buf.push(0);
    total_len + (len as usize) + 1
}

fn marshal_signature (x: String, buf: &mut Vec<u8>) -> usize {
    let bytes = x.into_bytes();
    let len = bytes.len() as u8;
    let total_len = len.dbus_encode(buf);
    for i in 0..len {
        buf.push(bytes[i as usize]);
    }
    buf.push(0);
    total_len + (len as usize) + 1
}

impl Marshal for u8 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        buf.push(*self);
        1
    }
    fn get_type (&self) -> String {
        "y".to_string()
    }
}

impl BasicMarshal for u8 { }

impl Marshal for bool {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        let val = match *self {
            true => 1,
            false => 0
        };
        marshal_int(val, 4, buf)
    }
    fn get_type (&self) -> String {
        "b".to_string()
    }
}
impl BasicMarshal for bool { }

impl Marshal for i16 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 2, buf)
    }
    fn get_type (&self) -> String {
        "n".to_string()
    }
}
impl BasicMarshal for i16 { }

impl Marshal for u16 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 2, buf)
    }
    fn get_type (&self) -> String {
        "q".to_string()
    }
}
impl BasicMarshal for u16 { }

impl Marshal for i32 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 4, buf)
    }
    fn get_type (&self) -> String {
        "i".to_string()
    }
}
impl BasicMarshal for i32 { }

impl Marshal for u32 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 4, buf)
    }
    fn get_type (&self) -> String {
        "u".to_string()
    }
}
impl BasicMarshal for u32 { }

impl Marshal for i64 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 8, buf)
    }
    fn get_type (&self) -> String {
        "x".to_string()
    }
}
impl BasicMarshal for i64 { }

impl Marshal for u64 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_int(*self as u64, 8, buf)
    }
    fn get_type (&self) -> String {
        "t".to_string()
    }
}
impl BasicMarshal for u64 { }

impl Marshal for f64 {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_double(*self, buf)
    }
    fn get_type (&self) -> String {
        "d".to_string()
    }
}
impl BasicMarshal for f64 { }

impl<'a> Marshal for &'a str {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_string(self.to_string(), buf)
    }
    fn get_type (&self) -> String {
        "s".to_string()
    }
}
impl<'a> Marshal for String {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_string(self.to_string(), buf)
    }
    fn get_type (&self) -> String {
        "s".to_string()
    }
}
impl<'a> BasicMarshal for &'a str { }

impl Marshal for Path {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_string(self.0.to_string(), buf)
    }
    fn get_type (&self) -> String {
        "o".to_string()
    }
}
impl BasicMarshal for Path { }

impl Marshal for Signature {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        marshal_signature(self.0.to_string(), buf)
    }
    fn get_type (&self) -> String {
        "o".to_string()
    }
}
impl BasicMarshal for Signature { }

impl Marshal for Struct {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        pad_to_multiple(buf, 8);
        let start_len = buf.len();
        for i in &self.objects {
            i.dbus_encode(buf);
        }
        buf.len() - start_len
    }

    fn get_type(&self) -> String {
        self.signature.0.to_string()
    }
}

impl<T: Marshal> Marshal for Vec<T> {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        // Encode a length of 0 as a place-holder since we don't know the real length yet
        let mut array_len = 0 as u32;
        array_len.dbus_encode(buf);
        let start_len = buf.len();
        let len_idx = start_len - 4;
        for x in self {
            x.dbus_encode(buf);
        }
        array_len = (buf.len() - start_len) as u32;

        // Update the encoded length with the real value
        let mut len_buf = Vec::new();
        array_len.dbus_encode(&mut len_buf);
        for i in 0..4 {
            buf[len_idx+i] = len_buf[i];
        }
        (array_len as usize) + 4
    }
    fn get_type(&self) -> String {
        "a".to_string() + &(self.iter().next().unwrap().get_type())
    }
}

struct DictEntry<K,V> {
    key: K,
    value: V
}

impl<K,V> Marshal for DictEntry<K, V>
        where K: Clone + Hash + Eq + BasicMarshal,
              V: Marshal {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        pad_to_multiple(buf, 8);
        let start_len = buf.len();
        self.key.dbus_encode(buf);
        self.value.dbus_encode(buf);
        buf.len() - start_len
    }
    fn get_type(&self) -> String {
        "{".to_string() + &self.key.get_type() + &self.value.get_type() + "}"
    }
}

impl<K,V> Marshal for HashMap<K, V>
        where K: Clone + Hash + Eq + BasicMarshal,
              V: Clone + Marshal {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        // Convert the map to an array of DictEntry
        let mut array = Vec::new();
        for (key, value) in self {
            array.push(DictEntry{key: key.clone(), value: value.clone()});
        }
        array.dbus_encode(buf)
    }
    fn get_type(&self) -> String {
        "a".to_string() + "{" + &self.keys().next().unwrap().get_type() + &self.values().next().unwrap().get_type() + "}"
    }
}

impl Marshal for Variant {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        let len = self.signature.dbus_encode(buf);
        // We want to include any padding from the variant payload, so we can't just add the return
        // value of the second dbus_encode
        let old_len = buf.len();
        self.object.dbus_encode(buf);
        len + buf.len() - old_len
    }
    fn get_type(&self) -> String {
        "v".to_string()
    }
}

impl Marshal for BasicValue {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        match self {
            &BasicValue::Byte(ref x) => x.dbus_encode(buf),
            &BasicValue::Boolean(ref x) => x.dbus_encode(buf),
            &BasicValue::Int16(ref x) => x.dbus_encode(buf),
            &BasicValue::Uint16(ref x) => x.dbus_encode(buf),
            &BasicValue::Int32(ref x) => x.dbus_encode(buf),
            &BasicValue::Uint32(ref x) => x.dbus_encode(buf),
            &BasicValue::Int64(ref x) => x.dbus_encode(buf),
            &BasicValue::Uint64(ref x) => x.dbus_encode(buf),
            &BasicValue::String(ref x) => x.dbus_encode(buf),
            &BasicValue::ObjectPath(ref x) => x.dbus_encode(buf),
            &BasicValue::Signature(ref x) => x.dbus_encode(buf),
        }
    }

    fn get_type(&self) -> String {
        match self {
            &BasicValue::Byte(_) => "y".to_string(),
            &BasicValue::Boolean(_) => "b".to_string(),
            &BasicValue::Int16(_) => "n".to_string(),
            &BasicValue::Uint16(_) => "q".to_string(),
            &BasicValue::Int32(_) => "i".to_string(),
            &BasicValue::Uint32(_) => "u".to_string(),
            &BasicValue::Int64(_) => "x".to_string(),
            &BasicValue::Uint64(_) => "t".to_string(),
            &BasicValue::String(_) => "s".to_string(),
            &BasicValue::ObjectPath(_) => "o".to_string(),
            &BasicValue::Signature(_) => "g".to_string(),
        }
    }
}

impl BasicMarshal for BasicValue { }

impl Marshal for Value {
    fn dbus_encode(&self, buf: &mut Vec<u8>) -> usize {
        match self {
            &Value::BasicValue(ref x) => x.dbus_encode(buf),
            &Value::Double(ref x) => x.dbus_encode(buf),
            &Value::Array(ref x) => x.dbus_encode(buf),
            &Value::Variant(ref x) => x.dbus_encode(buf),
            &Value::Struct(ref x) => x.dbus_encode(buf),
            &Value::Dictionary(ref x) => x.dbus_encode(buf)
        }
    }

    fn get_type(&self) -> String {
        match self {
            &Value::BasicValue(ref x) => x.get_type(),
            &Value::Double(_) => "d".to_string(),
            &Value::Array(ref x) => x.iter().next().unwrap().get_type(),
            &Value::Variant(_) => "v".to_string(),
            &Value::Struct(ref x) => x.get_type(),
            &Value::Dictionary(ref x) => {
                let key_type = x.keys().next().unwrap().get_type();
                let val_type = x.values().next().unwrap().get_type();
                "a{".to_string() + &key_type + &val_type + "}"
            }
        }
    }
}

#[test]
fn test_ints () {
    let x: u32 = 1;
    let x_bytes = vec![0, 0, 0, 0, 1, 0, 0, 0];
    // Start with a non-empty buffer to test padding
    let mut buf = vec![0];
    let len = x.dbus_encode(&mut buf);
    assert_eq!(len, 4);
    assert_eq!(buf, x_bytes);
    assert_eq!("u", x.get_type());
}

#[test]
fn test_string () {
    let x = "abc123";
    let x_bytes = vec![6, 0, 0, 0, 'a' as u8, 'b' as u8, 'c' as u8, '1' as u8, '2' as u8, '3' as u8, 0];
    let mut x_buf = Vec::new();
    let len = x.dbus_encode(&mut x_buf);
    assert_eq!(len, x_bytes.len());
    assert_eq!(x_buf, x_bytes);
}

#[test]
fn test_array () {
    //assert_eq!("ay", Vec::<u8>::get_type());
    //assert_eq!("aay", Vec::<Vec<u8>>::get_type());

    let empty_array : Vec<u8> = Vec::new();
    let mut bytes = vec![0, 0, 0, 0];
    let mut buf = Vec::new();
    let len = empty_array.dbus_encode(&mut buf);
    assert_eq!(buf, bytes);
    assert_eq!(len, buf.len());

    let array : Vec<u32> = vec![1, 2, 3];
    bytes = vec![12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
    buf = Vec::new();
    array.dbus_encode(&mut buf);
    assert_eq!(buf, bytes);
}

#[test]
fn test_variant () {
    let v = Variant{
        object: Box::new(Value::BasicValue(BasicValue::Uint32(42))),
        signature: Signature("u".to_string())
    };
    assert_eq!(v.get_type(), "v");
    let v_bytes = vec![1, 'u' as u8, 0, 0, 42, 0, 0, 0];

    let mut buf = Vec::new();
    let len = v.dbus_encode(&mut buf);
    assert_eq!(len, 8);
    assert_eq!(buf, v_bytes);
}
