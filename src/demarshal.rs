use std::collections::HashMap;
use std::mem::transmute;

use dbus_serialize::types::{Value,BasicValue,Path,Signature,Struct,Variant,Array,Dictionary};

#[derive(Debug)]
pub enum DemarshalError {
    MessageTooShort,
    CorruptedMessage,
    BadUTF8,
    BadSignature,
    ElementTooBig,
    MismatchedParens,
}

pub fn get_alignment(sig: char) -> usize {
    match sig {
        'y' => 1,
        'b' => 1,
        'n' => 2,
        'q' => 2,
        'i' => 4,
        'u' => 4,
        'x' => 8,
        't' => 8,
        's' => 4,
        'o' => 4,
        'g' => 1,

        'a' => 4,
        '(' => 8,
        '{' => 8,
        'v' => 1,
        _ => panic!("Bogus type")
    }
}

fn demarshal_byte(buf: &mut Vec<u8>, offset: &mut usize) -> Result<Value,DemarshalError> {
    if buf.len() < 1 {
        return Err(DemarshalError::MessageTooShort);
    }
    let byte = buf.remove(0);
    *offset += 1;
    Ok(Value::BasicValue(BasicValue::Byte(byte)))
}

fn align_to(buf: &mut Vec<u8>, offset: &mut usize, align: usize) -> Result<(),DemarshalError> {
    if *offset % align == 0 {
        return Ok(());
    }
    let delta = align - (*offset % align);
    if buf.len() < delta {
        return Err(DemarshalError::MessageTooShort);
    }
    for _ in 0..delta {
        buf.remove(0);
        *offset += 1;
    }
    Ok(())
}

fn demarshal_bool(buf: &mut Vec<u8>, offset: &mut usize) -> Result<Value,DemarshalError> {
    try!(align_to(buf, offset, 4));
    if buf.len() < 4 {
        return Err(DemarshalError::MessageTooShort);
    }
    let byte = buf.remove(0);
    *offset += 1;
    // XXX: assumes LE
    for _ in 0..3 {
        *offset += 1;
        // Only the first byte should have a non-zero value
        if buf.remove(0) != 0 {
            return Err(DemarshalError::CorruptedMessage);
        }
    }
    match byte {
        0 => Ok(Value::BasicValue(BasicValue::Boolean(false))),
        1 => Ok(Value::BasicValue(BasicValue::Boolean(true))),
        _ => Err(DemarshalError::CorruptedMessage)
    }
}

fn demarshal_int(buf: &mut Vec<u8>, offset: &mut usize, len: usize, is_signed: bool) -> Result<Value,DemarshalError> {
    try!(align_to(buf, offset, len));
    if buf.len() < len {
        return Err(DemarshalError::MessageTooShort);
    }
    let mut intbuf = [0; 8];
    for i in 0..len {
        intbuf[i] = buf.remove(0);
        *offset += 1;
    }
    // Check for sign-extension
    if is_signed && (intbuf[len-1] & 128 == 128) {
        for i in len..8 {
            intbuf[i] = 0xff;
        }
    }
    let val : u64 = unsafe { transmute(intbuf) };
    if is_signed {
        match len {
            2 => Ok(Value::BasicValue(BasicValue::Int16(val as i16))),
            4 => Ok(Value::BasicValue(BasicValue::Int32(val as i32))),
            8 => Ok(Value::BasicValue(BasicValue::Int64(val as i64))),
            _ => panic!("Bogus length {}", len)
        }
    } else {
        match len {
            1 => Ok(Value::BasicValue(BasicValue::Byte(val as u8))),
            2 => Ok(Value::BasicValue(BasicValue::Uint16(val as u16))),
            4 => Ok(Value::BasicValue(BasicValue::Uint32(val as u32))),
            8 => Ok(Value::BasicValue(BasicValue::Uint64(val))),
            _ => panic!("Bogus length {}", len)
        }
    }
}

fn demarshal_string(buf: &mut Vec<u8>, offset: &mut usize, count_size: usize, is_path: bool) -> Result<Value,DemarshalError> {
    // demarshal_int ensure we're correctly aligned with input
    let len = match demarshal_int(buf, offset, count_size, false) {
        Ok(Value::BasicValue(BasicValue::Uint32(x))) => x,
        Ok(Value::BasicValue(BasicValue::Byte(x))) => x as u32,
        _ => return Err(DemarshalError::CorruptedMessage),
    };
    let mut strbuf = Vec::new();
    for _ in 0..len {
        strbuf.push(buf.remove(0));
        *offset += 1
    }
    // Check the NUL byte
    if buf.remove(0) != 0 {
        return Err(DemarshalError::CorruptedMessage);
    }
    *offset += 1;
    let val = try!(String::from_utf8(strbuf).or(Err(DemarshalError::BadUTF8)));
    if is_path {
        Ok(Value::BasicValue(BasicValue::ObjectPath(Path(val))))
    } else {
        if count_size == 4 {
            Ok(Value::BasicValue(BasicValue::String(val)))
        } else {
            Ok(Value::BasicValue(BasicValue::Signature(Signature(val))))
        }
    }
}

fn demarshal_array(buf: &mut Vec<u8>, offset: &mut usize, sig: &mut String) -> Result<Value,DemarshalError> {
    if sig.len() < 1 {
        return Err(DemarshalError::BadSignature);
    }
    let typ = sig.chars().next().unwrap();
    let is_dict = typ == '{';
    // demarshal_int ensure we're correctly aligned with input
    let array_len = match demarshal_int(buf, offset, 4, false) {
        Ok(Value::BasicValue(BasicValue::Uint32(x))) => x,
        _ => return Err(DemarshalError::CorruptedMessage),
    };
    if array_len > 1 << 26 {
        return Err(DemarshalError::ElementTooBig);
    }
    try!(align_to(buf, offset, get_alignment(typ)));
    if buf.len() < (array_len as usize) {
        return Err(DemarshalError::MessageTooShort);
    }

    let mut vec = Vec::new();
    let start_offset = *offset;
    let mut sig_copy = "".to_owned();
    while *offset < start_offset+(array_len as usize) {
        // We want to pass the same signature to each call of demarshal
        sig_copy = sig.to_owned();
        vec.push(try!(demarshal(buf, offset, &mut sig_copy)));
    }
    // Now that we're done with our elements we can forget the elements consumed by demarshal
    let mut mysig = sig.clone();
    mysig.truncate(sig.len() - sig_copy.len());
    mysig.insert(0, 'a');
    *sig = sig_copy;

    if is_dict {
        let mut map : HashMap<BasicValue,Value> = HashMap::new();
        for x in vec {
            let mut s = match x {
                Value::Struct(x) => x,
                _ => panic!("Dictionaries should contain structs")
            };
            let val = s.objects.remove(1);
            let key = match s.objects[0] {
                Value::BasicValue(ref x) => x,
                _ => panic!("Dictionaries require BasicValue keys")
            };
            map.insert(key.clone(), val);
        }
        return Ok(Value::Dictionary(Dictionary::new_with_sig(map, mysig)));
    }

    Ok(Value::Array(Array::new_with_sig(vec, mysig)))
}

fn demarshal_struct(buf: &mut Vec<u8>, offset: &mut usize, sig: &mut String) -> Result<Value,DemarshalError> {
    if sig.len() < 1 {
        return Err(DemarshalError::BadSignature);
    }
    try!(align_to(buf, offset, 8));

    let mut vec = Vec::new();
    let mut mysig = sig.to_owned();
    loop {
        let typ = match sig.chars().next() {
            Some(x) => x,
            None => return Err(DemarshalError::MismatchedParens)
        };
        if typ == ')' {
            sig.remove(0);
            break;
        }
        vec.push(try!(demarshal(buf, offset, sig)));
    }
    // Only keep the characters that were consumed by demarshal
    let oldlen = mysig.len();
    mysig.truncate(oldlen - sig.len());
    mysig.insert(0, '(');

    Ok(Value::Struct(Struct{
        objects: vec,
        signature: Signature(mysig)
    }))
}

fn demarshal_variant(buf: &mut Vec<u8>, offset: &mut usize) -> Result<Value,DemarshalError> {
    let mut variant_sig = "g".to_owned();
    let sigval = try!(demarshal(buf, offset, &mut variant_sig));
    let sig = match sigval {
        Value::BasicValue(BasicValue::Signature(x)) => x,
        _ => return Err(DemarshalError::CorruptedMessage)
    };
    let mut s = sig.0.to_owned();
    let var = try!(demarshal(buf, offset, &mut s));
    Ok(Value::Variant(Variant{
        object: Box::new(var),
        signature: sig
    }))
}

pub fn demarshal(buf: &mut Vec<u8>, offset: &mut usize, sig: &mut String) -> Result<Value,DemarshalError> {
    let typ = sig.remove(0);
    match typ {
        'y' => demarshal_byte(buf, offset),
        'b' => demarshal_bool(buf, offset),
        'n' => demarshal_int(buf, offset, 2, true),
        'q' => demarshal_int(buf, offset, 2, false),
        'i' => demarshal_int(buf, offset, 4, true),
        'u' => demarshal_int(buf, offset, 4, false),
        'x' => demarshal_int(buf, offset, 8, true),
        't' => demarshal_int(buf, offset, 8, false),
        's' => demarshal_string(buf, offset, 4, false),
        'o' => demarshal_string(buf, offset, 4, true),
        'g' => demarshal_string(buf, offset, 1, false),

        'a' => demarshal_array(buf, offset, sig),
        '(' => demarshal_struct(buf, offset, sig),
        '{' => demarshal_struct(buf, offset, sig),
        'v' => demarshal_variant(buf, offset),
        _ => Err(DemarshalError::BadSignature)
    }
}

#[cfg(test)]
mod test {
    use marshal::Marshal;
    use demarshal::demarshal;
    use dbus_serialize::types::{Value,BasicValue,Signature};

    #[test]
    fn test_demarshal_u32() {
        let mut buf = Vec::new();
        let x = 16 as u32;
        let mut sig = x.get_type().to_string();
        x.dbus_encode(&mut buf);

        let mut offset = 0;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        assert_eq!(v, Value::BasicValue(BasicValue::Uint32(16)));
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
    }

    #[test]
    fn test_demarshal_u32_offset() {
        let mut buf = Vec::new();
        buf.insert(0, 0);
        let x = 16 as u32;
        let mut sig = x.get_type();
        x.dbus_encode(&mut buf);

        buf.remove(0);
        let mut offset = 1;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        assert_eq!(v, Value::BasicValue(BasicValue::Uint32(16)));
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
    }

    #[test]
    fn test_string() {
        let mut buf = Vec::new();
        let x = "swalter".to_string();
        let mut sig = x.get_type();
        x.dbus_encode(&mut buf);

        let mut offset = 0;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        assert_eq!(v, Value::BasicValue(BasicValue::String("swalter".to_string())));
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
    }

    #[test]
    fn test_array() {
        let mut buf = Vec::new();
        let x = vec![1 as u32, 2 as u32, 3 as u32];
        let mut sig = "au".to_string();
        x.dbus_encode(&mut buf);

        let mut offset = 0;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        let arr = match v {
            Value::Array(x) => x,
            _ => panic!("Bad return from demarshal {:?}", v)
        };
        let golden = vec![
            Value::BasicValue(BasicValue::Uint32(1)),
            Value::BasicValue(BasicValue::Uint32(2)),
            Value::BasicValue(BasicValue::Uint32(3)),
        ];
        assert_eq!(arr.objects, golden);
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
    }

    #[test]
    fn test_array_bytes() {
        let mut buf = Vec::new();
        let x = vec![1 as u8, 2 as u8, 3 as u8];
        let mut sig = "ay".to_string();
        x.dbus_encode(&mut buf);

        let mut offset = 0;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        let arr = match v {
            Value::Array(x) => x,
            _ => panic!("Bad return from demarshal {:?}", v)
        };
        let golden = vec![
            Value::BasicValue(BasicValue::Byte(1)),
            Value::BasicValue(BasicValue::Byte(2)),
            Value::BasicValue(BasicValue::Byte(3)),
        ];
        assert_eq!(arr.objects, golden);
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
    }

    #[test]
    fn test_struct() {
        let mut buf = Vec::new();
        let x = "swalter".to_string();
        let mut sig = "(ss)".to_string();
        x.dbus_encode(&mut buf);
        x.dbus_encode(&mut buf);

        let mut offset = 0;
        let v = demarshal(&mut buf, &mut offset, &mut sig).unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(sig, "");
        let s = match v {
            Value::Struct(x) => x,
            _ => panic!("Bad return from demarshal {:?}", v)
        };
        assert_eq!(s.signature, Signature("(ss)".to_string()));
    }
}
