//! Modified UTF-7 mailbox name encoding (RFC 3501, section 5.1.3).
//!
//! IMAP transmits non-ASCII folder names in a variant of UTF-7. Callers of
//! this crate always see and pass ordinary UTF-8 names.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Encodes a UTF-8 folder name for use on the wire.
pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending = Vec::new();
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush_base64(&mut out, &mut pending);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut units = [0_u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    flush_base64(&mut out, &mut pending);
    out
}

/// Writes pending UTF-16 code units as a `&...-` shifted run.
fn flush_base64(out: &mut String, pending: &mut Vec<u16>) {
    if pending.is_empty() {
        return;
    }
    let bytes: Vec<u8> = pending.drain(..).flat_map(u16::to_be_bytes).collect();
    out.push('&');
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for index in 0..=chunk.len() {
            let shift = 18 - 6 * index;
            out.push(char::from(ALPHABET[((bits >> shift) & 0x3f) as usize]));
        }
    }
    out.push('-');
}

/// Decodes a wire folder name. Returns `None` if the name is not valid
/// modified UTF-7.
pub fn decode(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let shifted = &rest[start + 1..];
        let end = shifted.find('-')?;
        let run = &shifted[..end];
        if run.is_empty() {
            out.push('&');
        } else {
            out.push_str(&decode_run(run)?);
        }
        rest = &shifted[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Decodes the base64 part of a single shifted run.
fn decode_run(run: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(run.len());
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    for symbol in run.bytes() {
        let value = ALPHABET.iter().position(|&a| a == symbol)?;
        bits = (bits << 6) | u32::try_from(value).ok()?;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            bytes.push(u8::try_from((bits >> bit_count) & 0xff).ok()?);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &[(&str, &str)] = &[
        ("INBOX", "INBOX"),
        ("Sent Messages", "Sent Messages"),
        ("Tom & Jerry", "Tom &- Jerry"),
        ("Entwürfe", "Entw&APw-rfe"),
        ("日本語", "&ZeVnLIqe-"),
        ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
        ("Rechnungen 📎", "Rechnungen &2D3czg-"),
    ];

    #[test]
    fn encodes_known_values() {
        for (plain, wire) in CASES {
            assert_eq!(encode(plain), *wire, "encoding {plain}");
        }
    }

    #[test]
    fn decodes_known_values() {
        for (plain, wire) in CASES {
            assert_eq!(decode(wire).as_deref(), Some(*plain), "decoding {wire}");
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(decode("&unterminated"), None);
        assert_eq!(decode("&!!!-"), None);
    }
}
