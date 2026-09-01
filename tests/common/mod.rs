//! Shared PPv2 header builder.
//!
//! `common/mod.rs` rather than `common.rs`: cargo treats every top-level file
//! in tests/ as its own test binary, and a subdirectory module is the standard
//! way to share code without producing an empty one.

use aws_ppv2_identity::ppv2::{AWS_SUBTYPE_VPCE_ID, SIGNATURE, TLV_AWS};

/// Version 2 + PROXY. The only 13th byte an NLB ever sends. Written literally
/// rather than imported from the parser: what is under test is the byte on the
/// wire, and importing the constant would only prove the parser agrees with
/// itself.
pub const V2_PROXY: u8 = 0x21;

/// `fam` is the whole 13th byte, so tests can express UDP and bad families.
pub fn build(ver_cmd: u8, fam: u8, src: &[u8], vpce: Option<&[u8]>) -> Vec<u8> {
    let addr_len = if fam >> 4 == 0x2 { 36 } else { 12 };
    let mut body = vec![0u8; addr_len];
    let n = src.len().min(addr_len);
    body[..n].copy_from_slice(&src[..n]);
    if let Some(v) = vpce {
        body.push(TLV_AWS);
        body.extend_from_slice(&((1 + v.len()) as u16).to_be_bytes());
        body.push(AWS_SUBTYPE_VPCE_ID);
        body.extend_from_slice(v);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE);
    out.push(ver_cmd);
    out.push(fam);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}
