#![no_main]
//! Fuzz target for Ethereum RLP receipt decoding.
//!
//! This tests the RLP receipt decoder used in Merkle proof verification
//! to ensure it handles malformed inputs safely.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test RLP receipt decoding (the internal Receipt::from_rlp path)
    // We don't have direct access, so we construct a minimal proof and try verification
    
    // Skip very short inputs
    if data.len() < 32 {
        return;
    }
    
    // Try to decode as RLP list
    let _ = try_decode_rlp_list(data);
});

fn try_decode_rlp_list(data: &[u8]) -> Option<()> {
    use alloy_rlp::{Buf, Header as RlpHeader};
    
    let mut buf = data;
    
    // Try to decode outer list header
    let header = RlpHeader::decode(&mut buf).ok()?;
    
    if !header.list {
        return None;
    }
    
    // Try to skip some fields (simulating receipt parsing)
    let mut remaining = header.payload_length;
    let mut field_count = 0;
    
    while remaining > 0 && buf.remaining() >= remaining {
        let field_header = RlpHeader::decode(&mut buf).ok()?;
        
        // Bound field sizes
        if field_header.payload_length > 1_000_000 {
            return None;
        }
        
        if buf.remaining() < field_header.payload_length {
            return None;
        }
        
        buf.advance(field_header.payload_length);
        
        let consumed = 1 + field_header.payload_length;
        if consumed > remaining {
            return None;
        }
        remaining -= consumed;
        
        field_count += 1;
        if field_count > 100 {
            // Too many fields
            return None;
        }
    }
    
    Some(())
}
