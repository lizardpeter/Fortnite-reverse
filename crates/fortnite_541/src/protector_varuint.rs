//! Recovered Fortnite 5.41 protected-stream unsigned base-128 decoder.
//!
//! Verified original native x64 loop at RVA 0x05C61E26:
//! - read byte via pointer-to-cursor, mask with 0x7F
//! - shift by a growing seven-bit offset and add into a u32
//! - advance cursor, repeat if continuation bit 0x80 was set
//!
//! This is not evidence of decrypted executable code. The original variant
//! uses wrapping arithmetic; use the checked decoder for untrusted inputs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedVaruintError {
    Unterminated,
    Overflow,
}

/// Faithfully implement observed original x86 32-bit SHL and ADD semantics.
///
/// SHL masks the shift count modulo 32; 32-bit addition wraps. No implicit
/// five-byte limit was observed in the source loop, so this must not be used
/// as a validating parser for metadata offsets, sizes, or counts.
pub fn decode_original_wrapping(input: &[u8]) -> Result<(u32, usize), ProtectedVaruintError> {
    let mut result = 0_u32;
    let mut bit_offset = 0_u32;
    for (i, &byte) in input.iter().enumerate() {
        let payload = u32::from(byte & 0x7f);
        result = result.wrapping_add(payload.wrapping_shl(bit_offset));
        bit_offset = bit_offset.wrapping_add(7);
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
    }
    Err(ProtectedVaruintError::Unterminated)
}

/// Parse a conventional unsigned u32 base-128 integer with overflow checks.
pub fn decode_u32_checked(input: &[u8]) -> Result<(u32, usize), ProtectedVaruintError> {
    let mut value = 0_u32;
    for (i, &byte) in input.iter().enumerate() {
        if i >= 5 {
            return Err(ProtectedVaruintError::Overflow);
        }
        let payload = u32::from(byte & 0x7f);
        if i == 4 && payload > 0x0f {
            return Err(ProtectedVaruintError::Overflow);
        }
        value |= payload << (i * 7);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        if i == 4 {
            return Err(ProtectedVaruintError::Overflow);
        }
    }
    Err(ProtectedVaruintError::Unterminated)
}

/// Source-backed accumulator mutated after the decoded integer is read.
///
/// Original retail x64 at RVA 0x05BF2A18:
///   value = *(u32 *)(output + 4) + decoded_varuint + *(u32 *)output;
///   *(u32 *)output = value;
///
/// The semantic purpose of the two fields is NOT yet established; names
/// avoid assuming they represent decryption keys or file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardVaruintAccumulator {
    pub current: u32,
    pub bias: u32,
}

/// Consume one authentic source-format integer and update the native state.
///
/// Returns consumed input bytes; all arithmetic matches original x86 u32
/// wrapping ADD behavior. This does not perform executable decryption.
pub fn consume_and_accumulate_original(
    input: &[u8],
    state: &mut GuardVaruintAccumulator,
) -> Result<usize, ProtectedVaruintError> {
    let (decoded, consumed) = decode_original_wrapping(input)?;
    state.current = state.bias.wrapping_add(decoded).wrapping_add(state.current);
    Ok(consumed)
}

#[cfg(test)]
mod tests {
    use super::{decode_original_wrapping, decode_u32_checked, ProtectedVaruintError as E};

    #[test]
    fn source_equivalent_integer_examples() {
        let cases: &[(&[u8], u32, usize)] = &[
            (&[0], 0, 1),
            (&[1], 1, 1),
            (&[0x7f], 127, 1),
            (&[0x80, 1], 128, 2),
            (&[0xe5, 0x8e, 0x26], 624_485, 3),
            (&[0xff, 0xff, 0xff, 0xff, 0x0f], u32::MAX, 5),
            (&[0x80, 0, 0xde, 0xad], 0, 2),
        ];
        for &(buf, expected, consumed) in cases {
            assert_eq!(decode_u32_checked(buf), Ok((expected, consumed)));
            assert_eq!(decode_original_wrapping(buf), Ok((expected, consumed)));
        }
    }

    #[test]
    fn malformed_and_truncated_cases() {
        assert_eq!(decode_u32_checked(&[]), Err(E::Unterminated));
        assert_eq!(decode_original_wrapping(&[]), Err(E::Unterminated));
        assert_eq!(decode_u32_checked(&[0x80]), Err(E::Unterminated));
        assert_eq!(decode_u32_checked(&[0x80, 0x80]), Err(E::Unterminated));
        assert_eq!(decode_u32_checked(&[0xff, 0xff, 0xff, 0xff, 0x10]), Err(E::Overflow));
        assert_eq!(decode_u32_checked(&[0x80, 0x80, 0x80, 0x80, 0x80, 0]), Err(E::Overflow));
    }

    #[test]
    fn original_x86_shift_count_wrap_is_explicit() {
        // The sixth payload uses bit offset 35, masked by x86 SHL to 3.
        let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 1];
        assert_eq!(decode_original_wrapping(&bytes), Ok((8, 6)));
        assert_eq!(decode_u32_checked(&bytes), Err(E::Overflow));
    }

    #[test]
    fn original_accumulator_addition_wrap_is_explicit() {
        let bytes = [0xff, 0xff, 0xff, 0xff, 0x8f, 1];
        assert_eq!(decode_original_wrapping(&bytes), Ok((7, 6)));
    }

    #[test]
    fn source_confirmed_original_accumulator_update() {
        use super::{consume_and_accumulate_original, GuardVaruintAccumulator};
        let mut state = GuardVaruintAccumulator { current: 10, bias: 4 };
        assert_eq!(consume_and_accumulate_original(&[5, 0xff], &mut state), Ok(1));
        assert_eq!(state.current, 19);
        assert_eq!(consume_and_accumulate_original(&[0x80, 1], &mut state), Ok(2));
        assert_eq!(state.current, 151);
        let unchanged = state;
        assert_eq!(consume_and_accumulate_original(&[0x80], &mut state), Err(E::Unterminated));
        assert_eq!(state, unchanged);
    }

    #[test]
    fn accumulator_matches_native_u32_overflow() {
        use super::{consume_and_accumulate_original, GuardVaruintAccumulator};
        let mut state = GuardVaruintAccumulator { current: u32::MAX, bias: 2 };
        assert_eq!(consume_and_accumulate_original(&[3], &mut state), Ok(1));
        assert_eq!(state.current, 4);
    }

    #[test]
    fn bounded_inputs_cannot_read_past_the_provided_slice() {
        assert_eq!(decode_original_wrapping(&[0x80, 0x80]), Err(E::Unterminated));
        assert_eq!(decode_original_wrapping(&[0x80, 0x80, 0]), Ok((0, 3)));
    }
}
