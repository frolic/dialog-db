/// How far a frame is padded before it is sealed.
///
/// Node sizes follow from the data, so unpadded sizes are a fingerprint of a
/// space's contents. Padding rounds each frame up to one of a small set of
/// sizes. Every replica of a space must use the same padding, because it
/// changes the sealed bytes and therefore every block address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Padding {
    /// No padding: the frame is sealed at its own length.
    None,
    /// Round up to the next power of two. Leaks the least, and costs up to
    /// twice the storage.
    PowerOfTwo,
    /// Round up with Padmé, which keeps the top bits of the length and zeroes
    /// the rest. It leaks `O(log log n)` bits of a length and costs at most
    /// 12% more storage.
    #[default]
    Padme,
}

impl Padding {
    /// The padded length of a frame of `length` bytes.
    pub fn padded_length(&self, length: usize) -> usize {
        match self {
            Padding::None => length,
            Padding::PowerOfTwo => length.next_power_of_two(),
            Padding::Padme => padme(length),
        }
    }
}

/// Padmé, from Nikitin et al., "Reducing Metadata Leakage from Encrypted
/// Files and Communication with PURBs" (PETS 2019).
fn padme(length: usize) -> usize {
    if length < 2 {
        return length;
    }
    let exponent = usize::BITS - 1 - length.leading_zeros();
    let bits_of_exponent = u32::BITS - exponent.leading_zeros();
    let low_bits = exponent - bits_of_exponent;
    let mask = (1usize << low_bits) - 1;
    (length + mask) & !mask
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::Padding;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[dialog_common::test]
    fn it_never_shrinks_a_frame() {
        for padding in [Padding::None, Padding::PowerOfTwo, Padding::Padme] {
            for length in 0..5000 {
                assert!(padding.padded_length(length) >= length);
            }
        }
    }

    #[dialog_common::test]
    fn it_rounds_to_powers_of_two() {
        assert_eq!(Padding::PowerOfTwo.padded_length(5), 8);
        assert_eq!(Padding::PowerOfTwo.padded_length(65_537), 131_072);
    }

    #[dialog_common::test]
    fn it_bounds_padme_overhead() {
        for length in 1..200_000usize {
            let padded = Padding::Padme.padded_length(length);
            assert!(padded * 100 <= length * 112 + 100, "{length} -> {padded}");
        }
        // Lengths collapse onto few sizes: many inputs share each output.
        assert_eq!(Padding::Padme.padded_length(65_537), 67_584);
        assert_eq!(Padding::Padme.padded_length(66_000), 67_584);
    }
}
