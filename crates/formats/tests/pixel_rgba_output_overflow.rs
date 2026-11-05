use craft_anything_formats::{
    FormatError,
    pixels::{self, Layout},
};

#[test]
fn expanded_rgba_dimensions_are_checked_before_reading_or_allocating() {
    for layout in [Layout::R8, Layout::Alpha8, Layout::Dxt1, Layout::Bc4] {
        assert!(matches!(pixels::decode(layout, u32::MAX, u32::MAX, &[]), Err(FormatError::TooLarge(_))), "layout {layout:?}");
        // The product fits u64 but exceeds the largest byte vector on a 64-bit target.
        assert!(matches!(pixels::decode(layout, 1 << 31, 1 << 30, &[]), Err(FormatError::TooLarge(_))), "layout {layout:?}");
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn rgba_expansion_cannot_wrap_a_32_bit_output_length() {
    assert!(matches!(pixels::decode(Layout::Dxt1, 65536, 16384, &[]), Err(FormatError::TooLarge(_))));
}

#[test]
fn ordinary_pixel_sizes_and_truncated_inputs_keep_their_results() {
    assert_eq!(pixels::decode(Layout::R8, 2, 1, &[7, 8]).unwrap(), [7, 7, 7, 255, 8, 8, 8, 255]);
    assert_eq!(pixels::decode(Layout::Dxt1, 5, 5, &[0; 32]).unwrap().len(), 100);
    assert!(matches!(pixels::decode(Layout::R8, 2, 1, &[7]), Err(FormatError::Truncated(_))));
    assert!(matches!(pixels::decode(Layout::Dxt1, 0, 1, &[]), Err(FormatError::Malformed(_))));
}
