use craft_anything_formats::{FormatError, unity_bundle};

#[test]
fn stored_blocks_must_match_the_declared_output_length() {
    for expected in [0, 2, 4] {
        assert!(matches!(unity_bundle::decompress(0, b"abc", expected), Err(FormatError::Malformed(_))), "declared {expected} bytes");
    }
    assert!(unity_bundle::decompress(0, &[], 1).is_err());
    assert_eq!(unity_bundle::decompress(0, b"abc", 3).unwrap(), b"abc");
    assert!(unity_bundle::decompress(0, &[], 0).unwrap().is_empty());
}

#[test]
fn compressed_blocks_keep_their_exact_length_contract() {
    let plain = b"a small Unity bundle block";
    let lz4 = craft_anything_testkit::games::lz4_literals(plain);
    for kind in [2, 3] {
        assert_eq!(unity_bundle::decompress(kind, &lz4, plain.len() as u32).unwrap(), plain);
        assert!(unity_bundle::decompress(kind, &lz4, plain.len() as u32 + 1).is_err());
        assert!(unity_bundle::decompress(kind, &lz4, plain.len() as u32 - 1).is_err());
    }
    let mut alone = Vec::new();
    lzma_rs::lzma_compress(&mut std::io::Cursor::new(plain), &mut alone).unwrap();
    let unity_lzma = [&alone[..5], &alone[13..]].concat();
    assert_eq!(unity_bundle::decompress(1, &unity_lzma, plain.len() as u32).unwrap(), plain);
    assert!(unity_bundle::decompress(1, &unity_lzma, plain.len() as u32 + 1).is_err());
}
