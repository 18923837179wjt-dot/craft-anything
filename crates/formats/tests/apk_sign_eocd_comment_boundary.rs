use craft_anything_formats::apk_sign;
use craft_anything_testkit::android::notes_apk;

#[test]
fn an_eocd_marker_inside_the_comment_does_not_hide_the_signature() {
    for fake_comment_length in [0u16, 1] {
        let mut apk = notes_apk();
        let original = apk_sign::parse(&apk).unwrap();
        let eocd = apk.len() - 22;
        assert_eq!(&apk[eocd..eocd + 4], b"PK\x05\x06");

        let mut comment = vec![0; 22];
        comment[..4].copy_from_slice(b"PK\x05\x06");
        comment[20..22].copy_from_slice(&fake_comment_length.to_le_bytes());
        apk[eocd + 20..eocd + 22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        apk.extend_from_slice(&comment);

        let found = apk_sign::parse(&apk).expect("the original EOCD still frames the APK");
        assert_eq!(found.offset, original.offset);
        assert_eq!(found.entries.len(), original.entries.len());
        assert_eq!(found.signers.len(), original.signers.len());
    }
}

#[test]
fn an_incomplete_eocd_comment_is_not_accepted() {
    let mut apk = notes_apk();
    let len = apk.len();
    apk[len - 2..].copy_from_slice(&1u16.to_le_bytes());
    assert!(apk_sign::parse(&apk).is_none());
}

#[test]
fn an_eocd_marker_in_a_signing_block_value_does_not_hide_the_signature() {
    for points_to_real_directory in [false, true] {
        let mut apk = notes_apk();
        let original = apk_sign::parse(&apk).unwrap();
        let eocd = apk.len() - 22;
        let cd = u32::from_le_bytes(apk[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let pair_at = cd - 24;
        let marker_at = pair_at + 12;
        let added = 8 + 4 + 22;
        let new_cd = cd + added;

        let mut value = vec![0; 22];
        value[..4].copy_from_slice(b"PK\x05\x06");
        let fake_cd = if points_to_real_directory { new_cd as u32 } else { 0 };
        value[16..20].copy_from_slice(&fake_cd.to_le_bytes());
        let comment_len = u16::try_from(apk.len() + added - marker_at - 22).unwrap();
        value[20..22].copy_from_slice(&comment_len.to_le_bytes());
        let mut pair = 26u64.to_le_bytes().to_vec();
        pair.extend_from_slice(&0x1357_2468u32.to_le_bytes());
        pair.extend_from_slice(&value);
        apk.splice(pair_at..pair_at, pair);

        let size = original.size + added as u64;
        let start = original.offset as usize;
        apk[start..start + 8].copy_from_slice(&size.to_le_bytes());
        apk[new_cd - 24..new_cd - 16].copy_from_slice(&size.to_le_bytes());
        apk[eocd + added + 16..eocd + added + 20].copy_from_slice(&(new_cd as u32).to_le_bytes());

        let found = apk_sign::parse(&apk).expect("a marker inside an unknown signing-block value is not the ZIP record");
        assert_eq!((found.offset, found.size), (original.offset, size));
        assert_eq!(&found.entries[..original.entries.len()], &original.entries);
        assert_eq!(found.entries.len(), original.entries.len() + 1);
        assert_eq!(found.entries.last().unwrap().id, "0x13572468");
        assert_eq!(found.signers, original.signers);
        assert!(found.warnings.is_empty());
    }
}

#[test]
fn a_signing_block_and_eocd_inside_the_comment_do_not_replace_the_original() {
    let mut apk = notes_apk();
    let original = apk_sign::parse(&apk).unwrap();
    let eocd = apk.len() - 22;
    let mut comment = 24u64.to_le_bytes().to_vec();
    comment.extend_from_slice(&24u64.to_le_bytes());
    comment.extend_from_slice(b"APK Sig Block 42");
    let fake_cd = apk.len() + comment.len();
    let mut fake_eocd = vec![0; 22];
    fake_eocd[..4].copy_from_slice(b"PK\x05\x06");
    fake_eocd[16..20].copy_from_slice(&(fake_cd as u32).to_le_bytes());
    comment.extend_from_slice(&fake_eocd);
    apk[eocd + 20..eocd + 22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
    apk.extend_from_slice(&comment);
    assert_eq!(apk_sign::parse(&apk).unwrap(), original);
}

#[test]
fn recoverable_size_and_pair_damage_still_returns_signing_evidence() {
    let original_bytes = notes_apk();
    let original = apk_sign::parse(&original_bytes).unwrap();
    let start = original.offset as usize;
    let mut size_mismatch = original_bytes.clone();
    size_mismatch[start..start + 8].copy_from_slice(&(original.size + 1).to_le_bytes());
    let found = apk_sign::parse(&size_mismatch).expect("header size disagreement is reported as a warning");
    assert_eq!(found.signers, original.signers);
    assert_eq!(found.entries, original.entries);
    assert!(found.warnings.iter().any(|w| w.contains("size fields disagree")));

    let mut bad_pair = original_bytes;
    let third_pair = start + 8 + original.entries.iter().take(2).map(|entry| entry.size as usize + 12).sum::<usize>();
    bad_pair[third_pair..third_pair + 8].copy_from_slice(&original.size.to_le_bytes());
    let found = apk_sign::parse(&bad_pair).expect("a malformed later pair keeps the preceding signers");
    assert_eq!(found.signers, original.signers);
    assert_eq!(found.entries.len(), 2);
    assert!(found.warnings.iter().any(|w| w.contains("malformed id-value pair")));
}
