use craft_anything_formats::pe;
use craft_anything_testkit::packed::pe_rcdata;

fn set_directory_size(data: &mut [u8], size: u32) {
    let headers = pe::headers(data).unwrap();
    let dirs = headers.pe_offset + 24 + if headers.pe32_plus { 112 } else { 96 };
    data[dirs + 20..dirs + 24].copy_from_slice(&size.to_le_bytes());
}

#[test]
fn resource_subdirectories_cannot_escape_the_directory_size() {
    let mut data = pe_rcdata("inside", b"payload");
    set_directory_size(&mut data, 24);
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert!(resources.entries.is_empty());
    assert!(!resources.warnings.is_empty());
}

#[test]
fn a_resource_name_cannot_be_read_from_bytes_after_the_directory() {
    let mut data = pe_rcdata("outside", b"payload");
    set_directory_size(&mut data, 0x60);
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert!(resources.entries.is_empty());
    assert!(!resources.warnings.is_empty());
}

#[test]
fn a_partial_resource_data_entry_is_not_reported_as_complete() {
    for size in [0x50, 0x54, 0x57] {
        let mut data = pe_rcdata("inside", b"payload");
        let headers = pe::headers(&data).unwrap();
        let root = headers.rva_to_offset(headers.dir(2).unwrap().0).unwrap();
        data[root + 0x28..root + 0x2c].copy_from_slice(&7u32.to_le_bytes());
        set_directory_size(&mut data, size);
        let resources = pe::parse_resources(&data, 10).unwrap();
        assert!(resources.entries.is_empty(), "size={size}");
        assert!(!resources.warnings.is_empty());
    }
}

#[test]
fn resource_payloads_still_use_their_own_rva() {
    let mut data = pe_rcdata("inside", b"payload");
    set_directory_size(&mut data, 0x60 + 2 + 6 * 2);
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert_eq!(resources.entries.len(), 1);
    let entry = &resources.entries[0];
    assert_eq!(entry.name, "inside");
    assert_eq!(entry.size, 7);
    let off = entry.file_offset.unwrap() as usize;
    assert_eq!(&data[off..off + 7], b"payload");
    assert!(resources.warnings.is_empty());
}
