use craft_anything_formats::pe;
use craft_anything_testkit::packed::{pe_rcdata, pe_section};

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

fn resource_with_long_name() -> Vec<u8> {
    let data = pe_rcdata("inside", b"payload");
    let headers = pe::headers(&data).unwrap();
    let (rva, size) = headers.dir(2).unwrap();
    let root = headers.rva_to_offset(rva).unwrap();
    let mut resource = data[root..root + size as usize].to_vec();
    let name_at = (resource.len() + 1) & !1;
    resource.resize(name_at, 0);
    resource.extend(4097u16.to_le_bytes());
    for _ in 0..4096 {
        resource.extend(u16::from(b'x').to_le_bytes());
    }
    resource.extend(u16::from(b'z').to_le_bytes());
    resource[0x28..0x2c].copy_from_slice(&(0x8000_0000 | name_at as u32).to_le_bytes());
    // Rebuild the section so its raw and virtual extents contain the complete name.
    let mut data = pe_section(".rsrc", &resource);
    let headers = pe::headers(&data).unwrap();
    let dirs = headers.pe_offset + 24 + if headers.pe32_plus { 112 } else { 96 };
    data[dirs + 16..dirs + 20].copy_from_slice(&rva.to_le_bytes());
    set_directory_size(&mut data, resource.len() as u32);
    data
}

#[test]
fn a_long_resource_name_must_fit_its_full_declared_span() {
    let mut data = resource_with_long_name();
    let headers = pe::headers(&data).unwrap();
    let (rva, size) = headers.dir(2).unwrap();
    let last_unit = headers.rva_to_offset(rva + size - 2).unwrap();
    set_directory_size(&mut data, size - 2);
    // The last unit remains mapped and present in the file, outside the declared directory.
    assert_eq!(&data[last_unit..last_unit + 2], b"z\0");
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert!(resources.entries.is_empty());
    assert!(resources.warnings.iter().any(|warning| warning == "resource name runs past the directory; skipped an entry"));
}

#[test]
fn a_long_resource_name_cannot_cross_the_mapped_raw_extent() {
    for delta in [0u32, 32] {
        let mut data = resource_with_long_name();
        let headers = pe::headers(&data).unwrap();
        let (rva, size) = headers.dir(2).unwrap();
        let root = headers.rva_to_offset(rva).unwrap();
        let section = &headers.sections[0];
        let optional_size = u16::from_le_bytes(data[headers.pe_offset + 20..headers.pe_offset + 22].try_into().unwrap());
        let section_at = headers.pe_offset + 24 + usize::from(optional_size);
        // Keep the resource at the same file offset, either at the section start or inside it.
        data[section_at + 8..section_at + 12].copy_from_slice(&(section.virtual_size + delta).to_le_bytes());
        data[section_at + 12..section_at + 16].copy_from_slice(&(section.rva - delta).to_le_bytes());
        data[section_at + 16..section_at + 20].copy_from_slice(&(delta + size - 2).to_le_bytes());
        data[section_at + 20..section_at + 24].copy_from_slice(&(section.raw_offset - delta).to_le_bytes());
        let mapped = pe::headers(&data).unwrap();
        let last_rva = rva + size - 2;
        let last_unit = root + size as usize - 2;
        assert_eq!(mapped.rva_to_offset(rva), Some(root));
        assert_eq!(rva - mapped.sections[0].rva, delta);
        assert!(last_rva - mapped.sections[0].rva < mapped.sections[0].virtual_size);
        assert_eq!(mapped.rva_to_offset(last_rva), None);
        assert_eq!(&data[last_unit..last_unit + 2], b"z\0");
        let resources = pe::parse_resources(&data, 10).unwrap();
        assert!(resources.entries.is_empty(), "delta={delta}");
        assert!(resources.warnings.iter().any(|warning| warning == "resource name runs past the directory; skipped an entry"), "delta={delta}");
    }
}

#[test]
fn resource_metadata_in_the_header_prefix_still_parses() {
    let mut data = pe_rcdata("inside", b"payload");
    let headers = pe::headers(&data).unwrap();
    let root = headers.rva_to_offset(headers.dir(2).unwrap().0).unwrap();
    let header_rva = 0x300u32;
    let metadata_size = 0x60 + 2 + 6 * 2;
    assert!(header_rva as usize + metadata_size <= headers.sections[0].raw_offset as usize);
    assert_eq!(headers.rva_to_offset(header_rva), Some(header_rva as usize));
    // Move only metadata into header padding; its payload keeps the original section RVA.
    data.copy_within(root..root + metadata_size, header_rva as usize);
    let dirs = headers.pe_offset + 24 + if headers.pe32_plus { 112 } else { 96 };
    data[dirs + 16..dirs + 20].copy_from_slice(&header_rva.to_le_bytes());
    set_directory_size(&mut data, metadata_size as u32);
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert_eq!(resources.entries.len(), 1);
    let entry = &resources.entries[0];
    assert_eq!(entry.name, "inside");
    assert_eq!(entry.size, 7);
    let off = entry.file_offset.unwrap() as usize;
    assert_eq!(&data[off..off + 7], b"payload");
    assert!(resources.warnings.is_empty());
}

#[test]
fn a_complete_long_resource_name_keeps_the_existing_output_limit() {
    let data = resource_with_long_name();
    let resources = pe::parse_resources(&data, 10).unwrap();
    assert_eq!(resources.entries.len(), 1);
    let entry = &resources.entries[0];
    assert_eq!(entry.name, "x".repeat(4096));
    assert_eq!(entry.size, 7);
    let off = entry.file_offset.unwrap() as usize;
    assert_eq!(&data[off..off + 7], b"payload");
    assert!(resources.warnings.is_empty());
}
