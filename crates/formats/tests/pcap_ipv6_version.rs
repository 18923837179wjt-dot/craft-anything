use craft_anything_formats::pcap::decode;
use craft_anything_testkit::pcap::eth;

#[test]
fn an_ethernet_type_does_not_replace_the_ipv6_version_check() {
    for version in [0, 4, 5, 7, 15] {
        let mut packet = [0u8; 40];
        packet[0] = version << 4;
        packet[6] = 59;
        let decoded = decode(1, &eth(0x86dd, &packet));
        assert!(decoded.ip.is_none(), "version {version}");
        assert!(decoded.transport.is_none());
        assert!(decoded.note.is_some());
    }
}

#[test]
fn ipv6_version_keeps_traffic_class_bits() {
    let mut packet = [0u8; 40];
    packet[0] = 0x6f;
    packet[6] = 59;
    assert_eq!(decode(1, &eth(0x86dd, &packet)).ip.unwrap().version, 6);
}
