use craft_anything_formats::pcap::{Dns, decode};
use craft_anything_testkit::pcap::{ipv4_pkt, udp};

fn query(last: usize, compressed: bool) -> Dns {
    let mut msg = vec![0, 1, 1, 0, 0, if compressed { 2 } else { 1 }, 0, 0, 0, 0, 0, 0];
    for len in [63, 63, 63, last] {
        msg.push(len as u8);
        msg.extend(vec![b'a'; len]);
    }
    msg.extend([0, 0, 1, 0, 1]);
    if compressed {
        msg.extend([0xc0, 12, 0, 1, 0, 1]);
    }
    decode(101, &ipv4_pkt(17, [1; 4], [2; 4], &udp(100, 53, &msg))).dns.unwrap()
}

#[test]
fn label_lengths_and_the_root_octet_count_towards_the_dns_limit() {
    for last in [62, 63] {
        let dns = query(last, false);
        assert!(dns.incomplete);
        assert!(dns.questions.is_empty());
    }
}

#[test]
fn a_255_octet_name_is_valid_in_plain_and_compressed_form() {
    for compressed in [false, true] {
        let dns = query(61, compressed);
        assert!(!dns.incomplete);
        assert_eq!(dns.questions.len(), if compressed { 2 } else { 1 });
        assert_eq!(dns.questions[0].name.len(), 253);
    }
}
