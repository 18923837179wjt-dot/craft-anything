use craft_anything_formats::pcap::{Dns, decode};
use craft_anything_testkit::pcap::{ipv4_pkt, udp};

fn response(data: &[u8]) -> Dns {
    let mut msg = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
    msg.extend([0, 0, 16, 0, 1, 0, 0, 0, 60]);
    msg.extend((data.len() as u16).to_be_bytes());
    msg.extend(data);
    decode(101, &ipv4_pkt(17, [1; 4], [2; 4], &udp(53, 100, &msg))).dns.unwrap()
}

fn prerequisites(flags: u16, class: u16, ttl: u32, data: &[u8]) -> Dns {
    let mut msg = vec![0, 1];
    msg.extend(flags.to_be_bytes());
    msg.extend([0, 1, 0, 2, 0, 0, 0, 0]);
    // UPDATE's zone section has the question layout: example.test, SOA, IN.
    msg.extend(b"\x07example\x04test\x00\x00\x06\x00\x01");
    msg.extend([0xc0, 12, 0, 16]);
    msg.extend(class.to_be_bytes());
    msg.extend(ttl.to_be_bytes());
    msg.extend((data.len() as u16).to_be_bytes());
    msg.extend(data);
    // A following value-dependent TXT prerequisite must also survive.
    msg.extend([0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 2, b'o', b'k']);
    decode(101, &ipv4_pkt(17, [1; 4], [2; 4], &udp(100, 53, &msg))).dns.unwrap()
}

#[test]
fn empty_update_prerequisites_preserve_following_records() {
    for class in [254, 255] {
        let dns = prerequisites(5 << 11, class, 0, &[]);
        assert!(!dns.incomplete, "class {class}");
        assert_eq!(dns.answers.len(), 2);
        assert_eq!(dns.answers[0].value, "");
        assert_eq!(dns.answers[1].value, "ok");
    }
}

#[test]
fn empty_txt_rdata_requires_update_and_a_prerequisite_class() {
    assert!(response(&[]).incomplete);
    for (flags, class, ttl) in [(0x8180, 254, 0), (0x8180, 255, 0), (5 << 11, 1, 0), (5 << 11, 254, 60), (5 << 11, 255, 60)] {
        let dns = prerequisites(flags, class, ttl, &[]);
        assert!(dns.incomplete, "flags {flags:#x}, class {class}, ttl {ttl}");
        assert!(dns.answers.is_empty());
    }
}

#[test]
fn update_prerequisite_classes_do_not_allow_truncated_strings() {
    for class in [254, 255] {
        let dns = prerequisites(5 << 11, class, 0, b"\x02x");
        assert!(dns.incomplete);
        assert!(dns.answers.is_empty());
    }
}

#[test]
fn truncated_txt_strings_are_not_complete_answers() {
    for data in [&b"\x05abc"[..], &b"\x02ok\x04x"[..], &b"\x01"[..]] {
        let dns = response(data);
        assert!(dns.incomplete);
        assert!(dns.answers.is_empty());
    }
}

#[test]
fn empty_and_multiple_complete_strings_remain_valid() {
    for (data, expected) in [(&b"\x00"[..], ""), (&b"\x00\x02ok\x01!"[..], "ok!")] {
        let dns = response(data);
        assert!(!dns.incomplete);
        assert_eq!(dns.answers[0].value, expected);
    }
}
