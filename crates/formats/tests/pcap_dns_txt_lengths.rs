use craft_anything_formats::pcap::{Dns, decode};
use craft_anything_testkit::pcap::{ipv4_pkt, udp};

fn response(data: &[u8]) -> Dns {
    let mut msg = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
    msg.extend([0, 0, 16, 0, 1, 0, 0, 0, 60]);
    msg.extend((data.len() as u16).to_be_bytes());
    msg.extend(data);
    decode(101, &ipv4_pkt(17, [1; 4], [2; 4], &udp(53, 100, &msg))).dns.unwrap()
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
