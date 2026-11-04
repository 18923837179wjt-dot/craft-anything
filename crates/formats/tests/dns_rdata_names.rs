use craft_anything_formats::pcap::{decode, summarize};
use craft_anything_testkit::pcap::{dns_query, eth, ipv4_pkt, pcap, udp};

fn response(record_type: u16, rdata: &[u8], declared_length: usize) -> Vec<u8> {
    let mut message = dns_query();
    message[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    message[6..8].copy_from_slice(&1u16.to_be_bytes());
    message.extend([0xc0, 12]); // owner points to the question's name
    message.extend(record_type.to_be_bytes());
    message.extend(1u16.to_be_bytes());
    message.extend(60u32.to_be_bytes());
    message.extend((declared_length as u16).to_be_bytes());
    message.extend(rdata);
    message
}

fn packet(message: &[u8]) -> Vec<u8> {
    eth(0x0800, &ipv4_pkt(17, [192, 0, 2, 2], [192, 0, 2, 1], &udp(53, 51000, message)))
}

/// Truncated literal names and compression pointers must stay inside RDLENGTH.
#[test]
fn answer_names_cannot_borrow_bytes_past_rdata() {
    for record_type in [2, 5, 12, 15] {
        for name in [b"\x04fake\x07example\x00".as_slice(), &[0xc0, 12]] {
            let mut rdata = if record_type == 15 { vec![0, 10] } else { Vec::new() };
            let prefix = rdata.len();
            rdata.extend(name);
            for declared in [prefix, prefix + name.len() - 1] {
                let dns = decode(1, &packet(&response(record_type, &rdata, declared))).dns.unwrap();
                assert!(dns.incomplete, "type {record_type}, declared length {declared}");
                assert!(dns.answers.is_empty(), "a name must be wholly encoded in its record");
            }
        }
    }
}

/// An incomplete pointer is malformed, rather than a successful empty answer.
#[test]
fn malformed_name_rdata_is_not_reported_as_an_empty_answer() {
    for record_type in [2, 5, 12, 15] {
        let rdata = if record_type == 15 { vec![0, 10, 0xc0] } else { vec![0xc0] };
        let dns = decode(1, &packet(&response(record_type, &rdata, rdata.len()))).dns.unwrap();
        assert!(dns.incomplete);
        assert!(dns.answers.is_empty());
    }
}

/// An MX name cannot borrow either of its required preference bytes from trailing data.
#[test]
fn an_mx_exchange_cannot_skip_a_missing_preference() {
    for declared in [0, 1] {
        let dns = decode(1, &packet(&response(15, &[0, 10, 0xc0, 12], declared))).dns.unwrap();
        assert!(dns.incomplete);
        assert!(dns.answers.is_empty());
    }
}

/// A terminator before the declared boundary must not hide unused RDATA bytes.
#[test]
fn a_name_must_account_for_all_of_its_rdata() {
    for record_type in [2, 5, 12, 15] {
        let rdata = if record_type == 15 { vec![0, 10, 0, 0xaa] } else { vec![0, 0xaa] };
        let dns = decode(1, &packet(&response(record_type, &rdata, rdata.len()))).dns.unwrap();
        assert!(dns.incomplete);
        assert!(dns.answers.is_empty());
    }
}

/// Literal, root, backward-pointer and label-plus-pointer names remain valid controls.
#[test]
fn complete_and_compressed_names_remain_supported() {
    for record_type in [2, 5, 12, 15] {
        for (name, expected) in [
            (b"\x04mail\x07example\x00".as_slice(), "mail.example"),
            (&[0xc0, 12], "example.com"),
            (b"\x03www\xc0\x0c".as_slice(), "www.example.com"),
            (&[0], "."),
        ] {
            let mut rdata = if record_type == 15 { vec![0, 10] } else { Vec::new() };
            rdata.extend(name);
            let dns = decode(1, &packet(&response(record_type, &rdata, rdata.len()))).dns.unwrap();
            assert!(!dns.incomplete, "type {record_type}, name {expected}");
            assert_eq!(dns.answers.len(), 1);
            assert_eq!(dns.answers[0].value, expected);
        }
    }
}

#[test]
fn names_outside_rdata_do_not_enter_the_answer_inventory() {
    let message = response(5, b"\x04fake\x07example\x00", 0);
    let summary = summarize(&pcap(&[packet(&message)]), &|| false).unwrap();
    assert_eq!(summary.packets, 1);
    assert!(summary.dns_answers.is_empty());
}

#[test]
fn earlier_answers_survive_before_a_malformed_name() {
    let mut message = response(1, &[192, 0, 2, 3], 4);
    message[6..8].copy_from_slice(&2u16.to_be_bytes());
    let malformed = response(5, b"\x04fake\x07example\x00", 0);
    message.extend(&malformed[dns_query().len()..]);

    let dns = decode(1, &packet(&message)).dns.unwrap();
    assert!(dns.incomplete);
    assert_eq!(dns.answers.len(), 1);
    assert_eq!(dns.answers[0].rtype, "A");
    assert_eq!(dns.answers[0].value, "192.0.2.3");
}
