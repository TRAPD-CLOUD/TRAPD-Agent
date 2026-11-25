#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use trapd_schema as schema;

mod telemetry {
    pub use trapd_schema::{limits, Enrichment, EnrichmentError};
}
#[allow(dead_code)]
#[path = "../../agent/src/collectors/etw_map.rs"]
mod etw_map;

use etw_map::{EtwRecord, EtwValue};

fuzz_target!(|fields: [u8; 12]| {
    let local = Ipv4Addr::new(fields[0], fields[1], fields[2], fields[3]);
    let remote = Ipv4Addr::new(fields[4], fields[5], fields[6], fields[7]);
    let sport = u16::from_be_bytes([fields[8], fields[9]]);
    let dport = u16::from_be_bytes([fields[10], fields[11]]);
    let props = HashMap::from([
        ("saddr".into(), EtwValue::Bytes(local.octets().to_vec())),
        ("daddr".into(), EtwValue::Bytes(remote.octets().to_vec())),
        (
            "sport".into(),
            EtwValue::Bytes(sport.to_be_bytes().to_vec()),
        ),
        (
            "dport".into(),
            EtwValue::Bytes(dport.to_be_bytes().to_vec()),
        ),
    ]);
    let mut record = EtwRecord {
        provider: etw_map::KERNEL_NETWORK,
        id: 12,
        props,
        ..Default::default()
    };
    let connect = etw_map::network_connection(&record, None).unwrap();
    assert_eq!(
        (connect.src_addr, connect.src_port),
        (local.to_string(), sport)
    );
    assert_eq!(
        (connect.dst_addr, connect.dst_port),
        (remote.to_string(), dport)
    );
    record.id = 15;
    let accept = etw_map::network_connection(&record, None).unwrap();
    assert_eq!(
        (accept.src_addr, accept.src_port),
        (remote.to_string(), dport)
    );
    assert_eq!(
        (accept.dst_addr, accept.dst_port),
        (local.to_string(), sport)
    );
});
