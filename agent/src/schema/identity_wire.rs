//! Lossless process-generation wire representation for JavaScript consumers.
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Text(String),
        Number(u64),
    }
    let wire = Option::<Wire>::deserialize(deserializer)?;
    wire.map(|wire| match wire {
        Wire::Number(n) => Ok(n),
        Wire::Text(s) => {
            if s.is_empty()
                || !s.bytes().all(|b| b.is_ascii_digit())
                || (s.len() > 1 && s.starts_with('0'))
            {
                return Err(serde::de::Error::custom("noncanonical process generation"));
            }
            s.parse().map_err(serde::de::Error::custom)
        }
    })
    .transpose()
}
/// Read a generation from dynamic evidence without numeric precision loss.
pub fn parse(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    let s = value.as_str()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use crate::schema::ProcessCreateData;
    #[test]
    fn windows_filetime_round_trips_losslessly_as_decimal_string() {
        let start = 133_800_000_000_000_001;
        let data = ProcessCreateData {
            process_start_time: Some(start),
            ..Default::default()
        };
        let wire = serde_json::to_value(&data).unwrap();
        assert_eq!(wire["process_start_time"], start.to_string());
        let decoded: ProcessCreateData = serde_json::from_value(wire).unwrap();
        assert_eq!(decoded.process_start_time, Some(start));
    }
    #[test]
    fn legacy_numeric_observations_decode_but_serialize_losslessly() {
        let mut data = serde_json::to_value(ProcessCreateData::default()).unwrap();
        data["process_start_time"] = serde_json::json!(1234);
        let decoded: ProcessCreateData = serde_json::from_value(data).unwrap();
        assert_eq!(decoded.process_start_time, Some(1234));
        assert_eq!(
            serde_json::to_value(decoded).unwrap()["process_start_time"],
            "1234"
        );
    }
}
