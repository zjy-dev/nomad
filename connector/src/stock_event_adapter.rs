//! Strict boundary for the event envelope observed from locked stock OpenCode.
//!
//! The committed evidence proves only the envelope and a small event-name set.
//! It does not prove enough property semantics to create durable Nomad events,
//! so successful parsing deliberately stops at an unmapped observation.

use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_EVENT_TYPE_BYTES: usize = 128;
const VERIFIED_EVENT_TYPES: &[&str] = &[
    "permission.asked",
    "permission.v2.asked",
    "question.asked",
    "question.v2.asked",
    "session.created",
    "session.diff",
];

pub const STOCK_EVENT_EVIDENCE_CLASS: &str = "official_registry_shape_only_not_provider_lifecycle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockEventEnvelopeError {
    Size,
    Json,
    Shape,
    UnsupportedType,
}

impl std::fmt::Display for StockEventEnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BLOCKED_STOCK_EVENT_ENVELOPE_INVALID")
    }
}

impl std::error::Error for StockEventEnvelopeError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StockEventClassification {
    ShapeObservedUnmapped,
}

impl std::fmt::Debug for StockEventClassification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ShapeObservedUnmapped")
    }
}

/// A bounded stock envelope whose business properties remain deliberately
/// unmapped until same-run lifecycle evidence is independently accepted.
pub struct OfficialStockObservation {
    event_id: String,
    event_type: String,
    property_count: usize,
}

impl OfficialStockObservation {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    pub fn property_count(&self) -> usize {
        self.property_count
    }

    pub fn classification(&self) -> StockEventClassification {
        StockEventClassification::ShapeObservedUnmapped
    }
}

impl std::fmt::Debug for OfficialStockObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfficialStockObservation")
            .field("event_id", &"<redacted>")
            .field("event_type", &self.event_type)
            .field("property_count", &self.property_count)
            .field("classification", &self.classification())
            .finish()
    }
}

pub fn observe_official_stock_envelope(
    raw: &[u8],
) -> Result<OfficialStockObservation, StockEventEnvelopeError> {
    if raw.is_empty() || raw.len() > MAX_ENVELOPE_BYTES {
        return Err(StockEventEnvelopeError::Size);
    }
    let value = strict_json(raw)?;
    let object = value.as_object().ok_or(StockEventEnvelopeError::Shape)?;
    if object.len() != 3
        || !object.contains_key("id")
        || !object.contains_key("type")
        || !object.contains_key("properties")
    {
        return Err(StockEventEnvelopeError::Shape);
    }
    let event_id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| safe_ascii(value, MAX_EVENT_ID_BYTES, false))
        .ok_or(StockEventEnvelopeError::Shape)?;
    let event_type = object
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| safe_ascii(value, MAX_EVENT_TYPE_BYTES, true))
        .ok_or(StockEventEnvelopeError::Shape)?;
    if !VERIFIED_EVENT_TYPES.contains(&event_type) {
        return Err(StockEventEnvelopeError::UnsupportedType);
    }
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(StockEventEnvelopeError::Shape)?;
    Ok(OfficialStockObservation {
        event_id: event_id.to_owned(),
        event_type: event_type.to_owned(),
        property_count: properties.len(),
    })
}

fn safe_ascii(value: &str, maximum: usize, event_type: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b':')
                || (event_type && byte == b'.')
        })
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded duplicate-free JSON")
    }

    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: DeError>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: DeError>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            values.insert(key, map.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}

pub(crate) fn strict_json(raw: &[u8]) -> Result<Value, StockEventEnvelopeError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSeed
        .deserialize(&mut deserializer)
        .map_err(|_| StockEventEnvelopeError::Json)?;
    deserializer
        .end()
        .map_err(|_| StockEventEnvelopeError::Json)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_official_shape_is_observed_but_not_mapped() {
        let observed = observe_official_stock_envelope(
            br#"{"id":"event_1","type":"question.asked","properties":{"sessionID":"session_1","questions":[]}}"#,
        )
        .unwrap();
        assert_eq!(observed.event_id(), "event_1");
        assert_eq!(observed.event_type(), "question.asked");
        assert_eq!(observed.property_count(), 2);
        assert_eq!(
            observed.classification(),
            StockEventClassification::ShapeObservedUnmapped
        );
        assert_eq!(
            STOCK_EVENT_EVIDENCE_CLASS,
            "official_registry_shape_only_not_provider_lifecycle"
        );
    }

    #[test]
    fn unknown_extra_missing_and_nonobject_properties_fail_closed() {
        for raw in [
            br#"{"id":"e","type":"unknown","properties":{}}"#.as_slice(),
            br#"{"id":"e","type":"session.created","properties":{},"seq":1}"#,
            br#"{"id":"e","type":"session.created"}"#,
            br#"{"id":"e","type":"session.created","properties":[]}"#,
        ] {
            assert!(observe_official_stock_envelope(raw).is_err());
        }
    }

    #[test]
    fn duplicate_keys_invalid_identifiers_trailing_and_oversize_fail_closed() {
        for raw in [
            br#"{"id":"e","id":"other","type":"session.created","properties":{}}"#.as_slice(),
            br#"{"id":"bad id","type":"session.created","properties":{}}"#,
            br#"{"id":"e","type":"Session.Created","properties":{}}"#,
            br#"{"id":"e","type":"session.created","properties":{"x":1,"x":2}}"#,
            br#"{"id":"e","type":"session.created","properties":{}} trailing"#,
        ] {
            assert!(observe_official_stock_envelope(raw).is_err());
        }
        assert!(matches!(
            observe_official_stock_envelope(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
            Err(StockEventEnvelopeError::Size)
        ));
    }

    #[test]
    fn upstream_sequence_and_durability_claims_are_rejected() {
        let raw = br#"{"id":"e","type":"session.diff","properties":{},"seq":7,"durable":true}"#;
        assert!(matches!(
            observe_official_stock_envelope(raw),
            Err(StockEventEnvelopeError::Shape)
        ));
    }
}
