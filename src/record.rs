//! Records and the standard event fields inside them.

use common::time::Ts;

use crate::tree::{Element, Node};
use crate::Value;

/// One decoded event record.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// File offset where the record starts.
    pub offset: u64,
    /// Event record identifier, from the record header.
    pub id: u64,
    /// Raw FILETIME at which the record was written, from the record header.
    pub written: u64,
    /// The decoded `<Event>` element.
    pub root: Element,
}

/// The standard `<System>` fields of an event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct System {
    /// `Provider/@Name`.
    pub provider: Option<String>,
    /// `EventID` (without qualifiers).
    pub event_id: Option<u32>,
    /// `Level`.
    pub level: Option<u8>,
    /// `TimeCreated/@SystemTime`.
    pub time_created: Option<Ts>,
    /// `EventRecordID`.
    pub record_id: Option<u64>,
    /// `Execution/@ProcessID`.
    pub process_id: Option<u32>,
    /// `Execution/@ThreadID`.
    pub thread_id: Option<u32>,
    /// `Channel`.
    pub channel: Option<String>,
    /// `Computer`.
    pub computer: Option<String>,
    /// `Security/@UserID`.
    pub user_id: Option<String>,
}

/// One `<Data>` item of `<EventData>`, or one child of `<UserData>`'s element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataItem {
    /// The `Name` attribute or the element name; `None` for unnamed `<Data>`.
    pub name: Option<String>,
    /// The item's text.
    pub value: String,
}

impl Record {
    /// When the record was written, from the record header.
    #[must_use]
    pub fn written_ts(&self) -> Ts {
        Ts::from_filetime(self.written)
    }

    /// The record as event XML.
    #[must_use]
    pub fn to_xml(&self) -> String {
        crate::xml::render(&self.root)
    }

    /// The standard `<System>` fields. Missing fields are `None`.
    #[must_use]
    pub fn system(&self) -> System {
        let Some(system) = self.root.child("System") else {
            return System::default();
        };
        let text = |name: &str| system.child(name).map(Element::text);
        let attribute =
            |element: &str, name: &str| system.child(element).and_then(|e| e.attribute(name));
        System {
            provider: attribute("Provider", "Name"),
            event_id: text("EventID").and_then(|t| t.parse().ok()),
            level: text("Level").and_then(|t| t.parse().ok()),
            time_created: system.child("TimeCreated").and_then(|e| {
                typed_attribute(e, "SystemTime")
                    .and_then(Value::as_ts)
                    .or_else(|| {
                        let text = e.attribute("SystemTime")?;
                        filetime_from_text(&text).map(Ts::from_filetime)
                    })
            }),
            record_id: text("EventRecordID").and_then(|t| t.parse().ok()),
            process_id: attribute("Execution", "ProcessID").and_then(|t| t.parse().ok()),
            thread_id: attribute("Execution", "ThreadID").and_then(|t| t.parse().ok()),
            channel: text("Channel"),
            computer: text("Computer"),
            user_id: attribute("Security", "UserID"),
        }
    }

    /// The event's payload: `<EventData>` items, or the children of the
    /// element inside `<UserData>`.
    #[must_use]
    pub fn data(&self) -> Vec<DataItem> {
        if let Some(event_data) = self.root.child("EventData") {
            return event_data
                .child_elements()
                .map(|item| DataItem {
                    name: item.attribute("Name"),
                    value: item.text(),
                })
                .collect();
        }
        self.root
            .child("UserData")
            .and_then(|user_data| user_data.child_elements().next())
            .map(|payload| {
                payload
                    .child_elements()
                    .map(|item| DataItem {
                        name: Some(item.name.clone()),
                        value: item.text(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Days from 1601-01-01 (the FILETIME epoch) to 1970-01-01.
const FILETIME_EPOCH_DAYS: i64 = 134_774;

/// A FILETIME from a time written as text, `2020-12-11T12:28:01.2990045Z`,
/// as records written outside a template carry it.
fn filetime_from_text(text: &str) -> Option<u64> {
    let (date, clock) = text.strip_suffix('Z')?.split_once('T')?;
    let mut date = date.splitn(3, '-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    let (clock, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let mut clock = clock.splitn(3, ':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    let valid = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && (0..24).contains(&hour)
        && (0..60).contains(&minute)
        && (0..61).contains(&second)
        && fraction.len() <= 9
        && fraction.bytes().all(|b| b.is_ascii_digit());
    if !valid {
        return None;
    }
    let ticks: u64 = format!("{fraction:0<7}")[..7].parse().ok()?;
    let days = common::time::days_from_civil(year, month, day) + FILETIME_EPOCH_DAYS;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds)
        .ok()?
        .checked_mul(10_000_000)?
        .checked_add(ticks)
}

/// The single typed value of attribute `name`, if it has exactly one.
fn typed_attribute<'e>(element: &'e Element, name: &str) -> Option<&'e Value> {
    let attribute = element.attributes.iter().find(|a| a.name == name)?;
    match attribute.value.as_slice() {
        [Node::Value(value)] => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_written_as_text() {
        assert_eq!(
            filetime_from_text("1970-01-01T00:00:00Z"),
            Some(116_444_736_000_000_000)
        );
        let ts = Ts::from_filetime(filetime_from_text("2020-12-11T12:28:01.2990045Z").unwrap());
        assert_eq!(ts.to_iso8601().unwrap(), "2020-12-11T12:28:01.2990045Z");
        let ts = Ts::from_filetime(filetime_from_text("2020-06-23T09:35:56.825510000Z").unwrap());
        assert_eq!(ts.to_iso8601().unwrap(), "2020-06-23T09:35:56.8255100Z");
        for bad in [
            "2020-13-01T00:00:00Z",
            "2020-01-01T00:00:00",
            "2020-01-01T24:00:00Z",
            "x",
        ] {
            assert_eq!(filetime_from_text(bad), None, "{bad}");
        }
    }
}
