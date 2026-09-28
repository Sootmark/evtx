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
            time_created: system
                .child("TimeCreated")
                .and_then(|e| typed_attribute(e, "SystemTime"))
                .and_then(Value::as_ts),
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

/// The single typed value of attribute `name`, if it has exactly one.
fn typed_attribute<'e>(element: &'e Element, name: &str) -> Option<&'e Value> {
    let attribute = element.attributes.iter().find(|a| a.name == name)?;
    match attribute.value.as_slice() {
        [Node::Value(value)] => Some(value),
        _ => None,
    }
}
