//! The element tree a record decodes to.

use crate::Value;

/// An XML element.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    /// Element name, e.g. `EventID`.
    pub name: String,
    /// Attributes, in file order.
    pub attributes: Vec<Attribute>,
    /// Child nodes, in file order.
    pub children: Vec<Node>,
}

/// An XML attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Attribute name, e.g. `SystemTime`.
    pub name: String,
    /// The value's parts; usually exactly one.
    pub value: Vec<Node>,
}

/// A piece of element content.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A child element.
    Element(Element),
    /// Text or a typed substitution value.
    Value(Value),
    /// A CDATA section.
    CData(String),
    /// An entity reference such as `amp`, without `&` and `;`.
    EntityRef(String),
    /// A character reference (`&#N;`).
    CharRef(u16),
    /// A processing instruction.
    ProcessingInstruction {
        /// The target.
        target: String,
        /// The data.
        data: String,
    },
}

impl Element {
    /// The first child element named `name`.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.child_elements().find(|e| e.name == name)
    }

    /// Child elements, skipping text and other nodes.
    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            _ => None,
        })
    }

    /// The value of attribute `name`, as text.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| text_of(&a.value))
    }

    /// The element's direct text content (values, CDATA, references).
    #[must_use]
    pub fn text(&self) -> String {
        text_of(&self.children)
    }
}

/// Concatenate the textual parts of `nodes`, ignoring child elements.
pub(crate) fn text_of(nodes: &[Node]) -> String {
    let mut text = String::new();
    for node in nodes {
        match node {
            Node::Value(value) => text.push_str(&value.to_string()),
            Node::CData(data) => text.push_str(data),
            Node::EntityRef(name) => text.push_str(&crate::xml::entity(name)),
            Node::CharRef(code) => text.extend(char::from_u32(u32::from(*code))),
            Node::Element(_) | Node::ProcessingInstruction { .. } => {}
        }
    }
    text
}
