//! Rendering records as event XML, the way Event Viewer shows them.

use core::fmt::Write;

use crate::tree::{Element, Node};

/// Render an element and its descendants as XML.
#[must_use]
pub fn render(element: &Element) -> String {
    let mut out = String::new();
    write_element(&mut out, element);
    out
}

/// Render a sequence of nodes as XML.
pub(crate) fn render_nodes(nodes: &[Node]) -> String {
    let mut out = String::new();
    for node in nodes {
        write_node(&mut out, node);
    }
    out
}

/// The text a predefined XML entity stands for, or the reference itself.
pub(crate) fn entity(name: &str) -> String {
    match name {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" => "'".into(),
        other => format!("&{other};"),
    }
}

fn write_element(out: &mut String, element: &Element) {
    out.push('<');
    out.push_str(&element.name);
    for attribute in &element.attributes {
        let value = crate::tree::text_of(&attribute.value);
        let _ = write!(out, " {}=\"{}\"", attribute.name, escape(&value));
    }
    if element.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    element
        .children
        .iter()
        .for_each(|node| write_node(out, node));
    let _ = write!(out, "</{}>", element.name);
}

fn write_node(out: &mut String, node: &Node) {
    match node {
        Node::Element(child) => write_element(out, child),
        Node::Value(value) => out.push_str(&escape(&value.to_string())),
        Node::CData(data) => {
            let _ = write!(out, "<![CDATA[{data}]]>");
        }
        Node::EntityRef(name) => {
            let _ = write!(out, "&{name};");
        }
        Node::CharRef(code) => {
            let _ = write!(out, "&#{code};");
        }
        Node::ProcessingInstruction { target, data } => {
            let _ = write!(out, "<?{target} {data}?>");
        }
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Attribute;
    use crate::Value;

    fn element(name: &str, attributes: Vec<Attribute>, children: Vec<Node>) -> Element {
        Element {
            name: name.into(),
            attributes,
            children,
        }
    }

    #[test]
    fn renders_attributes_children_and_empty_elements() {
        let data = element(
            "Data",
            vec![Attribute {
                name: "Name".into(),
                value: vec![Node::Value(Value::String("TargetUserName".into()))],
            }],
            vec![Node::Value(Value::String("alice".into()))],
        );
        let root = element(
            "EventData",
            vec![],
            vec![
                Node::Element(data),
                Node::Element(element("Binary", vec![], vec![])),
            ],
        );
        assert_eq!(
            render(&root),
            r#"<EventData><Data Name="TargetUserName">alice</Data><Binary/></EventData>"#
        );
    }

    #[test]
    fn escapes_markup_in_values() {
        let root = element(
            "Data",
            vec![],
            vec![Node::Value(Value::String("a<b & \"c\"".into()))],
        );
        assert_eq!(render(&root), "<Data>a&lt;b &amp; &quot;c&quot;</Data>");
    }
}
