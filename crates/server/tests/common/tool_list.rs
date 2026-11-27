//! Checks shared by the core and extension `tools/list` tests.

use schemars::Schema;
use schemars::transform::transform_subschemas;
use serde_json::Value;

/// Every advertised title is usable and every input property declares its type.
pub fn assert_listed_metadata(tool: &Value) {
    let title = &tool["title"];
    let name = &tool["name"];
    assert!(
        title.as_str().is_some_and(|title| !title.trim().is_empty()),
        "{name}: missing title"
    );
    assert_eq!(
        tool["annotations"]["title"], *title,
        "{name}: mismatched titles"
    );
    let mut input = Schema::try_from(tool["inputSchema"].clone()).unwrap();
    assert_property_types(&mut input, name);
}

fn assert_property_types(schema: &mut Schema, name: &Value) {
    let valid = |value: &Value| {
        matches!(
            value.as_str(),
            Some("array" | "boolean" | "integer" | "null" | "number" | "object" | "string")
        )
    };
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (property, schema) in properties {
            let kind = &schema["type"];
            assert!(
                valid(kind)
                    || kind
                        .as_array()
                        .is_some_and(|types| !types.is_empty() && types.iter().all(valid)),
                "{name}.{property}: no valid type in {schema}",
            );
        }
    }
    let mut visit = |child: &mut Schema| assert_property_types(child, name);
    if let Some(dependencies) = schema
        .get_mut("dependentSchemas")
        .and_then(Value::as_object_mut)
    {
        for child in dependencies.values_mut() {
            visit(<&mut Schema>::try_from(child).unwrap());
        }
    }
    for key in ["unevaluatedItems", "unevaluatedProperties", "contentSchema"] {
        if let Some(child) = schema.get_mut(key) {
            visit(<&mut Schema>::try_from(child).unwrap());
        }
    }
    transform_subschemas(&mut visit, schema);
}
