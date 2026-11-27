//! Completes the metadata advertised by `tools/list`, without changing calls.

use std::collections::BTreeSet;
use std::sync::Arc;

use rmcp::model::Tool;
use schemars::Schema;
use schemars::consts::meta_schemas::DRAFT2020_12;
use schemars::transform::transform_subschemas;
use serde_json::{Value, json};

// `number` also accepts every integer.
const ANY_TYPES: [&str; 6] = ["array", "boolean", "null", "number", "object", "string"];
type Types<'a> = BTreeSet<&'a str>;

pub(super) fn prepare_listed_tool(tool: &mut Tool) {
    let annotations = tool.annotations.get_or_insert_default();
    if tool
        .title
        .as_ref()
        .is_none_or(|title| title.trim().is_empty())
    {
        tool.title = Some(
            annotations
                .title
                .as_ref()
                .filter(|title| !title.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| tool.name.to_string()),
        );
    }
    annotations.title.clone_from(&tool.title);

    let original = tool.input_schema.as_ref();
    let mut schema = Schema::from(original.clone());
    add_property_types(&mut schema, original.get("$defs"), true, true);
    if let Value::Object(schema) = schema.to_value() {
        tool.input_schema = Arc::new(schema);
    }
}

fn add_property_types(schema: &mut Schema, defs: Option<&Value>, root: bool, infer: bool) {
    // Do not resolve a reference against a different resource or infer types
    // under an unknown dialect, where keyword semantics can differ.
    let defs = if root || schema.get("$id").is_none() {
        defs
    } else {
        None
    };
    let infer = schema
        .get("$schema")
        .map_or(infer, |dialect| dialect == DRAFT2020_12);
    let mut visit = |child: &mut Schema| add_property_types(child, defs, false, infer);
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        for property in properties.values_mut() {
            if let Ok(property) = <&mut Schema>::try_from(property)
                && property.get("type").is_none()
            {
                let types = infer
                    .then(|| infer_types(property.as_value(), defs, &mut 256))
                    .flatten();
                property.insert("type".to_owned(), type_keyword(types));
            }
        }
    }
    // Schemars's traversal doesn't include these 2020-12 subschema keywords.
    if let Some(dependencies) = schema
        .get_mut("dependentSchemas")
        .and_then(Value::as_object_mut)
    {
        for child in dependencies
            .values_mut()
            .filter_map(|value| <&mut Schema>::try_from(value).ok())
        {
            visit(child);
        }
    }
    for key in ["unevaluatedItems", "unevaluatedProperties", "contentSchema"] {
        if let Some(child) = schema
            .get_mut(key)
            .and_then(|value| <&mut Schema>::try_from(value).ok())
        {
            visit(child);
        }
    }
    transform_subschemas(&mut visit, schema);
}

fn type_keyword(types: Option<Types<'_>>) -> Value {
    let Some(mut types) = types.filter(|types| !types.is_empty()) else {
        return json!(ANY_TYPES);
    };
    if types.contains("number") {
        types.remove("integer");
    }
    if types.len() == 1
        && let Some(kind) = types.first()
    {
        return json!(kind);
    }
    json!(types)
}

// Each result is an upper bound on the types this schema accepts. `None`
// means unknown, not impossible. Keep integers separate from other numbers
// internally so type sets can be intersected (e.g. number AND integer).
fn infer_types<'a>(
    schema: &'a Value,
    defs: Option<&'a Value>,
    budget: &mut u16,
) -> Option<Types<'a>> {
    // Bound the total work, including repeated visits through branching refs.
    *budget = budget.checked_sub(1)?;
    if schema == &Value::Bool(false) {
        return Some(Types::new());
    }
    if schema
        .get("$schema")
        .is_some_and(|dialect| dialect != DRAFT2020_12)
    {
        return None;
    }
    let defs = if schema.get("$id").is_none() {
        defs
    } else {
        None
    };
    if let Some(kind) = schema.get("type") {
        let kinds = kind
            .as_array()
            .map_or_else(|| std::slice::from_ref(kind), Vec::as_slice);
        let mut types = Types::new();
        for kind in kinds {
            let kind = kind
                .as_str()
                .filter(|kind| *kind == "integer" || ANY_TYPES.contains(kind))?;
            insert_type(&mut types, kind);
        }
        return Some(types);
    }
    if let Some(values) = schema.get("const").map(std::slice::from_ref).or_else(|| {
        schema
            .get("enum")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    }) {
        let mut types = Types::new();
        for value in values {
            insert_type(&mut types, value_type(value));
        }
        return Some(types);
    }
    if let Some(target) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/$defs"))
        .and_then(|pointer| {
            // Only follow direct, same-resource definitions; do not cross an
            // intervening $id or misinterpret a URI-encoded pointer fragment.
            let key = pointer.strip_prefix('/')?;
            if key.contains(['/', '%']) {
                return None;
            }
            defs?.pointer(pointer)
        })
        .and_then(|target| infer_types(target, defs, budget))
    {
        return Some(target);
    }
    let mut intersection: Option<Types<'a>> = None;
    for part in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if *budget == 0 {
            break;
        }
        if let Some(part) = infer_types(part, defs, budget) {
            if let Some(types) = &mut intersection {
                types.retain(|kind| part.contains(kind));
            } else {
                intersection = Some(part);
            }
        }
    }
    if intersection.is_some() {
        return intersection;
    }
    ["anyOf", "oneOf"].into_iter().find_map(|keyword| {
        let mut types = Types::new();
        for part in schema.get(keyword)?.as_array()? {
            types.extend(infer_types(part, defs, budget)?);
        }
        Some(types)
    })
}

fn insert_type<'a>(types: &mut Types<'a>, kind: &'a str) {
    if kind == "number" {
        types.insert("integer");
    }
    types.insert(kind);
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "array",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::Object(_) => "object",
        Value::String(_) => "string",
    }
}
