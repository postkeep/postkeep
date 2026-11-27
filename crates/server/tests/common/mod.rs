//! Shared integration-test helpers for MCP requests and output schemas.

#[allow(dead_code, reason = "the provider suite only uses the schema helpers")]
pub mod mcp_request;

use serde_json::Value;

/// Panics unless `result`, the `structuredContent` of a call to `tool`,
/// matches the tool's `outputSchema` in `tools`, the list that `tools/list`
/// answers. A tool without an output schema passes.
pub fn assert_matches_output_schema(tools: &Value, tool: &str, result: &Value) {
    let listed = tools
        .as_array()
        .and_then(|tools| tools.iter().find(|listed| listed["name"] == tool))
        .unwrap_or_else(|| panic!("{tool} is not in tools/list"));
    let Some(schema) = listed.get("outputSchema") else {
        return;
    };
    let problems = problems(schema, schema, result, "result");
    assert!(
        problems.is_empty(),
        "{tool}'s result does not match its output schema: {problems:?}\n{result}"
    );
}

/// Where `value` breaks `schema`. Only the keywords that the tools' output
/// schemas use are known; any other one fails the test, so that this check
/// learns it before a schema relies on it. `root` holds the `$defs` that a
/// `$ref` names.
fn problems(root: &Value, schema: &Value, value: &Value, at: &str) -> Vec<String> {
    let Some(schema) = schema.as_object() else {
        panic!("{at}: a schema that is not an object: {schema}");
    };
    let mut found = Vec::new();
    for (keyword, rule) in schema {
        match keyword.as_str() {
            "$schema" | "$defs" | "description" | "format" => {}
            "$ref" => {
                let name = rule
                    .as_str()
                    .and_then(|path| path.strip_prefix("#/$defs/"))
                    .unwrap_or_else(|| panic!("{at}: a $ref this check can't follow: {rule}"));
                found.extend(problems(root, &root["$defs"][name], value, at));
            }
            "type" => {
                let kinds: Vec<&str> = match rule {
                    Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
                    kind => kind.as_str().into_iter().collect(),
                };
                if !kinds.iter().any(|kind| is(value, kind)) {
                    found.push(format!("{at} is not {}: {value}", kinds.join(" or ")));
                }
            }
            "required" => {
                if let Some(object) = value.as_object() {
                    let names = rule.as_array().into_iter().flatten();
                    for name in names.filter_map(Value::as_str) {
                        if !object.contains_key(name) {
                            found.push(format!("{at}.{name} is missing"));
                        }
                    }
                }
            }
            "properties" => {
                if let (Some(object), Some(properties)) = (value.as_object(), rule.as_object()) {
                    for (name, field) in object {
                        if let Some(property) = properties.get(name) {
                            found.extend(problems(root, property, field, &format!("{at}.{name}")));
                        }
                    }
                }
            }
            "items" => {
                for (index, item) in value.as_array().into_iter().flatten().enumerate() {
                    found.extend(problems(root, rule, item, &format!("{at}[{index}]")));
                }
            }
            "oneOf" => {
                let branches = rule.as_array().into_iter().flatten();
                let matching = branches
                    .filter(|branch| problems(root, branch, value, at).is_empty())
                    .count();
                if matching != 1 {
                    found.push(format!("{at} matches {matching} of oneOf: {value}"));
                }
            }
            "const" => {
                if value != rule {
                    found.push(format!("{at} is not {rule}: {value}"));
                }
            }
            "enum" => {
                if !rule.as_array().is_some_and(|values| values.contains(value)) {
                    found.push(format!("{at} is not one of {rule}: {value}"));
                }
            }
            "additionalProperties" => {
                if let Some(object) = value.as_object() {
                    for (name, field) in object {
                        if schema
                            .get("properties")
                            .is_some_and(|properties| properties.get(name).is_some())
                        {
                            continue;
                        }
                        match rule {
                            Value::Bool(true) => {}
                            Value::Bool(false) => found.push(format!("{at}.{name} is not allowed")),
                            _ => found.extend(problems(root, rule, field, &format!("{at}.{name}"))),
                        }
                    }
                }
            }
            "minimum" => {
                if let (Some(number), Some(minimum)) = (value.as_f64(), rule.as_f64())
                    && number < minimum
                {
                    found.push(format!("{at} is below {minimum}: {value}"));
                }
            }
            other => panic!("{at}: this check doesn't know the keyword {other}"),
        }
    }
    found
}

/// Whether `value` has the JSON Schema type `kind`.
fn is(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        other => panic!("a type this check doesn't know: {other}"),
    }
}

#[test]
fn enum_and_map_output_schemas_reject_wrong_values() {
    let schema = serde_json::json!({ "enum": ["allowed"] });
    assert_eq!(
        problems(&schema, &schema, &serde_json::json!("allowed"), "status"),
        [] as [String; 0]
    );
    assert_ne!(
        problems(&schema, &schema, &serde_json::json!("unknown"), "status"),
        [] as [String; 0]
    );
    let schema = serde_json::json!({ "additionalProperties": { "type": "string" } });
    assert_eq!(
        problems(
            &schema,
            &schema,
            &serde_json::json!({ "old": "new" }),
            "new_ids"
        ),
        [] as [String; 0]
    );
    assert_ne!(
        problems(
            &schema,
            &schema,
            &serde_json::json!({ "old": 1 }),
            "new_ids"
        ),
        [] as [String; 0]
    );
}
