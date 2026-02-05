//! OpenAPI spec parsing — extract operations, parameters, and response schemas

use std::collections::HashMap;

use crate::datagen;

/// Extracted API operation
pub(super) struct Operation {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) parameters: Vec<Parameter>,
    pub(super) request_body_schema: Option<serde_json::Value>,
    pub(super) expected_statuses: Vec<u16>,
    /// Response schemas per status code (resolved, ready for validation)
    pub(super) response_schemas: HashMap<u16, serde_json::Value>,
    /// Expected content types per status code
    pub(super) response_content_types: HashMap<u16, Vec<String>>,
}

pub(super) struct Parameter {
    pub(super) name: String,
    pub(super) location: ParamLocation,
    pub(super) schema: serde_json::Value,
    pub(super) required: bool,
}

#[derive(PartialEq)]
pub(super) enum ParamLocation {
    Path,
    Query,
    Header,
}

pub(super) fn extract_operations(spec: &serde_json::Value) -> Vec<Operation> {
    let mut ops = Vec::new();
    let components = spec
        .get("components")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let paths = match spec.get("paths").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return ops,
    };

    for (path, path_item) in paths {
        for method in &["get", "post", "put", "delete", "patch"] {
            if let Some(operation) = path_item.get(*method) {
                let mut parameters = Vec::new();

                // Collect parameters from path-level + operation-level
                for source in [path_item.get("parameters"), operation.get("parameters")]
                    .iter()
                    .flatten()
                {
                    if let Some(params) = source.as_array() {
                        for param in params {
                            if let Some(p) = parse_parameter(param) {
                                parameters.push(p);
                            }
                        }
                    }
                }

                // Request body schema
                let request_body_schema = operation
                    .get("requestBody")
                    .and_then(|rb| rb.get("content"))
                    .and_then(|c| c.get("application/json"))
                    .and_then(|ct| ct.get("schema"))
                    .cloned();

                // Extract response metadata per status code
                let responses_obj = operation.get("responses").and_then(|r| r.as_object());

                let expected_statuses: Vec<u16> = responses_obj
                    .map(|r| r.keys().filter_map(|k| k.parse().ok()).collect())
                    .unwrap_or_default();

                let mut response_schemas: HashMap<u16, serde_json::Value> = HashMap::new();
                let mut response_content_types: HashMap<u16, Vec<String>> = HashMap::new();

                if let Some(responses) = responses_obj {
                    for (status_str, resp_obj) in responses {
                        let Some(status) = status_str.parse::<u16>().ok() else {
                            continue;
                        };
                        if let Some(content) = resp_obj.get("content").and_then(|c| c.as_object()) {
                            // Content types declared for this status
                            let types: Vec<String> = content.keys().cloned().collect();
                            if !types.is_empty() {
                                response_content_types.insert(status, types);
                            }
                            // Response schema (prefer application/json)
                            if let Some(schema) = content
                                .get("application/json")
                                .and_then(|ct| ct.get("schema"))
                            {
                                let resolved = resolve_refs(schema, &components);
                                response_schemas.insert(status, resolved);
                            }
                        }
                    }
                }

                ops.push(Operation {
                    method: method.to_uppercase(),
                    path: path.clone(),
                    parameters,
                    request_body_schema,
                    expected_statuses,
                    response_schemas,
                    response_content_types,
                });
            }
        }
    }

    ops
}

fn parse_parameter(param: &serde_json::Value) -> Option<Parameter> {
    let name = param.get("name")?.as_str()?.to_string();
    let location = match param.get("in")?.as_str()? {
        "path" => ParamLocation::Path,
        "query" => ParamLocation::Query,
        "header" => ParamLocation::Header,
        _ => return None,
    };
    let schema = param
        .get("schema")
        .cloned()
        .unwrap_or(serde_json::json!({"type": "string"}));
    let required = param
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Some(Parameter {
        name,
        location,
        schema,
        required,
    })
}

/// Recursively resolve `$ref` in a JSON Schema against OpenAPI components.
///
/// Produces a self-contained schema suitable for `jsonschema` validation.
/// Depth-limited to 20 to prevent infinite recursion on circular refs.
fn resolve_refs(schema: &serde_json::Value, components: &serde_json::Value) -> serde_json::Value {
    resolve_refs_inner(schema, components, 0)
}

fn resolve_refs_inner(
    schema: &serde_json::Value,
    components: &serde_json::Value,
    depth: u32,
) -> serde_json::Value {
    if depth > 20 {
        return schema.clone();
    }
    match schema {
        serde_json::Value::Object(obj) => {
            // Resolve $ref
            if let Some(ref_str) = obj.get("$ref").and_then(|v| v.as_str()) {
                if let Some(resolved) = datagen::resolve_ref(ref_str, components) {
                    return resolve_refs_inner(&resolved, components, depth + 1);
                }
                return schema.clone();
            }
            // Recurse into all values
            let new_obj: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| (k.clone(), resolve_refs_inner(v, components, depth + 1)))
                .collect();
            serde_json::Value::Object(new_obj)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| resolve_refs_inner(v, components, depth + 1))
                .collect(),
        ),
        _ => schema.clone(),
    }
}
