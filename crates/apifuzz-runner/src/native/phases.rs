//! Fuzz phase case generation — boundary, type-confusion, probe, neighborhood

use std::collections::HashMap;

use rand::Rng;

use apifuzz_core::Probe;

use crate::datagen;

use super::spec::Operation;

/// Fuzz phase identifier — used to apply phase-specific checks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FuzzPhase {
    Probe,
    Boundary,
    TypeConfusion,
    Neighborhood,
    Random,
}

/// Overrides for boundary testing: force specific values for params or body properties.
#[derive(Default)]
pub(super) struct Overrides {
    pub(super) params: HashMap<String, serde_json::Value>,
    pub(super) body_props: HashMap<String, serde_json::Value>,
}

/// Generate a single near-boundary override for a random parameter or body property.
pub(super) fn generate_neighborhood_override(
    op: &Operation,
    components: &serde_json::Value,
    rng: &mut impl Rng,
) -> Overrides {
    enum Target {
        Param {
            name: String,
            schema: serde_json::Value,
        },
        BodyProp {
            name: String,
            schema: serde_json::Value,
        },
    }

    let mut targets: Vec<Target> = Vec::new();

    for param in &op.parameters {
        if !datagen::boundaries(&param.schema, components).is_empty() {
            targets.push(Target::Param {
                name: param.name.clone(),
                schema: param.schema.clone(),
            });
        }
    }

    if let Some(body_schema) = &op.request_body_schema {
        for (name, prop_schema) in datagen::resolve_object_properties(body_schema, components) {
            if !datagen::boundaries(&prop_schema, components).is_empty() {
                targets.push(Target::BodyProp {
                    name,
                    schema: prop_schema,
                });
            }
        }
    }

    if targets.is_empty() {
        return Overrides::default();
    }

    let target = &targets[rng.gen_range(0..targets.len())];
    match target {
        Target::Param { name, schema } => {
            let val = datagen::near_boundary(schema, components, rng);
            let mut params = HashMap::new();
            params.insert(name.clone(), val);
            Overrides {
                params,
                body_props: HashMap::new(),
            }
        }
        Target::BodyProp { name, schema } => {
            let val = datagen::near_boundary(schema, components, rng);
            let mut body_props = HashMap::new();
            body_props.insert(name.clone(), val);
            Overrides {
                params: HashMap::new(),
                body_props,
            }
        }
    }
}

/// Collect boundary test cases for an operation.
///
/// For each parameter and each body property, generates one `Overrides`
/// per boundary value. Other fields use random/default values.
pub(super) fn collect_boundary_cases(
    op: &Operation,
    components: &serde_json::Value,
) -> Vec<Overrides> {
    let mut cases = Vec::new();

    // Parameter boundaries (path, query, header)
    for param in &op.parameters {
        let bv = datagen::boundaries(&param.schema, components);
        for val in bv {
            let mut params = HashMap::new();
            params.insert(param.name.clone(), val);
            cases.push(Overrides {
                params,
                body_props: HashMap::new(),
            });
        }
    }

    // Request body property boundaries
    if let Some(body_schema) = &op.request_body_schema {
        let prop_boundaries = datagen::object_property_boundaries(body_schema, components);
        for (prop_name, bv) in prop_boundaries {
            for val in bv {
                let mut body_props = HashMap::new();
                body_props.insert(prop_name.clone(), val);
                cases.push(Overrides {
                    params: HashMap::new(),
                    body_props,
                });
            }
        }
    }

    cases
}

/// Collect type-confusion test cases for an operation.
///
/// For each parameter and body property, injects values of wrong JSON types
/// (e.g., string "123" where integer expected, null where object expected).
/// Catches serializer/deserializer coercion bugs and type-handling crashes.
pub(super) fn collect_type_confusion_cases(
    op: &Operation,
    components: &serde_json::Value,
) -> Vec<Overrides> {
    let mut cases = Vec::new();

    // Parameter type confusion
    for param in &op.parameters {
        let tc = datagen::type_confusion_values(&param.schema, components);
        for val in tc {
            let mut params = HashMap::new();
            params.insert(param.name.clone(), val);
            cases.push(Overrides {
                params,
                body_props: HashMap::new(),
            });
        }
    }

    // Body property type confusion
    if let Some(body_schema) = &op.request_body_schema {
        for (prop_name, prop_schema) in datagen::resolve_object_properties(body_schema, components)
        {
            let tc = datagen::type_confusion_values(&prop_schema, components);
            for val in tc {
                let mut body_props = HashMap::new();
                body_props.insert(prop_name.clone(), val);
                cases.push(Overrides {
                    params: HashMap::new(),
                    body_props,
                });
            }
        }
    }

    cases
}

/// Collect user-defined probe cases from TOML config.
///
/// Matches probes by operation label ("POST /orders") and generates
/// one `Overrides` per probe value. The target is matched against both
/// parameter names and body property names.
pub(super) fn collect_probe_cases(op: &Operation, probes: &[Probe]) -> Vec<Overrides> {
    let mut cases = Vec::new();

    let param_names: Vec<&str> = op.parameters.iter().map(|p| p.name.as_str()).collect();
    let body_prop_names: Vec<String> = op
        .request_body_schema
        .as_ref()
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default();

    for probe in probes {
        if !probe.matches_operation(&op.method, &op.path) {
            continue;
        }

        let values = probe.to_json_values();
        let is_param = param_names.contains(&probe.target.as_str());
        let is_body_prop = body_prop_names.contains(&probe.target);

        for val in values {
            if is_param {
                let mut params = HashMap::new();
                params.insert(probe.target.clone(), val.clone());
                cases.push(Overrides {
                    params,
                    body_props: HashMap::new(),
                });
            }
            if is_body_prop {
                let mut body_props = HashMap::new();
                body_props.insert(probe.target.clone(), val.clone());
                cases.push(Overrides {
                    params: HashMap::new(),
                    body_props,
                });
            }
            // target が param でも body_prop でもない場合は
            // param として注入を試みる（ユーザーの意図を尊重）
            if !is_param && !is_body_prop {
                let mut params = HashMap::new();
                params.insert(probe.target.clone(), val);
                cases.push(Overrides {
                    params,
                    body_props: HashMap::new(),
                });
            }
        }
    }

    cases
}
