//! Fuzz phase case generation — boundary, type-confusion, probe, neighborhood
//!
//! Each case carries a [`StatusExpectation`] derived from the OpenAPI spec
//! and the fuzz phase, enabling per-request verdict logic downstream.

use std::collections::HashMap;

use rand::Rng;

use apifuzz_core::Probe;

use crate::datagen;

use super::spec::Operation;

/// Fuzz phase identifier — used to derive expectations and apply phase-specific checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FuzzPhase {
    Probe,
    Boundary,
    TypeConfusion,
    Neighborhood,
    Random,
}

/// What status codes are expected for this case.
///
/// Derived from the OpenAPI spec's declared responses + fuzz phase.
/// Used by `StatusSatisfyExpectation` check to determine if actual
/// response status is acceptable.
#[derive(Clone, Debug)]
pub(super) enum StatusExpectation {
    /// Spec-declared 2xx codes expected (valid input: Random).
    /// Falls back to `[200]` if no 2xx declared in spec.
    SuccessExpected(Vec<u16>),
    /// Any spec-declared code is acceptable (edge/unknown input: Probe, Boundary, Neighborhood).
    /// Falls back to `[200]` if none declared.
    AnyDeclared(Vec<u16>),
    /// 4xx rejection expected — 2xx means the server accepted invalid input (TypeConfusion).
    Rejection,
}

impl StatusExpectation {
    /// Derive expectation from operation spec and fuzz phase.
    pub(super) fn from_phase(op: &Operation, phase: FuzzPhase) -> Self {
        let declared = &op.expected_statuses;
        match phase {
            // Random: datagen::generate() produces spec-compliant values → expect 2xx
            FuzzPhase::Random => {
                let success_codes: Vec<u16> = declared
                    .iter()
                    .copied()
                    .filter(|&c| (200..300).contains(&c))
                    .collect();
                if success_codes.is_empty() {
                    Self::SuccessExpected(vec![200])
                } else {
                    Self::SuccessExpected(success_codes)
                }
            }
            // Probe: user-defined values, intent unknown → any declared is acceptable
            // Boundary: edge values, some within spec, some outside → any declared
            // Neighborhood: near-boundary with noise → any declared
            FuzzPhase::Probe | FuzzPhase::Boundary | FuzzPhase::Neighborhood => {
                if declared.is_empty() {
                    Self::AnyDeclared(vec![200])
                } else {
                    Self::AnyDeclared(declared.clone())
                }
            }
            // TypeConfusion: wrong-type input → server must reject with 4xx
            FuzzPhase::TypeConfusion => Self::Rejection,
        }
    }
}

/// Overrides for boundary testing: force specific values for params or body properties.
#[derive(Default)]
pub(super) struct Overrides {
    pub(super) params: HashMap<String, serde_json::Value>,
    pub(super) body_props: HashMap<String, serde_json::Value>,
}

/// A fuzz case: what to send + what to expect.
pub(super) struct FuzzCase {
    pub(super) overrides: Overrides,
    pub(super) expectation: StatusExpectation,
}

impl FuzzCase {
    fn with_expectation(overrides: Overrides, expectation: StatusExpectation) -> Self {
        Self {
            overrides,
            expectation,
        }
    }
}

/// Generate a single near-boundary override for a random parameter or body property.
pub(super) fn generate_neighborhood_case(
    op: &Operation,
    components: &serde_json::Value,
    rng: &mut impl Rng,
) -> FuzzCase {
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

    let expectation = StatusExpectation::from_phase(op, FuzzPhase::Neighborhood);

    if targets.is_empty() {
        return FuzzCase::with_expectation(Overrides::default(), expectation);
    }

    let target = &targets[rng.gen_range(0..targets.len())];
    let overrides = match target {
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
    };

    FuzzCase::with_expectation(overrides, expectation)
}

/// Collect boundary test cases for an operation.
///
/// For each parameter and each body property, generates one [`FuzzCase`]
/// per boundary value. Other fields use random/default values.
pub(super) fn collect_boundary_cases(
    op: &Operation,
    components: &serde_json::Value,
) -> Vec<FuzzCase> {
    let mut cases = Vec::new();
    let expectation = StatusExpectation::from_phase(op, FuzzPhase::Boundary);

    // Parameter boundaries (path, query, header)
    for param in &op.parameters {
        let bv = datagen::boundaries(&param.schema, components);
        for val in bv {
            let mut params = HashMap::new();
            params.insert(param.name.clone(), val);
            cases.push(FuzzCase::with_expectation(
                Overrides {
                    params,
                    body_props: HashMap::new(),
                },
                expectation.clone(),
            ));
        }
    }

    // Request body property boundaries
    if let Some(body_schema) = &op.request_body_schema {
        let prop_boundaries = datagen::object_property_boundaries(body_schema, components);
        for (prop_name, bv) in prop_boundaries {
            for val in bv {
                let mut body_props = HashMap::new();
                body_props.insert(prop_name.clone(), val);
                cases.push(FuzzCase::with_expectation(
                    Overrides {
                        params: HashMap::new(),
                        body_props,
                    },
                    expectation.clone(),
                ));
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
) -> Vec<FuzzCase> {
    let mut cases = Vec::new();
    let expectation = StatusExpectation::from_phase(op, FuzzPhase::TypeConfusion);

    // Parameter type confusion
    for param in &op.parameters {
        let tc = datagen::type_confusion_values(&param.schema, components);
        for val in tc {
            let mut params = HashMap::new();
            params.insert(param.name.clone(), val);
            cases.push(FuzzCase::with_expectation(
                Overrides {
                    params,
                    body_props: HashMap::new(),
                },
                expectation.clone(),
            ));
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
                cases.push(FuzzCase::with_expectation(
                    Overrides {
                        params: HashMap::new(),
                        body_props,
                    },
                    expectation.clone(),
                ));
            }
        }
    }

    cases
}

/// Collect user-defined probe cases from TOML config.
///
/// Matches probes by operation label ("POST /orders") and generates
/// one [`FuzzCase`] per probe value. The target is matched against both
/// parameter names and body property names.
pub(super) fn collect_probe_cases(op: &Operation, probes: &[Probe]) -> Vec<FuzzCase> {
    let mut cases = Vec::new();
    let expectation = StatusExpectation::from_phase(op, FuzzPhase::Probe);

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
                cases.push(FuzzCase::with_expectation(
                    Overrides {
                        params,
                        body_props: HashMap::new(),
                    },
                    expectation.clone(),
                ));
            }
            if is_body_prop {
                let mut body_props = HashMap::new();
                body_props.insert(probe.target.clone(), val.clone());
                cases.push(FuzzCase::with_expectation(
                    Overrides {
                        params: HashMap::new(),
                        body_props,
                    },
                    expectation.clone(),
                ));
            }
            // target が param でも body_prop でもない場合は
            // param として注入を試みる（ユーザーの意図を尊重）
            if !is_param && !is_body_prop {
                let mut params = HashMap::new();
                params.insert(probe.target.clone(), val);
                cases.push(FuzzCase::with_expectation(
                    Overrides {
                        params,
                        body_props: HashMap::new(),
                    },
                    expectation.clone(),
                ));
            }
        }
    }

    cases
}
