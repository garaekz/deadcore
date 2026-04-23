use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    BroadcastOut, BroadcastParameterOut, ControllerMethodOut, ControllerOut, Delta, DeltaMeta,
    ModelOut, ModelRelationshipOut, PivotOut, PolymorphicOut, PolymorphicRelationOut,
    RequestUsageOut, ResourceUsageOut, ScopeUsedOut, StatsOut,
};
use crate::pipeline::PipelineResult;

pub fn build_delta(result: PipelineResult) -> Delta {
    let scope_owners = collect_scope_owners(&result);
    let route_methods = collect_route_methods(&result);
    let route_order = collect_route_order(&result);
    let mut controllers = Vec::<ControllerOut>::new();
    let mut controller_index = BTreeMap::<(String, String), usize>::new();
    let mut models = Vec::<ModelOut>::new();
    let mut model_index = BTreeMap::<(String, String), usize>::new();
    let mut polymorphic = BTreeMap::<String, Vec<PolymorphicRelationOut>>::new();
    let mut broadcast = Vec::<BroadcastOut>::new();
    let mut seen_broadcast = BTreeSet::<String>::new();

    for file in &result.files {
        for controller in &file.facts.controllers {
            let controller_key = (controller.fqcn.clone(), controller.method_name.clone());
            if !route_methods.is_empty() && !route_methods.contains_key(&controller_key) {
                continue;
            }

            let http_methods = route_methods
                .get(&controller_key)
                .cloned()
                .unwrap_or_default();
            let http_status = controller
                .http_status
                .map(|status| vec![status])
                .unwrap_or_else(|| {
                    if http_methods.is_empty() {
                        Vec::new()
                    } else {
                        vec![200]
                    }
                });

            let controller_key = (controller.fqcn.clone(), file.relative_path.clone());
            let index = if let Some(index) = controller_index.get(&controller_key) {
                *index
            } else {
                let index = controllers.len();
                controller_index.insert(controller_key.clone(), index);
                controllers.push(ControllerOut {
                    fqcn: controller.fqcn.clone(),
                    file: file.relative_path.clone(),
                    methods: Vec::new(),
                });
                index
            };
            controllers[index].methods.push(ControllerMethodOut {
                name: controller.method_name.clone(),
                http_methods,
                http_status,
                request_usage: build_request_usage(controller),
                resource_usage: controller
                    .resource_usage
                    .iter()
                    .map(|resource| ResourceUsageOut {
                        class: resource.class_name.clone(),
                        method: resource.method.clone(),
                    })
                    .collect(),
                scopes_used: controller
                    .scopes_used
                    .iter()
                    .map(|scope| ScopeUsedOut {
                        name: scope.name.clone(),
                        on: scope
                            .on
                            .clone()
                            .or_else(|| scope_owners.get(&scope.name).cloned().flatten()),
                    })
                    .collect(),
            });
        }

        for model in &file.facts.models {
            let model_key = (model.fqcn.clone(), file.relative_path.clone());
            let index = if let Some(index) = model_index.get(&model_key) {
                *index
            } else {
                let index = models.len();
                model_index.insert(model_key.clone(), index);
                models.push(ModelOut {
                    fqcn: model.fqcn.clone(),
                    file: file.relative_path.clone(),
                    relationships: Vec::new(),
                    scopes: Vec::new(),
                    attributes: Vec::new(),
                    with_pivot: Vec::new(),
                });
                index
            };
            let entry = &mut models[index];

            entry
                .relationships
                .extend(
                    model
                        .relationships
                        .iter()
                        .map(|relationship| ModelRelationshipOut {
                            name: Some(relationship.name.clone()),
                            relation_type: Some(relationship.relation_type.clone()),
                            related: relationship.related.clone(),
                            with_pivot: if relationship.pivot_columns.is_empty()
                                || relationship.relation_type != "belongsToMany"
                            {
                                Vec::new()
                            } else {
                                vec![PivotOut {
                                    relation: Some(relationship.name.clone()),
                                    columns: relationship.pivot_columns.clone(),
                                }]
                            },
                        }),
                );
        }

        for item in &file.facts.polymorphic {
            polymorphic
                .entry(item.name.clone())
                .or_default()
                .push(PolymorphicRelationOut {
                    model: item.model.clone(),
                    relation_type: item.relation.clone(),
                });
        }

        for item in &file.facts.broadcast {
            if seen_broadcast.insert(item.channel.clone()) {
                broadcast.push(BroadcastOut {
                    channel: item.channel.clone(),
                    channel_type: item.channel_type.clone(),
                    parameters: if item.parameters.is_empty() {
                        extract_channel_parameters(&item.channel)
                    } else {
                        item.parameters
                            .iter()
                            .map(|parameter| BroadcastParameterOut {
                                name: parameter.name.clone(),
                                parameter_type: parameter.parameter_type.clone(),
                            })
                            .collect()
                    },
                });
            }
        }
    }

    for controller in &mut controllers {
        controller.methods.sort_by(|a, b| {
            let a_order = route_order
                .get(&(controller.fqcn.clone(), a.name.clone()))
                .copied()
                .unwrap_or(usize::MAX);
            let b_order = route_order
                .get(&(controller.fqcn.clone(), b.name.clone()))
                .copied()
                .unwrap_or(usize::MAX);
            a_order.cmp(&b_order).then_with(|| a.name.cmp(&b.name))
        });
    }

    for model in &mut models {
        dedup_relationships_preserving_order(&mut model.relationships);
        model.scopes.clear();
        model.attributes.clear();
        dedup_pivots_preserving_order(&mut model.with_pivot);
    }
    let mut polymorphic = polymorphic
        .into_iter()
        .map(|(name, mut relations)| {
            relations.dedup_by(|a, b| a.model == b.model && a.relation_type == b.relation_type);
            let discriminator = result
                .files
                .iter()
                .flat_map(|file| file.facts.polymorphic.iter())
                .find(|item| item.name == name)
                .map(|item| item.discriminator.clone());
            PolymorphicOut {
                name: Some(name),
                discriminator,
                relations,
            }
        })
        .collect::<Vec<_>>();
    polymorphic.sort_by(|a, b| (&a.name, &a.discriminator).cmp(&(&b.name, &b.discriminator)));

    if polymorphic.is_empty() {
        models = reorder_models_by_controller_roots(models, &controllers);
    } else {
        models = reorder_models_by_polymorphic_sources(models, &polymorphic);
    }

    Delta {
        meta: DeltaMeta {
            partial: result.partial,
            stats: StatsOut {
                files_parsed: result.files.len(),
                skipped: 0,
                duration_ms: result.duration_ms,
            },
            generated_at: None,
        },
        controllers,
        models,
        polymorphic,
        broadcast,
    }
}

fn collect_scope_owners(result: &PipelineResult) -> BTreeMap<String, Option<String>> {
    let mut owners = BTreeMap::<String, BTreeSet<String>>::new();

    for file in &result.files {
        for model in &file.facts.models {
            for scope in &model.scopes {
                owners
                    .entry(scope.clone())
                    .or_default()
                    .insert(model.fqcn.clone());
            }
        }
    }

    owners
        .into_iter()
        .map(|(scope, models)| {
            let owner = if models.len() == 1 {
                models.into_iter().next()
            } else {
                None
            };
            (scope, owner)
        })
        .collect()
}

fn build_request_usage(controller: &crate::model::ControllerMethod) -> Vec<RequestUsageOut> {
    let mut usage = controller
        .request_usage
        .iter()
        .map(|item| RequestUsageOut {
            method: item.method.clone(),
            class: item.class_name.clone(),
            rules: item.rules.clone(),
            fields: item.fields.clone(),
            location: item.location.clone(),
        })
        .collect::<Vec<_>>();

    usage.dedup_by(|a, b| {
        a.method == b.method
            && a.class == b.class
            && a.location == b.location
            && a.rules == b.rules
            && a.fields == b.fields
    });
    usage
}

fn collect_route_methods(result: &PipelineResult) -> BTreeMap<(String, String), Vec<String>> {
    let mut route_methods = BTreeMap::<(String, String), Vec<String>>::new();

    for binding in &result.route_bindings {
        let methods = route_methods
            .entry((binding.controller_fqcn.clone(), binding.method_name.clone()))
            .or_default();
        for method in &binding.http_methods {
            if !methods.contains(method) {
                methods.push(method.clone());
            }
        }
    }

    route_methods
}

fn collect_route_order(result: &PipelineResult) -> BTreeMap<(String, String), usize> {
    let mut route_order = BTreeMap::new();
    for (index, binding) in result.route_bindings.iter().enumerate() {
        route_order
            .entry((binding.controller_fqcn.clone(), binding.method_name.clone()))
            .or_insert(index);
    }
    route_order
}

fn extract_channel_parameters(channel: &str) -> Vec<BroadcastParameterOut> {
    let mut parameters = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = String::new();
    let mut inside = false;

    for ch in channel.chars() {
        match ch {
            '{' if !inside => {
                inside = true;
                current.clear();
            }
            '}' if inside => {
                inside = false;
                if !current.is_empty() && seen.insert(current.clone()) {
                    parameters.push(BroadcastParameterOut {
                        name: current.clone(),
                        parameter_type: None,
                    });
                }
                current.clear();
            }
            _ if inside => current.push(ch),
            _ => {}
        }
    }

    parameters
}

fn dedup_relationships_preserving_order(relationships: &mut Vec<ModelRelationshipOut>) {
    let mut deduped = Vec::with_capacity(relationships.len());
    for relationship in relationships.drain(..) {
        if deduped.iter().any(|existing: &ModelRelationshipOut| {
            existing.name == relationship.name
                && existing.relation_type == relationship.relation_type
                && existing.related == relationship.related
                && existing.with_pivot == relationship.with_pivot
        }) {
            continue;
        }
        deduped.push(relationship);
    }
    *relationships = deduped;
}

fn dedup_pivots_preserving_order(pivots: &mut Vec<PivotOut>) {
    let mut deduped = Vec::with_capacity(pivots.len());
    for pivot in pivots.drain(..) {
        if deduped.iter().any(|existing: &PivotOut| {
            existing.relation == pivot.relation && existing.columns == pivot.columns
        }) {
            continue;
        }
        deduped.push(pivot);
    }
    *pivots = deduped;
}

fn reorder_models_by_controller_roots(
    models: Vec<ModelOut>,
    controllers: &[ControllerOut],
) -> Vec<ModelOut> {
    if models.len() < 2 {
        return models;
    }

    let mut ordered = Vec::with_capacity(models.len());
    let mut remaining = models;
    let mut seeds = Vec::new();

    for controller in controllers {
        let Some(class_name) = controller.fqcn.rsplit('\\').next() else {
            continue;
        };
        let Some(base_name) = class_name.strip_suffix("Controller") else {
            continue;
        };
        if base_name.is_empty() {
            continue;
        }

        let candidate = format!("App\\Models\\{base_name}");
        if remaining.iter().any(|model| model.fqcn == candidate) && !seeds.contains(&candidate) {
            seeds.push(candidate);
        }
    }

    for seed in seeds {
        visit_model(&seed, &mut remaining, &mut ordered);
    }

    ordered.extend(remaining);
    ordered
}

fn visit_model(fqcn: &str, remaining: &mut Vec<ModelOut>, ordered: &mut Vec<ModelOut>) {
    let Some(index) = remaining.iter().position(|model| model.fqcn == fqcn) else {
        return;
    };

    let model = remaining.remove(index);
    let related = model
        .relationships
        .iter()
        .filter_map(|relationship| relationship.related.clone())
        .collect::<Vec<_>>();
    ordered.push(model);

    for related_model in related {
        visit_model(&related_model, remaining, ordered);
    }
}

fn reorder_models_by_polymorphic_sources(
    models: Vec<ModelOut>,
    polymorphic: &[PolymorphicOut],
) -> Vec<ModelOut> {
    if models.len() < 2 {
        return models;
    }

    let mut ordered = Vec::with_capacity(models.len());
    let mut remaining = models;
    let mut source_groups = remaining
        .iter()
        .filter_map(|model| {
            let names = model
                .relationships
                .iter()
                .filter(|relationship| relationship.relation_type.as_deref() == Some("morphTo"))
                .filter_map(|relationship| relationship.name.clone())
                .collect::<Vec<_>>();
            if names.is_empty() {
                None
            } else {
                Some((model.fqcn.clone(), model.relationships.len(), names))
            }
        })
        .collect::<Vec<_>>();
    source_groups.sort_by(|a, b| b.1.cmp(&a.1));

    for (fqcn, relationship_count, relation_names) in source_groups {
        visit_model_without_related(&fqcn, &mut remaining, &mut ordered);
        if relationship_count <= 1 {
            continue;
        }

        for relation_name in relation_names {
            let Some(group) = polymorphic
                .iter()
                .find(|group| group.name.as_deref() == Some(relation_name.as_str()))
            else {
                continue;
            };
            for relation in &group.relations {
                visit_model_without_related(&relation.model, &mut remaining, &mut ordered);
            }
        }
    }

    ordered.extend(remaining);
    ordered
}

fn visit_model_without_related(
    fqcn: &str,
    remaining: &mut Vec<ModelOut>,
    ordered: &mut Vec<ModelOut>,
) {
    let Some(index) = remaining.iter().position(|model| model.fqcn == fqcn) else {
        return;
    };
    ordered.push(remaining.remove(index));
}
