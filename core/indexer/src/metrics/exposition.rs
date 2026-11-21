use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Write};

pub(super) fn gauge(output: &mut String, name: &str, help: &str, value: impl Display) {
    writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    )
    .unwrap();
}

// Names and types are pinned to the managed runtime. Never include peer- or
// request-labelled families just because the dependency adds them to its registry.
fn kind(name: &str) -> Option<&'static str> {
    if let Some(name) = name.strip_prefix("malachitebft_core_consensus_") {
        return match name {
            "height"
            | "round"
            | "connected_peers"
            | "queue_heights"
            | "queue_size"
            | "node_safety_failure" => Some("gauge"),
            "consensus_time" | "time_per_block" | "time_per_step" | "consensus_round" => {
                Some("histogram")
            }
            "rebroadcast_timeouts"
            | "dropped_future_round_votes"
            | "dropped_future_round_proposals"
            | "dropped_capped_proposals"
            | "dropped_capped_proposed_values"
            | "dropped_buffered_messages" => Some("counter"),
            _ => None,
        };
    }
    match name.strip_prefix("malachitebft_sync_")? {
        "sync_queue_heights" | "sync_queue_size" => Some("gauge"),
        "value_requests_sent"
        | "value_requests_received"
        | "value_responses_sent"
        | "value_responses_received"
        | "value_request_timeouts"
        | "value_local_transient_errors" => Some("counter"),
        "value_client_latency" | "value_server_latency" => Some("histogram"),
        _ => None,
    }
}

/// Translate only the supported OpenMetrics subset into Prometheus 0.0.4 text.
/// Counter metadata names need the suffix too; dropping EOF alone is insufficient.
pub(crate) fn normalize(raw: &str) -> Result<String, &'static str> {
    if raw.len() > 1024 * 1024 || !raw.ends_with("# EOF\n") {
        return Err("size or EOF");
    }
    let mut output = String::new();
    let mut family: Option<(&str, &str, bool)> = None;
    let mut families = BTreeSet::new();
    let mut series = BTreeSet::new();
    for line in raw.lines() {
        if let Some(help) = line.strip_prefix("# HELP ") {
            if family.is_some_and(|(_, _, typed)| !typed) {
                return Err("missing type");
            }
            let (name, text) = help.split_once(' ').ok_or("bad help")?;
            family = kind(name).map(|kind| (name, kind, false));
            if let Some((_, kind, _)) = family {
                if !families.insert(name) {
                    return Err("duplicate family");
                }
                let suffix = if kind == "counter" { "_total" } else { "" };
                writeln!(output, "# HELP {name}{suffix} {text}").unwrap();
            }
        } else if let Some(metadata) = line.strip_prefix("# TYPE ") {
            if let Some((name, expected, typed)) = family.as_mut() {
                if *typed || metadata != format!("{name} {expected}") {
                    return Err("bad type");
                }
                *typed = true;
                let suffix = if *expected == "counter" { "_total" } else { "" };
                writeln!(output, "# TYPE {name}{suffix} {expected}").unwrap();
            }
        } else if line == "# EOF" {
            if family.is_some_and(|(_, _, typed)| !typed) {
                return Err("missing type");
            }
            family = None;
        } else if let Some((name, kind, typed)) = family {
            if !typed || line.starts_with('#') {
                return Err("unsupported metadata");
            }
            let (sample, labels, value) = sample(line)?;
            let valid_name = match kind {
                "counter" => sample.strip_suffix("_total") == Some(name),
                "histogram" => ["_sum", "_count", "_bucket"]
                    .iter()
                    .any(|s| sample.strip_suffix(s) == Some(name)),
                _ => sample == name,
            };
            if !valid_name || value.parse::<f64>().is_err() {
                return Err("bad sample");
            }
            if !series.insert((sample, labels)) {
                return Err("duplicate series");
            }
            writeln!(output, "{line}").unwrap();
        }
    }
    if !families.contains("malachitebft_core_consensus_height") {
        return Err("missing consensus metrics");
    }
    Ok(output)
}

fn sample(line: &str) -> Result<(&str, BTreeMap<&str, &str>, &str), &'static str> {
    let end = line.find(['{', ' ']).ok_or("missing value")?;
    let name = &line[..end];
    let mut rest = &line[end..];
    let mut labels = BTreeMap::new();
    if rest.starts_with('{') {
        rest = &rest[1..];
        while !rest.starts_with('}') {
            let (key, after_key) = rest.split_once("=\"").ok_or("bad label")?;
            if !["moniker", "step", "reason", "le"].contains(&key) {
                return Err("unbounded label");
            }
            let mut escaped = false;
            let mut quote = None;
            for (i, byte) in after_key.bytes().enumerate() {
                if escaped {
                    if !b"n\\\"".contains(&byte) {
                        return Err("bad escape");
                    }
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quote = Some(i);
                    break;
                }
            }
            let quote = quote.ok_or("unterminated label")?;
            let value = &after_key[..quote];
            if labels.insert(key, value).is_some() {
                return Err("duplicate label");
            }
            match key {
                "moniker" if value.len() > 1024 => return Err("moniker limit"),
                "reason" if !["buffer_full", "restart"].contains(&value) => {
                    return Err("unknown reason");
                }
                "step"
                    if !["Unstarted", "Propose", "Prevote", "Precommit", "Commit"]
                        .contains(&value) =>
                {
                    return Err("unknown step");
                }
                "le" if value.parse::<f64>().is_err() => return Err("bad bucket"),
                _ => {}
            }
            rest = &after_key[quote + 1..];
            if let Some(next) = rest.strip_prefix(',') {
                rest = next;
            } else if !rest.starts_with('}') {
                return Err("label separator");
            }
        }
        rest = &rest[1..];
    }
    let value = rest.strip_prefix(' ').ok_or("value separator")?;
    if value.contains(char::is_whitespace) {
        return Err("timestamps and exemplars unsupported");
    }
    Ok((name, labels, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEIGHT: &str = "# HELP malachitebft_core_consensus_height Current height.\n# TYPE malachitebft_core_consensus_height gauge\nmalachitebft_core_consensus_height{moniker=\"node\\\"\\n\\\\\"} 2\n";

    #[test]
    fn converts_counter_metadata_preserves_histograms_and_filters_peer_families() {
        let raw = format!(
            "{HEIGHT}# HELP libp2p_identify_remote_protocols Peer protocols.\n# TYPE libp2p_identify_remote_protocols gauge\nlibp2p_identify_remote_protocols{{peer=\"untrusted\"}} 50\n# HELP malachitebft_core_consensus_rebroadcast_timeouts Retry count.\n# TYPE malachitebft_core_consensus_rebroadcast_timeouts counter\nmalachitebft_core_consensus_rebroadcast_timeouts_total 3\n# HELP malachitebft_core_consensus_consensus_time Duration.\n# TYPE malachitebft_core_consensus_consensus_time histogram\nmalachitebft_core_consensus_consensus_time_sum 0.3\nmalachitebft_core_consensus_consensus_time_count 1\nmalachitebft_core_consensus_consensus_time_bucket{{le=\"+Inf\"}} 1\n# EOF\n"
        );
        let output = normalize(&raw).unwrap();
        assert!(output.starts_with(HEIGHT));
        assert!(!output.contains("libp2p"));
        assert!(!output.contains("# EOF"));
        assert!(
            output.contains(
                "# TYPE malachitebft_core_consensus_rebroadcast_timeouts_total counter\n"
            )
        );
        assert!(output.contains("consensus_time_bucket{le=\"+Inf\"} 1\n"));
    }

    #[test]
    fn rejects_duplicate_wrongly_typed_and_unbounded_samples() {
        for raw in [
            format!("{HEIGHT}{HEIGHT}# EOF\n"),
            format!(
                "{}# EOF\n",
                HEIGHT.replace("height gauge", "height counter")
            ),
            format!("{}# EOF\n", HEIGHT.replace("moniker=", "peer=")),
            format!("{}# EOF\n", HEIGHT.replace("} 2\n", "} bogus\n")),
            format!(
                "{}# EOF\n",
                HEIGHT.replace(
                    " gauge\n",
                    " gauge\n# TYPE malachitebft_core_consensus_height gauge\n"
                )
            ),
            HEIGHT.to_string(),
        ] {
            assert!(normalize(&raw).is_err(), "accepted {raw}");
        }
    }
}
