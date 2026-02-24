# HOLMES-style APT Detection MVP

## Run tests

```bash
pytest -q
```

## Run pipeline

`--out` is an output directory, not a file path.
The pipeline creates these files inside the directory:
- `result.json`
- `summary.json`
- `matches.json`
- `hsg.json`

```bash
python -m engine.cli.run_pipeline \
  --events experiments/sample.jsonl \
  --rules rules/empty.yaml \
  --out out
```

## Paper mode recommended command

```bash
python -m engine.cli.run_pipeline \
  --events <events.jsonl> \
  --rules <rules.yaml> \
  --out out \
  --paper-mode strict \
  --path-factor-op le \
  --min-path-factor 3 \
  --prereq-policy dst_only \
  --scoring paper \
  --paper-weights 1.1,1.2,1.3,1.4,1.5,1.6,1.7 \
  --noise-model noise_model.json \
  --noise-bytes-threshold p95
```

## Rule schema

`event_predicate` supports exactly one of:

```yaml
event_predicate:
  op: "exec"
```

```yaml
event_predicate:
  event_type: "proc_to_file"
```

## Dependency strength

`dependency_strength(from_entity, to_entity)` is directed and uses shortest path attenuation.
If no directed path exists, strength is `0.0`.
Let `L = shortest_path_len(from_entity, to_entity)` in edge count; then strength is `1.0 / (1.0 + L)`.
If `from_entity == to_entity`, `L = 0` and strength is `1.0`.  # (코드에 맞게 조정)
Examples: 1-hop -> `0.5`, 2-hop -> `1/3`, 3-hop -> `0.25`.
In the HSG output (`out/hsg.json`), `graph_path` edges store this value in the `weight` field.

## Scenario scoring (MVP)

Scenario score = sum(rule severities in the scenario) + alpha * sum(edge weights in the scenario).
Edges without a `weight` field contribute 0.

## Path factor (MAC MVP)

Default `path_factor(from_entity, to_entity)` follows paper-style incremental propagation.
If no directed path exists, path_factor is `0.0`, and `path_factor(src, src) = 1.0`.
Process-node transitions without common ancestor with `src` increase path_factor by 1; non-process transitions keep it.
When multiple paths exist, the minimum propagated value is used.
Legacy MAC approximation remains available as `path_factor_legacy_mac(...)`.
For threshold filtering, `--path-factor-op ge` means keep edges with `path_factor >= threshold` (legacy behavior).
`--path-factor-op le` means keep edges with `path_factor <= threshold` (paper-style max allowed path_factor).
In paper mode, `--min-path-factor` is interpreted as `path_thres` (the option name is kept for compatibility).
Default `path_thres=3` is applied only by the mode resolver when scoring mode is `paper` and the option is omitted.
`--path-factor-op` default is also resolved by mode: `paper -> le`, `legacy -> ge`.

## Summary fields

`summary.json` includes:
- `resolved_effective_config`: resolved runtime config values after mode resolver (`path_thres`, `path_factor_op`, `scoring`, `paper_mode`, `paper_weights`)
- `paper_scoring`: paper scoring visibility fields (`threat_tuple`, `stage_severity`, `paper_weights`, `score_paper`)
