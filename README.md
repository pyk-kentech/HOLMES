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
