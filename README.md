# gooo-evaluator-integrity-projector

An independent Gooo metaprogramming mechanism that prevents a self-improving
program from declaring success by changing its own evaluator, denominator,
decision precedence, or evidence authority inside the same claim.

## Authority boundary

[`gooo/evaluator-integrity.gooo`](gooo/evaluator-integrity.gooo) is the semantic
authority. It declares the fixed denominator, precedence, UNKNOWN schema,
check operations, and deterministic fixtures. `gooo-gen` compiles that
metacode into exactly two Go artifacts under `internal/generated/`. The Go
runtime interprets generated check operations; it does not expose a policy
mutation API and is not an authority source.

The evaluator emits one vector per cell. It never emits a score or percentage.
Known contradictions resolve to `REFUTED`; absent, stale, ambiguous, or
unbounded evidence resolves to `UNKNOWN`; only evidence-free closure can be
`CLOSED`. The fixed-point improvement claim stays `UNKNOWN` until a same-
identity before/after pair exists.

## Fixed 12-cell denominator

| Cell | Integrity concern | Layer | Lens |
| --- | --- | --- | --- |
| C01 | Subject identity | FOUNDATION | DRIVER |
| C02 | Goal identity | FOUNDATION | OUTCOME |
| C03 | Denominator identity | FOUNDATION | GUARDRAIL |
| C04 | `REFUTED > UNKNOWN > CLOSED` precedence | FOUNDATION | OUTCOME |
| C05 | Six-field UNKNOWN record | COHERENCE | GUARDRAIL |
| C06 | Evidence authority | COHERENCE | DRIVER |
| C07 | Go/toolchain identity | COHERENCE | OUTCOME |
| C08 | Generator identity | COHERENCE | DRIVER |
| C09 | Evaluator identity and fresh digest | REGRESSION | OUTCOME |
| C10 | Subject/evaluator separation | REGRESSION | GUARDRAIL |
| C11 | Bounded amendment authority | REGRESSION | DRIVER |
| C12 | Human decision receipt | REGRESSION | GUARDRAIL |

The metacode enforces four cells in each layer and four in each lens. The
UNKNOWN record fields are exactly `stage`, `step`, `reason`, `unknown_class`,
`next_operation`, and `blocked_by`.

## Canonical fixtures

The metacode contains normal, UNKNOWN, and REFUTED fixtures plus counterexamples
for an UNKNOWN top-level decision attempting to become `FIXED_POINT`, denominator
shrink, joint subject/evaluator change without higher-level authority, precedence
inversion, missing evaluator digest, stale evaluator digest, ambiguous evidence,
unbounded evidence, and improvement without a same-identity pair.

`REFUTED` always wins over `UNKNOWN`, which wins over `CLOSED`. A rejected
top-level `FIXED_POINT` request is recorded as an `OPERATIONAL_REFUTED` event
without promoting the result.

## CI-only validation

GitHub Actions is the validation authority and runs Go 1.27.x through
`go generate`, `go fix`, `go fmt`, `go build`, `go vet`, `go test`, conformance,
replay, and provenance. Local validation count is intentionally `0`; no local
generator, formatter, build, vet, test, conformance, or replay was run while
creating this repository.

Provenance records the exact tracked-file inventory with the root `README.md`
excluded, generated artifact count, observed wall time, observed RSS when the
runner exposes it, file digests, authority counters, runtime repository writes
(`0`), and cross-project required gates (`0`). Missing measurements are
represented as `null` with `UNKNOWN` status, never as zero.

## CI commands

```text
go run ./cmd/gooo conformance
go run ./cmd/gooo replay
go run ./cmd/gooo provenance
```

The runtime is read-only with respect to the repository. Policy amendments are
not performed at runtime; any future bounded amendment must be represented by
new `.gooo` authority and a new reviewed history entry.
