// Package runtime evaluates generated Gooo check operations.
// It does not define evaluator policy; policy data is imported from generated.
package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kimjooyoon/gooo-evaluator-integrity-projector/internal/generated"
)

type UnknownRecord struct {
	Stage         string `json:"stage"`
	Step          string `json:"step"`
	Reason        string `json:"reason"`
	UnknownClass  string `json:"unknown_class"`
	NextOperation string `json:"next_operation"`
	BlockedBy     string `json:"blocked_by"`
}

type CellVector struct {
	CellID            string         `json:"cell_id"`
	Topic             string         `json:"topic"`
	Layer             string         `json:"layer"`
	Lens              string         `json:"lens"`
	Decision          string         `json:"decision"`
	Resolution       string         `json:"resolution"`
	EvidenceAuthority string         `json:"evidence_authority"`
	EvidenceDigest    string         `json:"evidence_digest"`
	Unknown           *UnknownRecord `json:"unknown"`
}

type Evaluation struct {
	Case               string         `json:"case"`
	Kind               string         `json:"kind"`
	Decision           string         `json:"decision"`
	Improvement        string         `json:"improvement"`
	Vectors            []CellVector   `json:"vectors"`
	Unknown            *UnknownRecord `json:"unknown"`
	OperationalRefuted []string       `json:"operational_refuted"`
	ResolutionEvents   []string       `json:"resolution_events"`
}

type AuthorityCounters struct {
	MetacodeAuthority          int `json:"metacode_authority"`
	GeneratedEvaluatorAuthority int `json:"generated_evaluator_authority"`
	RuntimePolicyMutations     int `json:"runtime_policy_mutations"`
	ImmutablePolicyMutations   int `json:"immutable_policy_mutations"`
	BoundedAmendmentAuthority  int `json:"bounded_amendment_authority"`
	HumanDecisionReceipts      int `json:"human_decision_receipts"`
	CrossProjectRequiredGates  int `json:"cross_project_required_gates"`
	RepositoryWritesRuntime    int `json:"repository_writes_runtime"`
	LocalValidationCount       int `json:"local_validation_count"`
}

type Report struct {
	PolicyName             string              `json:"policy_name"`
	PolicyVersion          string              `json:"policy_version"`
	Denominator            int                 `json:"denominator"`
	LayerCounts            map[string]int      `json:"layer_counts"`
	LensCounts             map[string]int      `json:"lens_counts"`
	GeneratedArtifactCount int                 `json:"generated_artifact_count"`
	GeneratedArtifacts     []string            `json:"generated_artifacts"`
	AuthorityCounters      AuthorityCounters   `json:"authority_counters"`
	CaseCounts             map[string]int      `json:"case_counts"`
	Cases                  []Evaluation        `json:"cases"`
	Passed                 bool                `json:"passed"`
	Failures               []string            `json:"failures"`
}

type ReplayCase struct {
	Case         string `json:"case"`
	FirstDigest  string `json:"first_digest"`
	SecondDigest string `json:"second_digest"`
	Stable       bool   `json:"stable"`
}

type ReplayReport struct {
	PolicyName string       `json:"policy_name"`
	Cases      []ReplayCase `json:"cases"`
	Stable     bool         `json:"stable"`
}

type Provenance struct {
	PolicyName             string              `json:"policy_name"`
	PolicyVersion          string              `json:"policy_version"`
	GithubActions          bool                `json:"github_actions"`
	GithubTokenSource      string              `json:"github_token_source"`
	GithubRunID            string              `json:"github_run_id"`
	GithubSHA              string              `json:"github_sha"`
	GeneratedArtifactCount int                 `json:"generated_artifact_count"`
	GeneratedArtifacts     []string            `json:"generated_artifacts"`
	Inventory              []string            `json:"inventory"`
	InventoryStatus        string              `json:"inventory_status"`
	RootReadmeExcluded     bool                `json:"root_readme_excluded"`
	FileDigests            map[string]string   `json:"file_digests"`
	WallMilliseconds       *int64              `json:"wall_milliseconds"`
	RSSBytes               *uint64             `json:"rss_bytes"`
	MeasurementStatus      string              `json:"measurement_status"`
	RepositoryWritesRuntime int                `json:"repository_writes_runtime"`
	LocalValidationCount   int                 `json:"local_validation_count"`
	CrossProjectRequiredGates int              `json:"cross_project_required_gates"`
	AuthorityCounters      AuthorityCounters   `json:"authority_counters"`
	CaseCounts             map[string]int      `json:"case_counts"`
}

type checkResult struct {
	Decision string
	Reason   string
	Event    string
}

func Evaluate(policy generated.Policy, fixture generated.Fixture) Evaluation {
	result := Evaluation{
		Case: fixture.Name,
		Kind: fixture.Kind,
		Vectors: make([]CellVector, 0, len(policy.Cells)),
		OperationalRefuted: []string{},
		ResolutionEvents: []string{"precedence:" + strings.Join(policy.Precedence, ">"), "resolution:never-lower-silently"},
	}

	for _, cell := range policy.Cells {
		checked := evaluateCell(policy, cell, fixture.Facts)
		vector := CellVector{
			CellID: cell.ID,
			Topic: cell.Topic,
			Layer: cell.Layer,
			Lens: cell.Lens,
			Decision: checked.Decision,
			Resolution: checked.Decision,
			EvidenceAuthority: value(fixture.Facts, "evidence_authority"),
			EvidenceDigest: value(fixture.Facts, "evaluator_digest"),
		}
		if checked.Decision == "UNKNOWN" {
			vector.Unknown = unknownFromFacts(fixture.Facts, cell.ID, checked.Reason)
		}
		if checked.Event != "" {
			result.ResolutionEvents = append(result.ResolutionEvents, checked.Event)
		}
		result.Vectors = append(result.Vectors, vector)
	}

	result.Decision = deriveDecision(result.Vectors, fixture.Facts)
	if result.Decision == "UNKNOWN" || result.Decision == "REFUTED" {
		result.Unknown = firstUnknown(result.Vectors)
	}
	result.Improvement = deriveImprovement(policy, result.Decision, fixture.Facts, &result)

	declared := value(fixture.Facts, "declared_decision")
	if declared == "FIXED_POINT" && result.Decision != "FIXED_POINT" {
		switch result.Decision {
		case "UNKNOWN":
			result.OperationalRefuted = append(result.OperationalRefuted, "OPERATIONAL_REFUTED:UNKNOWN_TOP_LEVEL_DECISION_REJECTED")
		case "CLOSED":
			result.OperationalRefuted = append(result.OperationalRefuted, "OPERATIONAL_REFUTED:FIXED_POINT_WITHOUT_SAME_IDENTITY_PAIR")
		case "REFUTED":
			result.OperationalRefuted = append(result.OperationalRefuted, "OPERATIONAL_REFUTED:KNOWN_CONTRADICTION_OVERRIDES_FIXED_POINT")
		}
	}
	return result
}

func evaluateCell(policy generated.Policy, cell generated.CellSpec, facts map[string]string) checkResult {
	switch cell.Check {
	case "equal":
		if len(cell.Args) < 2 {
			return unknownResult("invalid_equal_operation")
		}
		left, right := value(facts, cell.Args[0]), value(facts, cell.Args[1])
		if missing(left) || missing(right) {
			return unknownResult("absent_identity_evidence")
		}
		if left != right {
			return refutedResult("known_identity_contradiction")
		}
		return closedResult()
	case "precedence":
		observed := value(facts, cell.Args[0])
		if missing(observed) {
			return unknownResult("absent_precedence_evidence")
		}
		if observed != strings.Join(policy.Precedence, ">") {
			return refutedResult("precedence_inversion")
		}
		return closedResult()
	case "unknown_record":
		state := value(facts, "unknown_record_state")
		present := unknownFieldsPresent(facts)
		if state == "present" && allUnknownFieldsPresent(facts) {
			return closedResult()
		}
		if state == "absent" && !present {
			return closedResult()
		}
		return unknownResult("incomplete_unknown_record")
	case "authority":
		if len(cell.Args) < 2 {
			return unknownResult("invalid_authority_operation")
		}
		authority, allowed := value(facts, cell.Args[0]), value(facts, cell.Args[1])
		if missing(authority) || missing(allowed) {
			return unknownResult("absent_evidence_authority")
		}
		switch strings.ToLower(authority) {
		case "stale", "ambiguous", "unbounded":
			return unknownResult(strings.ToLower(authority) + "_evidence_authority")
		}
		if authority != allowed {
			return unknownResult("ambiguous_evidence_authority")
		}
		return closedResult()
	case "digest_fresh":
		if len(cell.Args) < 4 {
			return unknownResult("invalid_digest_operation")
		}
		digest, fresh := value(facts, cell.Args[0]), value(facts, cell.Args[1])
		if missing(digest) {
			return unknownResult("missing_evaluator_digest")
		}
		if fresh != "true" {
			return unknownResult("stale_evaluator_digest")
		}
		identity, claim := value(facts, cell.Args[2]), value(facts, cell.Args[3])
		if missing(identity) || missing(claim) {
			return unknownResult("absent_evaluator_identity")
		}
		if identity != claim {
			return refutedResult("known_evaluator_identity_contradiction")
		}
		return closedResult()
	case "separate":
		if len(cell.Args) < 2 {
			return unknownResult("invalid_separation_operation")
		}
		subject, evaluator := value(facts, cell.Args[0]), value(facts, cell.Args[1])
		if missing(subject) || missing(evaluator) {
			return unknownResult("absent_subject_evaluator_digest")
		}
		if subject == evaluator {
			return refutedResult("subject_and_evaluator_share_identity")
		}
		return closedResult()
	case "bounded_amendment":
		if value(facts, "subject_changed") == "true" && value(facts, "evaluator_changed") == "true" && value(facts, "higher_level_authority") != "true" {
			return refutedResult("joint_subject_evaluator_change_without_higher_authority")
		}
		authority := strings.ToLower(value(facts, "amendment_authority"))
		if missing(authority) || authority == "stale" || authority == "ambiguous" || authority == "unbounded" {
			return unknownResult("unbounded_or_absent_amendment_authority")
		}
		return closedResult()
	case "human_receipt":
		if missing(value(facts, "human_decision_receipt")) || value(facts, "human_decision_receipt_valid") != "true" {
			return unknownResult("absent_or_invalid_human_decision_receipt")
		}
		return closedResult()
	default:
		return unknownResult("unknown_check_operation")
	}
}

func deriveDecision(vectors []CellVector, facts map[string]string) string {
	hasRefuted := false
	hasUnknown := false
	for _, vector := range vectors {
		switch vector.Decision {
		case "REFUTED":
			hasRefuted = true
		case "UNKNOWN":
			hasUnknown = true
		}
	}
	if hasRefuted {
		return "REFUTED"
	}
	if hasUnknown {
		return "UNKNOWN"
	}
	if sameIdentityPair(facts) {
		return "FIXED_POINT"
	}
	return "CLOSED"
}

func deriveImprovement(policy generated.Policy, decision string, facts map[string]string, result *Evaluation) string {
	if policy.ImprovementRule == "same_identity_pair" && sameIdentityPair(facts) && decision == "FIXED_POINT" {
		return "FIXED_POINT"
	}
	if policy.ImprovementRule == "same_identity_pair" && !sameIdentityPair(facts) {
		result.ResolutionEvents = append(result.ResolutionEvents, "improvement:UNKNOWN_without_same_identity_before_after_pair")
	}
	return "UNKNOWN"
}

func sameIdentityPair(facts map[string]string) bool {
	before, after := value(facts, "before_identity"), value(facts, "after_identity")
	return value(facts, "same_identity_pair") == "true" && !missing(before) && before == after
}

func unknownFromFacts(facts map[string]string, step, fallback string) *UnknownRecord {
	record := &UnknownRecord{
		Stage: value(facts, "unknown_stage"),
		Step: value(facts, "unknown_step"),
		Reason: value(facts, "unknown_reason"),
		UnknownClass: value(facts, "unknown_class"),
		NextOperation: value(facts, "unknown_next_operation"),
		BlockedBy: value(facts, "unknown_blocked_by"),
	}
	if missing(record.Stage) {
		record.Stage = "UNKNOWN"
	}
	if missing(record.Step) {
		record.Step = step
	}
	if missing(record.Reason) {
		record.Reason = fallback
	}
	if missing(record.UnknownClass) {
		record.UnknownClass = "ABSENT"
	}
	if missing(record.NextOperation) {
		record.NextOperation = "obtain_authoritative_evidence"
	}
	if missing(record.BlockedBy) {
		record.BlockedBy = "evidence_authority"
	}
	return record
}

func firstUnknown(vectors []CellVector) *UnknownRecord {
	for _, vector := range vectors {
		if vector.Unknown != nil {
			return vector.Unknown
		}
	}
	return nil
}

func unknownFieldsPresent(facts map[string]string) bool {
	for _, field := range []string{"unknown_stage", "unknown_step", "unknown_reason", "unknown_class", "unknown_next_operation", "unknown_blocked_by"} {
		if !missing(value(facts, field)) {
			return true
		}
	}
	return false
}

func allUnknownFieldsPresent(facts map[string]string) bool {
	for _, field := range []string{"unknown_stage", "unknown_step", "unknown_reason", "unknown_class", "unknown_next_operation", "unknown_blocked_by"} {
		if missing(value(facts, field)) {
			return false
		}
	}
	return true
}

func value(facts map[string]string, key string) string {
	return facts[key]
}

func missing(value string) bool {
	return value == "" || value == "-" || strings.EqualFold(value, "null")
}

func closedResult() checkResult {
	return checkResult{Decision: "CLOSED"}
}

func unknownResult(reason string) checkResult {
	return checkResult{Decision: "UNKNOWN", Reason: reason}
}

func refutedResult(reason string) checkResult {
	return checkResult{Decision: "REFUTED", Reason: reason, Event: "REFUTED:" + reason}
}

func BuildConformance() Report {
	policy := generated.PolicyDefinition
	result := Report{
		PolicyName: policy.Name,
		PolicyVersion: policy.Version,
		Denominator: policy.Denominator,
		LayerCounts: map[string]int{},
		LensCounts: map[string]int{},
		GeneratedArtifactCount: len(policy.GeneratedArtifacts),
		GeneratedArtifacts: append([]string(nil), policy.GeneratedArtifacts...),
		CaseCounts: map[string]int{},
		Cases: make([]Evaluation, 0, len(generated.Fixtures)),
		Passed: true,
		Failures: []string{},
		AuthorityCounters: AuthorityCounters{
			MetacodeAuthority: 1,
			GeneratedEvaluatorAuthority: 0,
			RuntimePolicyMutations: 0,
			ImmutablePolicyMutations: 0,
			BoundedAmendmentAuthority: 1,
			HumanDecisionReceipts: len(generated.Fixtures),
			CrossProjectRequiredGates: 0,
			RepositoryWritesRuntime: 0,
			LocalValidationCount: 0,
		},
	}
	for _, cell := range policy.Cells {
		result.LayerCounts[cell.Layer]++
		result.LensCounts[cell.Lens]++
	}
	if len(policy.Cells) != policy.Denominator || policy.Denominator != 12 {
		result.fail("denominator is not fixed at twelve")
	}
	for _, layer := range []string{"FOUNDATION", "COHERENCE", "REGRESSION"} {
		if result.LayerCounts[layer] != 4 {
			result.fail("layer " + layer + " does not contain four cells")
		}
	}
	for _, lens := range []string{"DRIVER", "OUTCOME", "GUARDRAIL"} {
		if result.LensCounts[lens] != 4 {
			result.fail("lens " + lens + " does not contain four cells")
		}
	}
	for _, fixture := range generated.Fixtures {
		evaluation := Evaluate(policy, fixture)
		result.Cases = append(result.Cases, evaluation)
		result.CaseCounts[evaluation.Decision]++
		if len(evaluation.Vectors) != policy.Denominator {
			result.fail(fixture.Name + ": vector count does not equal denominator")
		}
		if evaluation.Decision != fixture.ExpectedDecision {
			result.fail(fixture.Name + ": expected " + fixture.ExpectedDecision + ", got " + evaluation.Decision)
		}
		if evaluation.Improvement != fixture.ExpectedImprovement {
			result.fail(fixture.Name + ": expected improvement " + fixture.ExpectedImprovement + ", got " + evaluation.Improvement)
		}
		if evaluation.Decision == "UNKNOWN" && evaluation.Unknown == nil {
			result.fail(fixture.Name + ": UNKNOWN has no six-field record")
		}
	}
	return result
}

func (r *Report) fail(message string) {
	r.Passed = false
	r.Failures = append(r.Failures, message)
}

func BuildReplay() ReplayReport {
	policy := generated.PolicyDefinition
	replay := ReplayReport{PolicyName: policy.Name, Stable: true, Cases: make([]ReplayCase, 0, len(generated.Fixtures))}
	for _, fixture := range generated.Fixtures {
		first := Evaluate(policy, fixture)
		second := Evaluate(policy, fixture)
		firstDigest := digest(first.Vectors)
		secondDigest := digest(second.Vectors)
		stable := reflect.DeepEqual(first, second)
		replay.Cases = append(replay.Cases, ReplayCase{Case: fixture.Name, FirstDigest: firstDigest, SecondDigest: secondDigest, Stable: stable})
		if !stable {
			replay.Stable = false
		}
	}
	return replay
}

func digest(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func BuildProvenance() Provenance {
	started := time.Now()
	policy := generated.PolicyDefinition
	inventory, status := trackedInventory()
	digests := map[string]string{}
	for _, path := range inventory {
		if value, ok := fileDigest(path); ok {
			digests[path] = value
		}
	}
	result := BuildConformance()
	wall := time.Since(started).Milliseconds()
	rss := currentRSS()
	measurementStatus := "OBSERVED"
	if rss == nil {
		measurementStatus = "UNKNOWN"
	}
	return Provenance{
		PolicyName: policy.Name,
		PolicyVersion: policy.Version,
		GithubActions: os.Getenv("GITHUB_ACTIONS") == "true",
		GithubTokenSource: "github.token",
		GithubRunID: os.Getenv("GITHUB_RUN_ID"),
		GithubSHA: os.Getenv("GITHUB_SHA"),
		GeneratedArtifactCount: len(policy.GeneratedArtifacts),
		GeneratedArtifacts: append([]string(nil), policy.GeneratedArtifacts...),
		Inventory: inventory,
		InventoryStatus: status,
		RootReadmeExcluded: true,
		FileDigests: digests,
		WallMilliseconds: &wall,
		RSSBytes: rss,
		MeasurementStatus: measurementStatus,
		RepositoryWritesRuntime: 0,
		LocalValidationCount: 0,
		CrossProjectRequiredGates: 0,
		AuthorityCounters: result.AuthorityCounters,
		CaseCounts: result.CaseCounts,
	}
}

func trackedInventory() ([]string, string) {
	command := exec.Command("git", "ls-files")
	output, err := command.Output()
	if err != nil {
		return []string{}, "UNKNOWN"
	}
	paths := []string{}
	for _, path := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if path == "" || path == "README.md" {
			continue
		}
		paths = append(paths, filepath.ToSlash(path))
	}
	sort.Strings(paths)
	return paths, "OBSERVED"
}

func fileDigest(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

func currentRSS() *uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return nil
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return nil
	}
	bytes := pages * uint64(os.Getpagesize())
	return &bytes
}

func RuntimeMetadata() map[string]string {
	return map[string]string{
		"go_version": runtime.Version(),
		"goos": runtime.GOOS,
		"goarch": runtime.GOARCH,
		"local_validation_count": "0",
		"repository_writes_runtime": "0",
	}
}

func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r ReplayReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (p Provenance) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

func (r Report) String() string {
	if r.Passed {
		return "conformance passed"
	}
	return fmt.Sprintf("conformance failed: %s", strings.Join(r.Failures, "; "))
}
