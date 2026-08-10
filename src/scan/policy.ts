import { severityRank } from "./severity.js";
import {
	candidateComputed,
	candidateDuplicateOf,
	candidateStatus,
	type Candidate,
	type Coverage,
	type PassCoverage,
	type Severity,
} from "../types.js";

/** CI exit status: 0 passes, 1 violates policy, 2 cannot safely pass. */
export function policyExitCode(
	input: { candidates: Candidate[]; coverage: Coverage; passCoverage?: PassCoverage[] },
	failSeverity?: Severity,
): 0 | 1 | 2 {
	if (!failSeverity) return 0;
	if (
		input.passCoverage?.some((pass) => !pass.completed) ||
		input.coverage.files_touched !== input.coverage.files_in_scope ||
		input.coverage.bytes_read < input.coverage.bytes_in_scope
	) {
		return 2;
	}
	const violates = input.candidates.some((candidate) => {
		const computed = candidateComputed(candidate);
		return (
			candidateStatus(candidate) === "confirmed" &&
			!candidateDuplicateOf(candidate) &&
			computed?.reportable !== false &&
			computed !== undefined &&
			severityRank(computed.severity) <= severityRank(failSeverity)
		);
	});
	return violates ? 1 : 0;
}
