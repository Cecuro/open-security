import { describe, expect, it } from "vitest";

import {
	OPAQUE_RESPONSE_FAILED,
	retryableOpaqueAzureError,
} from "../src/agents/azure-retry.js";

const opaqueFailure = {
	api: "azure-openai-responses",
	provider: "azure-openai-responses",
	stopReason: "error",
	rawStopReason: "failed",
	errorMessage: OPAQUE_RESPONSE_FAILED,
};

describe("opaque Azure response failures", () => {
	it("rewrites the exact opaque failure for PI's retry classifier", () => {
		const errorMessage = retryableOpaqueAzureError(opaqueFailure);
		expect(errorMessage).toBe(
			`Provider returned error: Azure response.failed without error details (original: ${OPAQUE_RESPONSE_FAILED})`,
		);
	});

	it("does not rewrite other providers or Azure errors with useful details", () => {
		expect(retryableOpaqueAzureError({ ...opaqueFailure, provider: "openai" })).toBeUndefined();
		expect(
			retryableOpaqueAzureError({ ...opaqueFailure, errorMessage: "insufficient_quota" }),
		).toBeUndefined();
	});
});
