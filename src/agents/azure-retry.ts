const AZURE_PROVIDER = "azure-openai-responses";
export const OPAQUE_RESPONSE_FAILED = "Unknown error (no error details in response)";

/**
 * PI retries errors classified from their message text. Azure can send a
 * response.failed event without an error body, which PI 0.84 does not classify
 * as transient. Return a retryable message only for that exact response.
 */
export function retryableOpaqueAzureError(message: {
	api: string;
	provider: string;
	stopReason: string;
	rawStopReason?: string;
	errorMessage?: string;
}): string | undefined {
	if (
		message.api !== AZURE_PROVIDER ||
		message.provider !== AZURE_PROVIDER ||
		message.stopReason !== "error" ||
		message.rawStopReason !== "failed" ||
		message.errorMessage !== OPAQUE_RESPONSE_FAILED
	) {
		return undefined;
	}

	return `Provider returned error: Azure response.failed without error details (original: ${OPAQUE_RESPONSE_FAILED})`;
}
