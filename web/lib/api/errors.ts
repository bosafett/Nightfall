/** Parses the API's error bodies: {detail: {code, message}} or FastAPI validation errors. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

type ValidationItem = { loc?: (string | number)[]; msg?: string };

export function parseError(status: number, body: unknown): ApiError {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const d = detail as { code?: string; message?: string };
    return new ApiError(status, d.code ?? "error", d.message ?? "Something went wrong.");
  }
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as ValidationItem;
    const field = first.loc?.filter((p) => p !== "body").join(".") ?? "";
    const msg = (first.msg ?? "Invalid value").replace(/^Value error, /, "");
    return new ApiError(status, "validation_error", field ? `${field}: ${msg}` : msg);
  }
  if (status === 429) return new ApiError(status, "rate_limited", "Too many requests. Try again shortly.");
  return new ApiError(status, "error", "Something went wrong. Try again.");
}
