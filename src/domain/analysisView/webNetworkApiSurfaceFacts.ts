import { createHash } from "node:crypto";
import { z } from "zod";
import type { AnalysisError } from "../analysisErrorBase.js";
import {
  parseRecordedTransportUrl,
  type RecordedTransportUrl,
} from "../recordedTransportUrl.js";
import { ok, type Result } from "../result.js";
import type { WebNetworkCaptureRecord } from "../webNetworkCapture.js";

export const apiSurfaceExclusionSchema = z.enum([
  "url-redacted",
  "url-unparseable",
  "request-unavailable",
  "method-unavailable",
  "non-http-flow",
  "flow-type-unavailable",
  "unsupported-request-target",
]);
type ApiSurfaceExclusion = z.infer<typeof apiSurfaceExclusionSchema>;
type Facts =
  | {
      readonly kind: "request";
      readonly method: unknown;
      readonly url: unknown;
      readonly transport: RecordedTransportUrl | null;
      readonly status: unknown;
      readonly mime: unknown;
    }
  | { readonly kind: "excluded"; readonly reason: ApiSurfaceExclusion };
type Admit = (length: number) => Result<void, AnalysisError>;
type Binary = WebNetworkCaptureRecord["binary_fields"][number];
type ByteIndex = ReadonlyMap<string, Binary | null>;
const harRequestSchema = z.object({
  request: z.object({ url: z.unknown(), method: z.unknown() }),
});
const harResponseSchema = z.object({
  response: z.object({
    status: z.unknown().optional(),
    content: z.unknown().optional(),
  }),
});
const harContentSchema = z.object({ mimeType: z.unknown().optional() });
const nativeSchema = z.object({
  type: z.unknown().optional(),
  request: z.unknown().optional(),
  response: z.unknown().optional(),
});
const nativeRequestSchema = z.object({
  method: z.unknown().optional(),
  scheme: z.unknown().optional(),
  host: z.unknown().optional(),
  port: z.unknown().optional(),
  path: z.unknown().optional(),
});
const nativeResponseSchema = z.object({
  status_code: z.unknown().optional(),
  headers: z.unknown().optional(),
});
const excluded = (reason: ApiSurfaceExclusion): Result<Facts, AnalysisError> =>
  ok({ kind: "excluded", reason });

/** Borrow producer text; exact retained byte sidecars must agree before use. */
function nativeText(
  index: ByteIndex,
  pointer: string,
  value: unknown,
  admit: Admit,
): Result<string | null, AnalysisError> {
  if (typeof value !== "string") return ok(null);
  // Covers UTF-8 encoding, base64 comparison and subsequent normalization,
  // including producer strings that make no original-byte claim.
  const admitted = admit(value.length);
  if (!admitted.ok) return admitted;
  if (!index.has(pointer)) return ok(value);
  const field = index.get(pointer);
  if (
    field == null ||
    field.state !== "retained" ||
    field.representation !== "producer-bytes"
  )
    return ok(null);
  const bytes = Buffer.from(value, "utf8");
  return ok(
    bytes.length === field.bytes &&
      bytes.toString("base64") === field.content_base64 &&
      createHash("sha256").update(bytes).digest("hex") === field.sha256
      ? value
      : null,
  );
}

function nativeMime(
  headers: unknown,
  index: ByteIndex,
  admit: Admit,
): Result<string | undefined, AnalysisError> {
  if (!Array.isArray(headers)) return ok(undefined);
  let mime: string | undefined;
  let candidates = 0;
  let unknownName = false;
  for (let ordinal = 0; ordinal < headers.length; ordinal++) {
    const pair: unknown = headers[ordinal];
    if (!Array.isArray(pair) || pair.length !== 2) {
      unknownName = true;
      continue;
    }
    const name = nativeText(
      index,
      `/response/headers/${ordinal}/0`,
      pair[0],
      admit,
    );
    if (!name.ok) return name;
    if (name.value === null) {
      unknownName = true;
      continue;
    }
    if (name.value.toLowerCase() !== "content-type") continue;
    candidates++;
    const value = nativeText(
      index,
      `/response/headers/${ordinal}/1`,
      pair[1],
      admit,
    );
    if (!value.ok) return value;
    mime = value.value ?? undefined;
  }
  // Do not choose a duplicate header or overlook an unreadable possible name.
  return ok(candidates === 1 && !unknownName ? mime : undefined);
}

function nativeInteger(
  record: WebNetworkCaptureRecord,
  pointer: string,
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  )
    return null;
  let count = 0;
  for (const number of record.numeric_literals) {
    if (number.pointer !== pointer) continue;
    count++;
    if (
      count > 1 ||
      number.producer_type !== "integer" ||
      number.literal !== String(value)
    )
      return null;
  }
  return value;
}

/** Own format interpretation; downstream grouping receives one request representation. */
export function apiSurfaceRecordFacts(
  record: WebNetworkCaptureRecord,
  format: "har" | "mitmproxy",
  admit: Admit,
): Result<Facts, AnalysisError> {
  if (format === "har") {
    const request = harRequestSchema.safeParse(record.reported);
    if (!request.success) return excluded("request-unavailable");
    // Parse response facets independently, preserving the existing HAR behavior.
    const response = harResponseSchema.safeParse(record.reported);
    const content = harContentSchema.safeParse(
      response.success ? response.data.response.content : undefined,
    );
    const url = request.data.request.url;
    if (typeof url === "string") {
      const admitted = admit(url.length);
      if (!admitted.ok) return admitted;
    }
    return ok({
      kind: "request",
      ...request.data.request,
      transport:
        typeof url === "string" ? parseRecordedTransportUrl(url) : null,
      status: response.success ? response.data.response.status : undefined,
      mime: content.success ? content.data.mimeType : undefined,
    });
  }
  const parsed = nativeSchema.safeParse(record.reported);
  if (!parsed.success) return excluded("request-unavailable");
  if (typeof parsed.data.type !== "string")
    return excluded("flow-type-unavailable");
  // Index the producer's coordinates once rather than rescan sidecars for every
  // header. Duplicate coordinates remain ambiguous, including identical ones.
  const reserved = admit(record.binary_fields.length * 32);
  if (!reserved.ok) return reserved;
  const index = new Map<string, Binary | null>();
  for (const field of record.binary_fields)
    index.set(field.pointer, index.has(field.pointer) ? null : field);
  const flowType = nativeText(index, "/type", parsed.data.type, admit);
  if (!flowType.ok) return flowType;
  if (flowType.value === null) return excluded("flow-type-unavailable");
  if (flowType.value !== "http") return excluded("non-http-flow");
  const parsedRequest = nativeRequestSchema.safeParse(parsed.data.request);
  if (!parsedRequest.success) return excluded("request-unavailable");
  const request = parsedRequest.data;
  const texts: (string | null)[] = [];
  for (const name of ["method", "scheme", "host", "path"] as const) {
    const text = nativeText(index, `/request/${name}`, request[name], admit);
    if (!text.ok) return text;
    texts.push(text.value);
  }
  const [method, scheme, host, path] = texts;
  const port = nativeInteger(record, "/request/port", request.port, 1, 65535);
  if (!method || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(method))
    return excluded("method-unavailable");
  if (
    !scheme ||
    !/^https?$/iu.test(scheme) ||
    !host ||
    /[\s/?#@\\%]/u.test(host) ||
    port === null
  )
    return excluded("url-unparseable");
  if (path == null)
    return excluded(
      record.redactions.some(
        (redaction) => redaction.pointer === "/request/path",
      )
        ? "url-redacted"
        : "url-unparseable",
    );
  if (
    method === "CONNECT" ||
    /[\x00-\x20\x7f]/u.test(path) ||
    !(path.startsWith("/") || /^https?:\/\//iu.test(path))
  )
    return excluded("unsupported-request-target");
  const admitted = admit(scheme.length + host.length + path.length + 16);
  if (!admitted.ok) return admitted;
  const authority =
    host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const base = `${scheme}://${authority}:${port}`;
  const baseFacts = parseRecordedTransportUrl(base);
  const url = path.startsWith("/") ? base + path : path;
  const urlFacts = parseRecordedTransportUrl(url);
  if (
    baseFacts.origin === null ||
    urlFacts.origin !== baseFacts.origin ||
    urlFacts.credentials !== null ||
    urlFacts.path === null
  )
    return excluded("unsupported-request-target");
  const response = nativeResponseSchema.safeParse(parsed.data.response);
  const mime = nativeMime(
    response.success ? response.data.headers : undefined,
    index,
    admit,
  );
  if (!mime.ok) return mime;
  const status = response.success ? response.data.status_code : undefined;
  return ok({
    kind: "request",
    method,
    url,
    transport: urlFacts,
    status: nativeInteger(record, "/response/status_code", status, 100, 599),
    mime: mime.value,
  });
}
