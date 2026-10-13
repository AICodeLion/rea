import { expect, it } from "vitest";
import { nativeApiSurfaceCapture } from "../../../tests/fixtures/nativeApiSurface.js";
import { analysisViewCaptureEvidence } from "../../../tests/fixtures/analysisView.js";
import { projectAnalysisView } from "./analysisView.js";
import { WebNetworkApiSurfaceAccumulator } from "./WebNetworkApiSurfaceAccumulator.js";

const project = (
  capture = nativeApiSurfaceCapture(),
  offset = 0,
  limit = 50,
  sensitiveValueCount = 0,
) => {
  const parent = analysisViewCaptureEvidence(capture);
  const result = projectAnalysisView(
    {
      evidenceId: parent.evidence_id,
      operation: parent.operation,
      normalizedResult: capture,
      limitations: capture.limitations,
      parameters: { sensitive_value_count: sensitiveValueCount },
    },
    { kind: "api-surface", offset, limit },
  );
  if (!result.ok) throw result.error;
  if (result.value.kind !== "api-surface")
    throw new Error("Expected API surface");
  return result.value;
};

it("groups original native HTTP text, keeps response uncertainty and excludes other targets", () => {
  const surface = project();
  expect(surface.groups).toMatchObject([
    {
      path_template: "/dup",
      record_ordinals: [3],
      statuses: [200],
      content_types: [],
    },
    {
      path_template: "/health",
      record_ordinals: [2],
      statuses: [],
      content_types: [],
    },
    {
      path_template: "/items/{numeric}",
      origin: "https://example.test",
      record_ordinals: [0, 1],
      statuses: [200, 404],
      content_types: ["application/json", "text/plain"],
      flags: ["mixed-statuses", "mixed-content-types"],
    },
  ]);
  expect(surface.excluded_records).toEqual([
    { ordinal: 4, reason: "unsupported-request-target" },
    { ordinal: 5, reason: "url-redacted" },
    { ordinal: 6, reason: "non-http-flow" },
  ]);
  expect(surface.records).toEqual({ examined: 7, total: 7, excluded: 3 });
  expect(surface.unknowns.length).toBeGreaterThan(0);
  for (const canary of ["AUTH_ONLY", "BODY_ONLY", "QUERY_VALUE_ONLY"])
    expect(JSON.stringify(surface)).not.toContain(canary);
  expect(project(undefined, 2, 1)).toMatchObject({
    groups: [surface.groups[2]],
    coverage: { total: 3, examined: 1, exhausted: true },
  });
  expect(() => project(undefined, 0, 50, 1)).toThrow(
    "sensitive_values_unretained",
  );
});

it("keeps unreadable or contradictory text and response bytes unknown", () => {
  const capture = nativeApiSurfaceCapture();
  capture.records = capture.records.slice(0, 4);
  const first = capture.records[0]!;
  first.binary_fields.find(
    (field) => field.pointer === "/request/path",
  )!.sha256 = "0".repeat(64);
  const second = capture.records[1]!;
  second.binary_fields.push(
    second.binary_fields.find((field) => field.pointer === "/request/method")!,
  );
  const fourth = capture.records[3]!;
  fourth.numeric_literals.find(
    (number) => number.pointer === "/response/status_code",
  )!.literal = "201";
  const surface = project(capture);
  expect(surface.excluded_records).toEqual([
    { ordinal: 0, reason: "url-unparseable" },
    { ordinal: 1, reason: "method-unavailable" },
  ]);
  expect(surface.groups).toMatchObject([
    { path_template: "/dup", statuses: [], content_types: [] },
    { path_template: "/health", statuses: [] },
  ]);
});

it("preserves original encoded and dot segments and admits only explicit aligned origins", () => {
  const capture = nativeApiSurfaceCapture();
  const prototype = capture.records[0]!;
  const requests = [
    { host: "::1", port: 8443, path: "/a/%2e%2e/1?value=ordinary" },
    { host: "example.test", port: 443, path: "https://other.test/path" },
    { host: "example.test", port: 443, path: "relative/path" },
    { host: null, port: 443, path: "/path" },
    { host: "example.test", port: 443, path: "/path", method: "CONNECT" },
  ];
  capture.records = requests.map((request, ordinal) => ({
    ...prototype,
    ordinal,
    binary_fields: [],
    numeric_literals: [],
    redactions: [],
    reported: {
      type: "http",
      request: { method: "GET", scheme: "https", ...request },
      response: null,
    },
  }));
  const surface = project(capture);
  expect(surface.groups).toMatchObject([
    {
      origin: "https://[::1]:8443",
      path_template: "/a/%2e%2e/{numeric}",
      record_ordinals: [0],
    },
  ]);
  expect(surface.excluded_records).toEqual([
    { ordinal: 1, reason: "unsupported-request-target" },
    { ordinal: 2, reason: "unsupported-request-target" },
    { ordinal: 3, reason: "url-unparseable" },
    { ordinal: 4, reason: "unsupported-request-target" },
  ]);
});

it("admits native text and coordinate indexes before allocation and clears failed scratch", () => {
  const accumulator = new WebNetworkApiSurfaceAccumulator(20_000);
  const record = nativeApiSurfaceCapture().records[0]!;
  record.binary_fields = [];
  record.numeric_literals = [];
  record.reported = {
    type: "http",
    request: {
      method: "GET",
      scheme: "https",
      host: "example.test",
      port: 443,
      path: "/" + "x".repeat(20_000),
    },
  };
  expect(accumulator.add(record, "mitmproxy")).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError" },
  });
  expect(accumulator.page(0, 50).groups).toEqual([]);
  const next = accumulator.add(
    {
      ...record,
      reported: {
        type: "http",
        request: {
          method: "GET",
          scheme: "https",
          host: "example.test",
          port: 443,
          path: "/ok",
        },
      },
    },
    "mitmproxy",
  );
  if (!next.ok) throw next.error;
  expect(accumulator.page(0, 50).groups).toMatchObject([
    { path_template: "/ok" },
  ]);
});

it("preserves status when response header identity is unreadable and rejects inconsistent ports", () => {
  const capture = nativeApiSurfaceCapture();
  capture.records = capture.records.slice(0, 2);
  const first = capture.records[0]!;
  first.binary_fields = first.binary_fields.filter(
    (field) => !field.pointer.startsWith("/response/headers/"),
  );
  first.reported = {
    type: "http",
    request: {
      method: "GET",
      scheme: "https",
      host: "example.test",
      port: 443,
      path: "/items/1?token=QUERY_VALUE_ONLY",
    },
    response: {
      status_code: 200,
      headers: [
        ["Content-Type", "application/json"],
        [null, "unknown-name"],
      ],
    },
  };
  capture.records[1]!.numeric_literals.find(
    (number) => number.pointer === "/request/port",
  )!.literal = "8443";
  const surface = project(capture);
  expect(surface.groups).toMatchObject([
    { path_template: "/items/{numeric}", statuses: [200], content_types: [] },
  ]);
  expect(surface.excluded_records).toEqual([
    { ordinal: 1, reason: "url-unparseable" },
  ]);
});
