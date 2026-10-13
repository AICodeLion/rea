import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { runOwnedCommand } from "../../dist/process/OwnedCommand.js";
import { mcpTextValue } from "./mcp-verifier-results.mjs";

/** Real native decoding once, followed by portable/retained projections offline. */
export async function verifyNativeApiSurface({
  client,
  entrypoint,
  environment,
  directory,
}) {
  // Keep caller-relative entrypoints relative to the original verifier cwd.
  const cwd = process.cwd();
  const runCli = (args, env = environment, timeoutMs = 30_000) =>
    runOwnedCommand(
      {
        command: process.execPath,
        arguments: [entrypoint, ...args],
        cwd,
        runId: `rea-native-surface-${randomUUID()}`,
        hostEnvironment: env,
      },
      { timeoutMs, diagnosticBytes: 4 * 1024 * 1024 },
    );
  const capturePath = join(directory, "api-surface.mitm");
  const captureInput = { capture_path: capturePath, format: "mitmproxy" };
  const captured = await client.callTool({
    name: "inspect_web_network_capture",
    arguments: captureInput,
  });
  assert.notEqual(captured.isError, true, mcpTextValue(captured));
  const parent = parseEvidence(JSON.parse(mcpTextValue(captured)));
  const sensitive = await client.callTool({
    name: "inspect_web_network_capture",
    arguments: { ...captureInput, sensitive_values: ["QUERY_VALUE_ONLY"] },
  });
  assert.notEqual(sensitive.isError, true, mcpTextValue(sensitive));
  const sensitiveParent = parseEvidence(JSON.parse(mcpTextValue(sensitive)));
  const portable = await runCli(
    ["inspect-web-network-capture", capturePath, "mitmproxy", "--json"],
    environment,
    40_000,
  );
  const portableParent = parseEvidence(JSON.parse(portable.stdout.text));
  await unlink(capturePath);
  const view = { kind: "api-surface" };
  const inputPath = join(directory, "native-surface-view.json");
  await writeFile(
    inputPath,
    JSON.stringify({
      source: { kind: "inline", evidence: portableParent },
      view,
    }),
  );
  const cli = await runCli(["inspect-analysis-view", inputPath, "--json"], {
    ...environment,
    REA_MITMDUMP_COMMAND: join(directory, "unavailable-mitmdump"),
  });
  const projected = await client.callTool({
    name: "inspect_analysis_view",
    arguments: {
      source: { kind: "retained-evidence", evidence_id: parent.evidence_id },
      view,
    },
  });
  assert.notEqual(projected.isError, true, mcpTextValue(projected));
  for (const evidence of [
    parseEvidence(JSON.parse(cli.stdout.text)),
    parseEvidence(JSON.parse(mcpTextValue(projected))),
  ]) {
    const surface = evidence.normalized_result;
    assert.equal(surface.kind, "api-surface");
    assert.deepEqual(surface.records, { total: 7, examined: 7, excluded: 3 });
    assert.deepEqual(
      surface.groups.map((group) => group.path_template),
      ["/dup", "/health", "/items/{numeric}"],
    );
    assert.deepEqual(surface.groups[2].record_ordinals, [0, 1]);
    assert.deepEqual(surface.groups[2].statuses, [200, 404]);
    assert.deepEqual(surface.groups[2].content_types, [
      "application/json",
      "text/plain",
    ]);
    assert.deepEqual(surface.groups[0].content_types, []);
    assert.deepEqual(surface.groups[1].statuses, []);
    assert.deepEqual(surface.excluded_records, [
      { ordinal: 4, reason: "unsupported-request-target" },
      { ordinal: 5, reason: "url-redacted" },
      { ordinal: 6, reason: "non-http-flow" },
    ]);
    assert.equal(evidence.confidence, "inferred");
    assert.equal(evidence.evidence_links.length, 1);
    for (const canary of ["AUTH_ONLY", "BODY_ONLY", "QUERY_VALUE_ONLY"])
      assert.ok(!JSON.stringify(evidence).includes(canary));
  }
  const page = await client.callTool({
    name: "inspect_analysis_view",
    arguments: {
      source: { kind: "retained-evidence", evidence_id: parent.evidence_id },
      view: { ...view, offset: 2, limit: 1 },
    },
  });
  assert.notEqual(page.isError, true, mcpTextValue(page));
  const paged = parseEvidence(JSON.parse(mcpTextValue(page)));
  assert.equal(paged.normalized_result.groups.length, 1);
  assert.equal(paged.normalized_result.coverage.exhausted, true);
  const refused = await client.callTool({
    name: "inspect_analysis_view",
    arguments: {
      source: {
        kind: "retained-evidence",
        evidence_id: sensitiveParent.evidence_id,
      },
      view,
    },
  });
  assert.equal(refused.isError, true);
  assert.ok(mcpTextValue(refused).includes("sensitive_values_unretained"));
  assert.ok(!mcpTextValue(refused).includes("QUERY_VALUE_ONLY"));
  return 7;
}
