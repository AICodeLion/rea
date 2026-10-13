import { join } from "node:path";
import { writeFile } from "node:fs/promises";
import { expect } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { analysisViewCaptureEvidence } from "../../fixtures/analysisView.js";
import { nativeApiSurfaceCapture } from "../../fixtures/nativeApiSurface.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "projects portable native producer facts with compiled CLI and stdio MCP without a decoder or source file",
  async ({ cli }) => {
    const directory = await createTestTempDirectory("rea-native-api-surface-");
    const capture = nativeApiSurfaceCapture();
    capture.artifact.path = join(directory, "absent.mitm");
    const evidence = analysisViewCaptureEvidence(capture);
    const input = {
      source: { kind: "inline", evidence },
      view: { kind: "api-surface" },
    };
    const inputPath = join(directory, "view.json");
    await writeFile(inputPath, JSON.stringify(input));
    const result = await cli.run({
      arguments: ["inspect-analysis-view", inputPath, "--json"],
      environment: { REA_MITMDUMP_COMMAND: join(directory, "absent-mitmdump") },
    });
    expect(result.exitCode, result.stdout + result.stderr).toBe(0);
    const cliEvidence = parseEvidence(result.json);
    const { call } = await connectLocalToolsMcp({
      REA_MITMDUMP_COMMAND: join(directory, "absent-mitmdump"),
    });
    const reply = await call("inspect_analysis_view", input);
    expect(reply.isError).not.toBe(true);
    const mcpEvidence = parseEvidence(reply.structuredContent);
    expect(mcpEvidence.normalized_result).toEqual(
      cliEvidence.normalized_result,
    );
    expect(cliEvidence.normalized_result).toMatchObject({
      groups: [
        { path_template: "/dup" },
        { path_template: "/health" },
        { path_template: "/items/{numeric}", record_ordinals: [0, 1] },
      ],
      records: { total: 7, examined: 7, excluded: 3 },
    });
    for (const value of [cliEvidence, mcpEvidence]) {
      expect(value.evidence_links).toEqual([evidence.evidence_id]);
      expect(value.confidence).toBe("inferred");
      for (const canary of ["AUTH_ONLY", "BODY_ONLY", "QUERY_VALUE_ONLY"])
        expect(JSON.stringify(value)).not.toContain(canary);
    }
  },
);
