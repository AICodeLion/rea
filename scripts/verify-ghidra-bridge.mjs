#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const install = process.env.GHIDRA_INSTALL_DIR;
if (!install)
  throw new Error(
    "Bridge compilation requires existing GHIDRA_INSTALL_DIR and JDK 21 or newer. REA does not install either tool.",
  );
const manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const sources = manifest.files
  .filter((path) => path.startsWith("bridge/ghidra/") && path.endsWith(".java"))
  .sort()
  .map((path) => join(root, path));
if (sources.length === 0)
  throw new Error("No packaged Ghidra Java sources were found.");
async function jars(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...(await jars(path)));
    else if (entry.isFile() && path.endsWith(".jar")) found.push(path);
  }
  return found.sort();
}
const classpath = await jars(resolve(install, "Ghidra"));
if (classpath.length === 0)
  throw new Error("The selected Ghidra installation contains no API jars.");
const javac = process.env.JAVA_HOME
  ? join(
      process.env.JAVA_HOME,
      "bin",
      process.platform === "win32" ? "javac.exe" : "javac",
    )
  : "javac";
const temporary = await mkdtemp(join(tmpdir(), "rea-ghidra-bridge-"));
try {
  const classes = join(temporary, "classes");
  await mkdir(classes);
  const argumentsFile = join(temporary, "javac.args");
  // An argument file avoids Windows command-line limits. javac owns this
  // quoting syntax; shell expansion is never involved.
  const argumentsList = [
    "--release",
    "21",
    "-encoding",
    "UTF-8",
    "-proc:none",
    "-cp",
    classpath.join(delimiter),
    "-d",
    classes,
    ...sources,
  ];
  await writeFile(
    argumentsFile,
    argumentsList
      .map(
        (argument) =>
          `"${argument.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`,
      )
      .join("\n"),
  );
  const started = performance.now();
  const compiled = spawnSync(
    javac,
    [
      "-J-Xmx512m",
      "-J-XX:ActiveProcessorCount=1",
      // JDK 21's supported stream properties keep redirected diagnostics
      // aligned with Node's UTF-8 decoder, including Windows code-page hosts.
      "-J-Dstdout.encoding=UTF-8",
      "-J-Dstderr.encoding=UTF-8",
      "-J-Duser.language=en",
      "-J-Duser.country=US",
      `@${argumentsFile}`,
    ],
    {
      cwd: root,
      encoding: "utf8",
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  if (compiled.stdout) process.stdout.write(compiled.stdout);
  if (compiled.stderr) process.stderr.write(compiled.stderr);
  if (compiled.error || compiled.status !== 0)
    throw new Error(
      `Ghidra bridge compilation failed: ${compiled.error?.message ?? `javac exit ${compiled.status}, signal ${compiled.signal ?? "none"}`}`,
    );
  console.log(
    JSON.stringify({
      packaged_sources: sources.length,
      api_jars: classpath.length,
      release: 21,
      elapsed_ms: Math.round(performance.now() - started),
    }),
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
