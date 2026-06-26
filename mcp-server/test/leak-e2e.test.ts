import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

const canary = "ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST";

describe("plaintext leak scanner", () => {
  it("reports leaking file paths without echoing canary values", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "asv-leak-e2e-"));
    try {
      const leakPath = path.join(directory, "deliberate-leak.txt");
      await writeFile(leakPath, canary);

      const result = await runScanner([directory]);

      expect(result.status).not.toBe(0);
      expect(result.stdout).toContain(leakPath);
      expect(result.stdout).not.toContain(canary);
      expect(result.stderr).not.toContain(canary);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

interface ScannerResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runScanner(scanPaths: string[]): Promise<ScannerResult> {
  const scriptPath = path.resolve(projectRoot(), "scripts/scan-plaintext.sh");
  const child = spawn(scriptPath, scanPaths, {
    env: { ...process.env, ASV_CANARY: canary }
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({
        status,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      });
    });
  });
}

function projectRoot(): string {
  return path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../.."
  );
}
