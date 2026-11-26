import { expect, test } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hooksealExpress, sign, verifyRequest, type ExpressLikeRequest } from "../src/index.js";
import { runCli } from "../src/run.js";

const body = JSON.stringify({ type: "push", ref: "refs/heads/main" });

test("verifyRequest works with a Fetch API Request", async () => {
  const headers = await sign({ provider: "github", payload: body, secret: "s" });
  const request = new Request("https://example.com/hook", { method: "POST", headers, body });
  const result = await verifyRequest<{ ref: string }>(request, { provider: "github", secret: "s" });
  expect(result.valid && result.event?.ref).toBe("refs/heads/main");
});

test("verifyRequest uses request.url for square", async () => {
  const url = "https://example.com/square";
  const headers = await sign({ provider: "square", payload: body, secret: "s", url });
  const request = new Request(url, { method: "POST", headers, body });
  expect((await verifyRequest(request, { provider: "square", secret: "s" })).valid).toBe(true);
});

function fakeRes() {
  const res = { statusCode: 0, sent: undefined as unknown };
  return {
    res,
    api: { status: (code: number) => ((res.statusCode = code), { json: (b: unknown) => (res.sent = b) }) },
  };
}

test("express middleware: accepts valid, rejects invalid, explains missing raw body", async () => {
  const middleware = hooksealExpress({ provider: "github", secret: "s" });
  const headers = await sign({ provider: "github", payload: body, secret: "s" });

  const good: ExpressLikeRequest = { headers, body: Buffer.from(body) };
  let nextArg: unknown = "not called";
  await middleware(good, fakeRes().api, (e) => (nextArg = e));
  expect(nextArg).toBeUndefined();
  expect(good.webhook?.event).toMatchObject({ type: "push" });

  const bad = fakeRes();
  let called = false;
  await middleware({ headers, body: Buffer.from(body + "x") }, bad.api, () => (called = true));
  expect(called).toBe(false);
  expect(bad.res.statusCode).toBe(401);
  expect(bad.res.sent).toMatchObject({ error: "invalid_signature" });

  let error: unknown;
  await middleware({ headers, body: JSON.parse(body) }, fakeRes().api, (e) => (error = e));
  expect(String(error)).toMatch(/express\.raw/);
});

async function cli(args: string[], env: Record<string, string> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(args, { stdout: (t) => (stdout += `${t}\n`), stderr: (t) => (stderr += `${t}\n`), env });
  return { code, stdout, stderr };
}

test("CLI sign then verify", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hookseal-"));
  const file = join(dir, "event.json");
  writeFileSync(file, body);

  const signed = await cli(["sign", "--provider", "stripe", "--file", file, "--json"], { HOOKSEAL_SECRET: "whsec_x" });
  expect(signed.code).toBe(0);
  const headers = JSON.parse(signed.stdout) as Record<string, string>;
  const headerArgs = Object.entries(headers).flatMap(([k, v]) => ["--header", `${k}: ${v}`]);

  const ok = await cli(["verify", "--provider", "stripe", "--file", file, ...headerArgs], { HOOKSEAL_SECRET: "whsec_x" });
  expect(ok).toMatchObject({ code: 0 });
  expect(ok.stdout).toMatch(/valid stripe signature/);

  const bad = await cli(["verify", "--provider", "stripe", "--data", "{}", ...headerArgs], { HOOKSEAL_SECRET: "whsec_x" });
  expect(bad.code).toBe(1);
  expect(bad.stdout).toMatch(/invalid_signature/);
});

test("CLI curl output and errors", async () => {
  const curl = await cli(["sign", "--provider", "github", "--secret", "s", "--data", body, "--curl", "http://localhost:3000/hook"]);
  expect(curl.stdout).toMatch(/^curl -X POST 'http:\/\/localhost:3000\/hook'/);
  expect(curl.stdout).toMatch(/x-hub-signature-256: sha256=[0-9a-f]{64}/);

  expect((await cli(["sign", "--provider", "github", "--data", "x"])).code).toBe(2); // no secret
  expect((await cli(["sign", "--provider", "nope", "--secret", "s", "--data", "x"])).code).toBe(2);
  expect((await cli(["providers"])).stdout).toMatch(/stripe/);
});
