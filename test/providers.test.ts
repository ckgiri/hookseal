import { describe, expect, test } from "vitest";
import { createHash, createHmac } from "node:crypto";
import { sign, verify, verifyOrThrow, HooksealError, type ProviderName, type VerifyOptions } from "../src/index.js";

const NOW = 1_764_158_400; // fixed epoch seconds
const now = NOW * 1000;
const body = JSON.stringify({ id: "evt_123", type: "payment.succeeded", amount: 4200 });
const hmacHex = (algo: string, key: string | Buffer, data: string) => createHmac(algo, key).update(data).digest("hex");
const hmacB64 = (algo: string, key: string | Buffer, data: string) => createHmac(algo, key).update(data).digest("base64");

const base = (provider: ProviderName, headers: Record<string, string>, secret: string, extra: Partial<VerifyOptions> = {}) =>
  verify({ provider, payload: body, headers, secret, now, ...extra });

describe("official formats (expected values computed independently with node:crypto)", () => {
  test("GitHub docs test vector", async () => {
    // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
    const result = await verify({
      provider: "github",
      payload: "Hello, World!",
      secret: "It's a Secret to Everybody",
      headers: { "x-hub-signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17" },
    });
    expect(result.valid).toBe(true);
  });

  test("stripe", async () => {
    const secret = "whsec_test_secret";
    const sig = hmacHex("sha256", secret, `${NOW}.${body}`);
    const result = await base("stripe", { "Stripe-Signature": `t=${NOW},v1=${sig},v0=ignored` }, secret);
    expect(result).toMatchObject({ valid: true, timestamp: NOW, event: { id: "evt_123" } });
  });

  test("shopify", async () => {
    const secret = "shpss_secret";
    const result = await base("shopify", { "X-Shopify-Hmac-Sha256": hmacB64("sha256", secret, body) }, secret);
    expect(result.valid).toBe(true);
  });

  test("razorpay", async () => {
    const secret = "rzp_secret";
    expect((await base("razorpay", { "x-razorpay-signature": hmacHex("sha256", secret, body) }, secret)).valid).toBe(true);
  });

  test("lemonsqueezy", async () => {
    const secret = "ls_secret";
    expect((await base("lemonsqueezy", { "X-Signature": hmacHex("sha256", secret, body) }, secret)).valid).toBe(true);
  });

  test("slack", async () => {
    const secret = "slack_signing_secret";
    const sig = `v0=${hmacHex("sha256", secret, `v0:${NOW}:${body}`)}`;
    const result = await base("slack", { "X-Slack-Signature": sig, "X-Slack-Request-Timestamp": String(NOW) }, secret);
    expect(result).toMatchObject({ valid: true, timestamp: NOW });
  });

  test("paddle", async () => {
    const secret = "pdl_ntfset_secret";
    const sig = hmacHex("sha256", secret, `${NOW}:${body}`);
    expect((await base("paddle", { "Paddle-Signature": `ts=${NOW};h1=${sig}` }, secret)).valid).toBe(true);
  });

  test("standard webhooks / svix with whsec_ base64 secret", async () => {
    const keyBytes = Buffer.from("super-secret-key-material-32byte");
    const secret = `whsec_${keyBytes.toString("base64")}`;
    const sig = hmacB64("sha256", keyBytes, `msg_1.${NOW}.${body}`);
    const svix = await base("svix", { "svix-id": "msg_1", "svix-timestamp": String(NOW), "svix-signature": `v1,bad v1,${sig}` }, secret);
    expect(svix.valid).toBe(true);
    const std = await base("standard-webhooks", { "webhook-id": "msg_1", "webhook-timestamp": String(NOW), "webhook-signature": `v1,${sig}` }, secret);
    expect(std.valid).toBe(true);
  });

  test("square signs url + body", async () => {
    const secret = "sq_key";
    const url = "https://example.com/webhooks/square";
    const header = { "x-square-hmacsha256-signature": hmacB64("sha256", secret, url + body) };
    expect((await base("square", header, secret, { url })).valid).toBe(true);
    expect((await base("square", header, secret)).valid).toBe(false);
    expect(await base("square", header, secret, { url: "https://evil.example/hook" })).toMatchObject({ reason: "invalid_signature" });
  });

  test("twilio form params, sorted", async () => {
    const secret = "twilio_auth_token";
    const url = "https://example.com/twilio/sms?x=1";
    const form = "To=%2B15550001111&From=%2B15552223333&Body=Hi+there&Body=Again";
    const data = `${url}BodyAgainBodyHi thereFrom+15552223333To+15550001111`;
    const result = await verify({
      provider: "twilio",
      payload: form,
      url,
      secret,
      headers: { "X-Twilio-Signature": hmacB64("sha1", secret, data) },
    });
    expect(result).toMatchObject({ valid: true, event: { To: "+15550001111", From: "+15552223333" } });
  });

  test("twilio JSON body with bodySHA256", async () => {
    const secret = "twilio_auth_token";
    const url = `https://example.com/twilio/json?bodySHA256=${createHash("sha256").update(body).digest("hex")}`;
    const headers = { "x-twilio-signature": hmacB64("sha1", secret, url) };
    expect((await verify({ provider: "twilio", payload: body, url, secret, headers })).valid).toBe(true);
    const tampered = await verify({ provider: "twilio", payload: body + " ", url, secret, headers });
    expect(tampered).toMatchObject({ valid: false, reason: "invalid_signature" });
  });

  test("custom scheme", async () => {
    const secret = "in-house";
    const custom = { header: "X-Acme-Signature", algorithm: "sha512" as const, encoding: "base64" as const, prefix: "acme=" };
    const headers = { "x-acme-signature": `acme=${hmacB64("sha512", secret, body)}` };
    expect((await base("custom", headers, secret, { custom })).valid).toBe(true);
    expect(await base("custom", headers, secret)).toMatchObject({ reason: "invalid_options" });
  });
});

describe("sign() round trips for every provider", () => {
  const providers: ProviderName[] = [
    "stripe", "github", "shopify", "razorpay", "lemonsqueezy", "slack", "paddle",
    "standard-webhooks", "svix", "clerk", "resend", "square", "twilio",
  ];
  const secretFor = (p: ProviderName) =>
    ["standard-webhooks", "svix", "clerk", "resend"].includes(p) ? `whsec_${Buffer.from("k".repeat(24)).toString("base64")}` : "s3cret";

  for (const provider of providers) {
    test(provider, async () => {
      const secret = secretFor(provider);
      const url = "https://example.com/hook";
      const headers = await sign({ provider, payload: body, secret, timestamp: NOW, url });
      const ok = await verify({ provider, payload: body, headers, secret, url, now });
      expect(ok.valid).toBe(true);

      const tampered = await verify({ provider, payload: body.replace("4200", "1"), headers, secret, url, now });
      expect(tampered).toMatchObject({ valid: false, reason: "invalid_signature" });

      const wrongSecret = await verify({ provider, payload: body, headers, secret: secretFor(provider) + "x", url, now });
      expect(wrongSecret.valid).toBe(false);

      const missing = await verify({ provider, payload: body, headers: {}, secret, url, now });
      expect(missing).toMatchObject({ valid: false, reason: "missing_header" });
    });
  }
});

describe("behaviour", () => {
  test("rejects replayed timestamps and allows disabling the check", async () => {
    const headers = await sign({ provider: "stripe", payload: body, secret: "s", timestamp: NOW - 301 });
    expect(await verify({ provider: "stripe", payload: body, headers, secret: "s", now })).toMatchObject({
      reason: "timestamp_out_of_range",
    });
    expect((await verify({ provider: "stripe", payload: body, headers, secret: "s", now, toleranceSeconds: 600 })).valid).toBe(true);
    expect((await verify({ provider: "stripe", payload: body, headers, secret: "s", now, toleranceSeconds: false })).valid).toBe(true);
  });

  test("key rotation: any secret may match", async () => {
    const headers = await sign({ provider: "github", payload: body, secret: "new" });
    expect((await verify({ provider: "github", payload: body, headers, secret: ["old", "new"] })).valid).toBe(true);
    expect((await verify({ provider: "github", payload: body, headers, secret: ["old", "older"] })).valid).toBe(false);
  });

  test("accepts Buffer, Uint8Array, ArrayBuffer and Headers", async () => {
    const headers = await sign({ provider: "github", payload: body, secret: "s" });
    const bytes = new TextEncoder().encode(body);
    for (const payload of [Buffer.from(body), bytes, bytes.buffer.slice(0)]) {
      expect((await verify({ provider: "github", payload, headers: new Headers(headers), secret: "s" })).valid).toBe(true);
    }
  });

  test("node-style headers with arrays and mixed case", async () => {
    const signed = await sign({ provider: "github", payload: body, secret: "s" });
    const headers = { "X-HUB-SIGNATURE-256": [signed["x-hub-signature-256"]!], other: undefined };
    expect((await verify({ provider: "github", payload: body, headers, secret: "s" })).valid).toBe(true);
  });

  test("helpful errors for common mistakes", async () => {
    const headers = await sign({ provider: "github", payload: body, secret: "s" });
    expect(await verify({ provider: "github", payload: JSON.parse(body), headers, secret: "s" })).toMatchObject({
      reason: "invalid_payload",
    });
    expect(await verify({ provider: "github", payload: body, headers, secret: undefined })).toMatchObject({ reason: "missing_secret" });
    expect(await verify({ provider: "nope" as ProviderName, payload: body, headers, secret: "s" })).toMatchObject({
      reason: "unknown_provider",
    });
    expect(await verify({ provider: "github", payload: body, headers: { "x-hub-signature-256": "md5=abc" }, secret: "s" })).toMatchObject({
      reason: "malformed_header",
    });
    expect(await verify({ provider: "svix", payload: body, headers: { "svix-id": "1", "svix-timestamp": String(NOW), "svix-signature": "v1,x" }, secret: "not base64!", now })).toMatchObject({
      reason: "invalid_secret",
    });
  });

  test("parse: false skips JSON parsing", async () => {
    const headers = await sign({ provider: "github", payload: body, secret: "s" });
    const result = await verify({ provider: "github", payload: body, headers, secret: "s", parse: false });
    expect(result).toMatchObject({ valid: true, event: undefined, payload: body });
  });

  test("verifyOrThrow throws HooksealError", async () => {
    await expect(verifyOrThrow({ provider: "github", payload: body, headers: {}, secret: "s" })).rejects.toBeInstanceOf(HooksealError);
    await expect(verifyOrThrow({ provider: "github", payload: body, headers: {}, secret: "s" })).rejects.toMatchObject({
      reason: "missing_header",
    });
  });

  test("sign() needs a url for square and twilio", async () => {
    await expect(sign({ provider: "square", payload: body, secret: "s" })).rejects.toMatchObject({ reason: "missing_url" });
  });
});
