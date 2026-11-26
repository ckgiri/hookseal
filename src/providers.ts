import { fromBase64, fromUtf8, hmac, safeEqual, sha256, toBase64, toHex } from "./crypto.js";
import { getHeader } from "./headers.js";
import type { CustomScheme, FailureReason, HashAlgorithm, HeadersLike, ProviderName } from "./types.js";

export interface VerifyContext {
  body: Uint8Array;
  headers: HeadersLike;
  secret: string;
  url?: string;
  nowSec: number;
  tolerance: number | false;
  custom?: CustomScheme;
}

export interface SignContext {
  body: Uint8Array;
  secret: string;
  timestamp: number;
  id: string;
  url?: string;
  custom?: CustomScheme;
}

export type Check = { ok: true; timestamp?: number } | { ok: false; reason: FailureReason; message: string };

export interface Provider {
  verify(ctx: VerifyContext): Promise<Check>;
  sign(ctx: SignContext): Promise<Record<string, string>>;
}

export class HooksealError extends Error {
  constructor(
    readonly reason: FailureReason,
    message: string,
    readonly provider?: ProviderName,
  ) {
    super(message);
    this.name = "HooksealError";
  }
}

const fail = (reason: FailureReason, message: string): Check => ({ ok: false, reason, message });
const missing = (header: string) => fail("missing_header", `Missing ${header} header`);
const malformed = (header: string) => fail("malformed_header", `Malformed ${header} header`);
const mismatch = (detail = "Signature does not match") => fail("invalid_signature", detail);

function splitOnce(text: string, separator: string): [string, string] {
  const i = text.indexOf(separator);
  return i === -1 ? [text, ""] : [text.slice(0, i), text.slice(i + separator.length)];
}

const parseTimestamp = (value: string): number => (/^\d+$/.test(value) ? Number(value) : Number.NaN);

function checkTimestamp(ts: number, ctx: VerifyContext): Check {
  if (ctx.tolerance !== false) {
    const drift = Math.abs(ctx.nowSec - ts);
    if (drift > ctx.tolerance) {
      return fail(
        "timestamp_out_of_range",
        `Signed timestamp is ${drift}s away from now (tolerance ${ctx.tolerance}s). Possible replay, or the server clock is off`,
      );
    }
  }
  return { ok: true, timestamp: ts };
}

function requireUrl(url: string | undefined, provider: string): string {
  if (!url) throw new HooksealError("missing_url", `${provider} signs the request URL: pass the full public URL as \`url\``);
  return url;
}

async function digest(algorithm: HashAlgorithm, encoding: "hex" | "base64", key: string | Uint8Array, ...parts: Array<string | Uint8Array>) {
  const bytes = await hmac(algorithm, key, ...parts);
  return encoding === "hex" ? toHex(bytes) : toBase64(bytes);
}

const compare = (received: string, expected: string, encoding: "hex" | "base64") =>
  encoding === "hex" ? safeEqual(received.trim().toLowerCase(), expected) : safeEqual(received.trim(), expected);

// ---------- HMAC over the raw body (GitHub, Shopify, Razorpay, Lemon Squeezy, custom) ----------

function bodyHmac(header: string, algorithm: HashAlgorithm, encoding: "hex" | "base64", prefix = ""): Provider {
  return {
    async verify(ctx) {
      const value = getHeader(ctx.headers, header);
      if (!value) return missing(header);
      if (prefix && !value.startsWith(prefix)) return malformed(header);
      const expected = await digest(algorithm, encoding, ctx.secret, ctx.body);
      return compare(value.slice(prefix.length), expected, encoding) ? { ok: true } : mismatch();
    },
    async sign(ctx) {
      return { [header]: prefix + (await digest(algorithm, encoding, ctx.secret, ctx.body)) };
    },
  };
}

const custom: Provider = {
  verify(ctx) {
    const scheme = ctx.custom!;
    return bodyHmac(scheme.header.toLowerCase(), scheme.algorithm ?? "sha256", scheme.encoding ?? "hex", scheme.prefix ?? "").verify(ctx);
  },
  sign(ctx) {
    const scheme = ctx.custom!;
    return bodyHmac(scheme.header.toLowerCase(), scheme.algorithm ?? "sha256", scheme.encoding ?? "hex", scheme.prefix ?? "").sign(ctx);
  },
};

// ---------- Stripe: Stripe-Signature: t=<ts>,v1=<hex>[,v1=...] over "<ts>.<body>" ----------

const stripe: Provider = {
  async verify(ctx) {
    const header = getHeader(ctx.headers, "stripe-signature");
    if (!header) return missing("Stripe-Signature");
    let t: string | undefined;
    const signatures: string[] = [];
    for (const part of header.split(",")) {
      const [key, value] = splitOnce(part.trim(), "=");
      if (key === "t") t = value;
      else if (key === "v1" && value) signatures.push(value);
    }
    if (!t || signatures.length === 0) return malformed("Stripe-Signature");
    const ts = parseTimestamp(t);
    if (Number.isNaN(ts)) return malformed("Stripe-Signature");
    const expected = await digest("sha256", "hex", ctx.secret, `${t}.`, ctx.body);
    if (!signatures.some((s) => compare(s, expected, "hex"))) return mismatch();
    return checkTimestamp(ts, ctx);
  },
  async sign(ctx) {
    const sig = await digest("sha256", "hex", ctx.secret, `${ctx.timestamp}.`, ctx.body);
    return { "stripe-signature": `t=${ctx.timestamp},v1=${sig}` };
  },
};

// ---------- Slack: X-Slack-Signature: v0=<hex> over "v0:<ts>:<body>" ----------

const slack: Provider = {
  async verify(ctx) {
    const signature = getHeader(ctx.headers, "x-slack-signature");
    const timestamp = getHeader(ctx.headers, "x-slack-request-timestamp");
    if (!signature) return missing("X-Slack-Signature");
    if (!timestamp) return missing("X-Slack-Request-Timestamp");
    if (!signature.startsWith("v0=")) return malformed("X-Slack-Signature");
    const ts = parseTimestamp(timestamp);
    if (Number.isNaN(ts)) return malformed("X-Slack-Request-Timestamp");
    const expected = await digest("sha256", "hex", ctx.secret, `v0:${timestamp}:`, ctx.body);
    if (!compare(signature.slice(3), expected, "hex")) return mismatch();
    return checkTimestamp(ts, ctx);
  },
  async sign(ctx) {
    const sig = await digest("sha256", "hex", ctx.secret, `v0:${ctx.timestamp}:`, ctx.body);
    return { "x-slack-request-timestamp": String(ctx.timestamp), "x-slack-signature": `v0=${sig}` };
  },
};

// ---------- Paddle Billing: Paddle-Signature: ts=<ts>;h1=<hex> over "<ts>:<body>" ----------

const paddle: Provider = {
  async verify(ctx) {
    const header = getHeader(ctx.headers, "paddle-signature");
    if (!header) return missing("Paddle-Signature");
    let ts: string | undefined;
    const signatures: string[] = [];
    for (const part of header.split(";")) {
      const [key, value] = splitOnce(part.trim(), "=");
      if (key === "ts") ts = value;
      else if (key === "h1" && value) signatures.push(value);
    }
    if (!ts || signatures.length === 0) return malformed("Paddle-Signature");
    const parsed = parseTimestamp(ts);
    if (Number.isNaN(parsed)) return malformed("Paddle-Signature");
    const expected = await digest("sha256", "hex", ctx.secret, `${ts}:`, ctx.body);
    if (!signatures.some((s) => compare(s, expected, "hex"))) return mismatch();
    return checkTimestamp(parsed, ctx);
  },
  async sign(ctx) {
    const sig = await digest("sha256", "hex", ctx.secret, `${ctx.timestamp}:`, ctx.body);
    return { "paddle-signature": `ts=${ctx.timestamp};h1=${sig}` };
  },
};

// ---------- Standard Webhooks / Svix (Clerk, Resend, ...) ----------

function webhookKey(secret: string): Uint8Array | undefined {
  const key = fromBase64(secret.replace(/^whsec_/, ""));
  return key && key.length > 0 ? key : undefined;
}

function standardWebhooks(signPrefix: "webhook" | "svix"): Provider {
  const read = (headers: HeadersLike, name: string) =>
    getHeader(headers, `webhook-${name}`) ?? getHeader(headers, `svix-${name}`);
  return {
    async verify(ctx) {
      const id = read(ctx.headers, "id");
      const timestamp = read(ctx.headers, "timestamp");
      const signature = read(ctx.headers, "signature");
      if (!id) return missing("webhook-id (or svix-id)");
      if (!timestamp) return missing("webhook-timestamp (or svix-timestamp)");
      if (!signature) return missing("webhook-signature (or svix-signature)");
      const ts = parseTimestamp(timestamp);
      if (Number.isNaN(ts)) return malformed("webhook-timestamp");
      const key = webhookKey(ctx.secret);
      if (!key) return fail("invalid_secret", "Secret must be base64, optionally prefixed with whsec_");

      const candidates = signature
        .split(" ")
        .map((s) => splitOnce(s, ","))
        .filter(([version, value]) => version === "v1" && value)
        .map(([, value]) => value);
      if (candidates.length === 0) return malformed("webhook-signature");

      const expected = await digest("sha256", "base64", key, `${id}.${timestamp}.`, ctx.body);
      if (!candidates.some((c) => compare(c, expected, "base64"))) return mismatch();
      return checkTimestamp(ts, ctx);
    },
    async sign(ctx) {
      const key = webhookKey(ctx.secret);
      if (!key) throw new HooksealError("invalid_secret", "Secret must be base64, optionally prefixed with whsec_");
      const sig = await digest("sha256", "base64", key, `${ctx.id}.${ctx.timestamp}.`, ctx.body);
      return {
        [`${signPrefix}-id`]: ctx.id,
        [`${signPrefix}-timestamp`]: String(ctx.timestamp),
        [`${signPrefix}-signature`]: `v1,${sig}`,
      };
    },
  };
}

// ---------- Square: base64 HMAC-SHA256 over "<notification url><body>" ----------

const square: Provider = {
  async verify(ctx) {
    const header = getHeader(ctx.headers, "x-square-hmacsha256-signature");
    if (!header) return missing("X-Square-HmacSha256-Signature");
    if (!ctx.url) return fail("missing_url", "Square signs the notification URL: pass the full public URL as `url`");
    const expected = await digest("sha256", "base64", ctx.secret, ctx.url, ctx.body);
    return compare(header, expected, "base64") ? { ok: true } : mismatch();
  },
  async sign(ctx) {
    const url = requireUrl(ctx.url, "Square");
    return { "x-square-hmacsha256-signature": await digest("sha256", "base64", ctx.secret, url, ctx.body) };
  },
};

// ---------- Twilio: base64 HMAC-SHA1 over URL + sorted form params (or bodySHA256 for JSON) ----------

function twilioParams(body: Uint8Array): string {
  const params = new URLSearchParams(fromUtf8(body));
  const keys = [...new Set(params.keys())].sort();
  return keys.map((key) => params.getAll(key).sort().map((value) => key + value).join("")).join("");
}

async function twilioData(url: string, body: Uint8Array): Promise<{ data: string } | { error: Check }> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { error: fail("missing_url", `Invalid url: ${url}`) };
  }
  const bodyHash = parsed.searchParams.get("bodySHA256");
  if (bodyHash !== null) {
    if (!safeEqual(toHex(await sha256(body)), bodyHash.toLowerCase())) {
      return { error: mismatch("Body does not match the bodySHA256 query parameter") };
    }
    return { data: url };
  }
  return { data: url + twilioParams(body) };
}

const twilio: Provider = {
  async verify(ctx) {
    const header = getHeader(ctx.headers, "x-twilio-signature");
    if (!header) return missing("X-Twilio-Signature");
    if (!ctx.url) return fail("missing_url", "Twilio signs the request URL: pass the full public URL as `url`");
    const result = await twilioData(ctx.url, ctx.body);
    if ("error" in result) return result.error;
    const expected = await digest("sha1", "base64", ctx.secret, result.data);
    return compare(header, expected, "base64") ? { ok: true } : mismatch();
  },
  async sign(ctx) {
    const url = requireUrl(ctx.url, "Twilio");
    const result = await twilioData(url, ctx.body);
    if ("error" in result) throw new HooksealError("missing_url", (result.error as { message: string }).message);
    return { "x-twilio-signature": await digest("sha1", "base64", ctx.secret, result.data) };
  },
};

export const PROVIDERS: Record<ProviderName, Provider> = {
  stripe,
  github: bodyHmac("x-hub-signature-256", "sha256", "hex", "sha256="),
  shopify: bodyHmac("x-shopify-hmac-sha256", "sha256", "base64"),
  razorpay: bodyHmac("x-razorpay-signature", "sha256", "hex"),
  lemonsqueezy: bodyHmac("x-signature", "sha256", "hex"),
  slack,
  paddle,
  square,
  twilio,
  "standard-webhooks": standardWebhooks("webhook"),
  svix: standardWebhooks("svix"),
  clerk: standardWebhooks("svix"),
  resend: standardWebhooks("svix"),
  custom,
};

export const PROVIDER_NAMES = Object.keys(PROVIDERS) as ProviderName[];
