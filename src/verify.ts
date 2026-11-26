import { fromUtf8, utf8 } from "./crypto.js";
import { HooksealError, PROVIDERS, PROVIDER_NAMES, type Check } from "./providers.js";
import type { FailureReason, Payload, ProviderName, SignOptions, VerifyOptions, VerifyResult } from "./types.js";

const DEFAULT_TOLERANCE = 300;

function toBytes(payload: unknown): Uint8Array | undefined {
  if (typeof payload === "string") return utf8(payload);
  if (payload instanceof Uint8Array) return payload; // includes Node Buffer
  if (payload instanceof ArrayBuffer) return new Uint8Array(payload);
  return undefined;
}

const PAYLOAD_HINT =
  "payload must be the raw request body (string, Buffer, Uint8Array or ArrayBuffer), not parsed JSON. " +
  "In Express use express.raw({ type: '*/*' }) on the webhook route";

function parseEvent(provider: ProviderName, text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    if (provider === "twilio") return Object.fromEntries(new URLSearchParams(text));
    return undefined;
  }
}

/**
 * Verify a webhook signature. Never throws for bad input: check `result.valid`.
 */
export async function verify<T = unknown>(options: VerifyOptions): Promise<VerifyResult<T>> {
  const provider = options.provider;
  const failure = (reason: FailureReason, message: string): VerifyResult<T> => ({ valid: false, provider, reason, message });

  const impl = PROVIDERS[provider];
  if (!impl) return failure("unknown_provider", `Unknown provider "${provider}". Supported: ${PROVIDER_NAMES.join(", ")}`);
  if (provider === "custom" && !options.custom?.header) {
    return failure("invalid_options", 'provider "custom" needs a `custom: { header }` scheme');
  }

  const body = toBytes(options.payload);
  if (!body) return failure("invalid_payload", PAYLOAD_HINT);

  const secrets = (Array.isArray(options.secret) ? options.secret : [options.secret]).filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  if (secrets.length === 0) return failure("missing_secret", "No webhook secret provided");

  const nowMs = options.now instanceof Date ? options.now.getTime() : (options.now ?? Date.now());
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE;

  let last: Check | undefined;
  for (const secret of secrets) {
    const check = await impl.verify({
      body,
      headers: options.headers ?? {},
      secret,
      url: options.url,
      nowSec: Math.floor(nowMs / 1000),
      tolerance,
      custom: options.custom,
    });
    if (check.ok) {
      const payload = fromUtf8(body);
      return {
        valid: true,
        provider,
        payload,
        event: options.parse === false ? undefined : (parseEvent(provider, payload) as T | undefined),
        ...(check.timestamp !== undefined ? { timestamp: check.timestamp } : {}),
      };
    }
    // Only a signature mismatch can be fixed by trying the next secret.
    if (check.reason !== "invalid_signature") return failure(check.reason, check.message);
    last = check;
  }
  const final = last as { reason: FailureReason; message: string };
  return failure(final.reason, final.message);
}

/** Like `verify`, but throws a `HooksealError` when the signature is not valid. */
export async function verifyOrThrow<T = unknown>(options: VerifyOptions) {
  const result = await verify<T>(options);
  if (!result.valid) throw new HooksealError(result.reason, result.message, result.provider);
  return result;
}

/**
 * Verify a Fetch API `Request` (Hono, Next.js route handlers, Cloudflare Workers, Bun, Deno).
 * Reads the body, so use `result.event` / `result.payload` afterwards.
 */
export async function verifyRequest<T = unknown>(
  request: Request,
  options: Omit<VerifyOptions, "payload" | "headers">,
): Promise<VerifyResult<T>> {
  const body = new Uint8Array(await request.arrayBuffer());
  return verify<T>({ ...options, payload: body, headers: request.headers, url: options.url ?? request.url });
}

function randomId(): string {
  return `msg_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
}

/**
 * Create the signature headers a provider would send. Useful for tests and local development.
 */
export async function sign(options: SignOptions): Promise<Record<string, string>> {
  const impl = PROVIDERS[options.provider];
  if (!impl) throw new HooksealError("unknown_provider", `Unknown provider "${options.provider}"`);
  if (options.provider === "custom" && !options.custom?.header) {
    throw new HooksealError("invalid_options", 'provider "custom" needs a `custom: { header }` scheme');
  }
  const body = toBytes(options.payload as Payload);
  if (!body) throw new HooksealError("invalid_payload", PAYLOAD_HINT);
  if (!options.secret) throw new HooksealError("missing_secret", "No webhook secret provided");

  return impl.sign({
    body,
    secret: options.secret,
    timestamp: options.timestamp ?? Math.floor(Date.now() / 1000),
    id: options.id ?? randomId(),
    url: options.url,
    custom: options.custom,
  });
}
