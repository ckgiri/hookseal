export type ProviderName =
  | "stripe"
  | "github"
  | "shopify"
  | "razorpay"
  | "slack"
  | "paddle"
  | "lemonsqueezy"
  | "square"
  | "twilio"
  | "standard-webhooks"
  | "svix"
  | "clerk"
  | "resend"
  | "custom";

/** A Fetch API `Headers` object or a plain object such as Node's `req.headers`. */
export type HeadersLike = Headers | Record<string, string | string[] | number | undefined>;

/** The raw request body. Never pass parsed JSON: re-serialising changes the bytes. */
export type Payload = string | Uint8Array | ArrayBuffer;

export type HashAlgorithm = "sha1" | "sha256" | "sha512";

/** Describe an in-house HMAC scheme. */
export interface CustomScheme {
  /** Header that carries the signature, e.g. "x-signature". */
  header: string;
  /** Default: "sha256" */
  algorithm?: HashAlgorithm;
  /** Default: "hex" */
  encoding?: "hex" | "base64";
  /** Text before the signature, e.g. "sha256=". Default: "" */
  prefix?: string;
}

export interface VerifyOptions {
  provider: ProviderName;
  /** Raw request body. */
  payload: Payload;
  headers: HeadersLike;
  /** Webhook secret. Pass several during key rotation: any match passes. */
  secret: string | string[] | undefined;
  /** Maximum age of a signed timestamp in seconds. `false` disables the check. Default: 300 */
  toleranceSeconds?: number | false;
  /** Full public URL the provider sent the webhook to. Required for Square and Twilio. */
  url?: string;
  /** Parse the payload into `event`. Default: true */
  parse?: boolean;
  /** Required when provider is "custom". */
  custom?: CustomScheme;
  /** Clock override (Date or epoch milliseconds). */
  now?: Date | number;
}

export type FailureReason =
  | "unknown_provider"
  | "invalid_payload"
  | "invalid_options"
  | "missing_secret"
  | "invalid_secret"
  | "missing_url"
  | "missing_header"
  | "malformed_header"
  | "invalid_signature"
  | "timestamp_out_of_range";

export interface VerifySuccess<T = unknown> {
  valid: true;
  provider: ProviderName;
  /** Raw payload as text. */
  payload: string;
  /** Parsed JSON (or form fields for Twilio). `undefined` if parsing is off or fails. */
  event: T | undefined;
  /** Signed timestamp in epoch seconds, for providers that sign one. */
  timestamp?: number;
}

export interface VerifyFailure {
  valid: false;
  provider: ProviderName;
  reason: FailureReason;
  message: string;
}

export type VerifyResult<T = unknown> = VerifySuccess<T> | VerifyFailure;

export interface SignOptions {
  provider: ProviderName;
  payload: Payload;
  secret: string;
  /** Epoch seconds. Default: now */
  timestamp?: number;
  /** Required for Square and Twilio. */
  url?: string;
  /** Message id for Standard Webhooks / Svix. Default: random */
  id?: string;
  /** Required when provider is "custom". */
  custom?: CustomScheme;
}
