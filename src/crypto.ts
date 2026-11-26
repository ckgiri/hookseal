import type { HashAlgorithm } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (text: string): Uint8Array => encoder.encode(text);
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

const HASH_NAMES: Record<HashAlgorithm, string> = { sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512" };

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("hookseal needs the Web Crypto API (globalThis.crypto.subtle), available in Node 20+, Bun, Deno and edge runtimes");
  return s;
}

export function concat(...parts: Array<string | Uint8Array>): Uint8Array {
  const arrays = parts.map((p) => (typeof p === "string" ? utf8(p) : p));
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export async function hmac(
  algorithm: HashAlgorithm,
  key: string | Uint8Array,
  ...parts: Array<string | Uint8Array>
): Promise<Uint8Array> {
  const keyBytes = typeof key === "string" ? utf8(key) : key;
  const cryptoKey = await subtle().importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: HASH_NAMES[algorithm] },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle().sign("HMAC", cryptoKey, concat(...parts) as BufferSource));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));
}

export const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array | undefined {
  try {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** Constant-time string comparison. Length is not secret (signature lengths are public). */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
