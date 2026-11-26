import type { HeadersLike } from "./types.js";

/** Case-insensitive header lookup for Fetch `Headers` and plain objects. */
export function getHeader(headers: HeadersLike, name: string): string | undefined {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name) ?? undefined;
  }
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    if (key.toLowerCase() !== wanted || value === undefined || value === null) continue;
    return Array.isArray(value) ? (value[0] === undefined ? undefined : String(value[0])) : String(value);
  }
  return undefined;
}
