import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { HooksealError, PROVIDER_NAMES } from "./providers.js";
import { sign, verify } from "./verify.js";
import type { ProviderName } from "./types.js";

declare const __VERSION__: string;
const VERSION = typeof __VERSION__ !== "undefined" ? __VERSION__ : "dev";

const HELP = `hookseal - verify and create webhook signatures

Usage
  hookseal providers
  hookseal sign   --provider <name> --file <payload> [--secret <s>] [--url <url>] [--curl <endpoint>]
  hookseal verify --provider <name> --file <payload> --header "<name>: <value>" [--secret <s>] [--url <url>]

Options
  --provider <name>    ${PROVIDER_NAMES.join(", ")}
  --file <path>        Payload file (raw body)
  --data <text>        Payload text instead of --file
  --secret <secret>    Webhook secret (or set HOOKSEAL_SECRET to keep it out of shell history)
  --url <url>          Public URL (required for square, twilio)
  --header <h: v>      Request header for verify (repeatable)
  --timestamp <sec>    Timestamp for sign (default: now)
  --tolerance <sec>    Replay window for verify, 0 = off (default: 300)
  --curl <endpoint>    sign: print a ready-to-run curl command
  --json               Print JSON
  -h, --help           Show help
  -v, --version        Show version

Examples
  hookseal sign --provider stripe --secret whsec_test --file event.json --curl http://localhost:3000/webhooks/stripe
  hookseal verify --provider github --secret s3cret --file body.json --header "X-Hub-Signature-256: sha256=..."`;

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
}

const defaultIO: CliIO = {
  stdout: (t) => console.log(t),
  stderr: (t) => console.error(t),
  env: process.env,
};

const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

export async function runCli(argv: string[], io: CliIO = defaultIO): Promise<number> {
  try {
    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        provider: { type: "string" },
        file: { type: "string" },
        data: { type: "string" },
        secret: { type: "string" },
        url: { type: "string" },
        header: { type: "string", multiple: true },
        timestamp: { type: "string" },
        tolerance: { type: "string" },
        curl: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });

    const command = positionals[0];
    if (values.version) {
      io.stdout(VERSION);
      return 0;
    }
    if (values.help || !command) {
      io.stdout(HELP);
      return command || values.help ? 0 : 2;
    }
    if (command === "providers") {
      io.stdout(PROVIDER_NAMES.join("\n"));
      return 0;
    }
    if (command !== "sign" && command !== "verify") throw new Error(`Unknown command "${command}". Run hookseal --help`);

    const provider = values.provider as ProviderName | undefined;
    if (!provider) throw new Error("--provider is required");
    if (!PROVIDER_NAMES.includes(provider) || provider === "custom") {
      throw new Error(`Unknown provider "${provider}". Supported: ${PROVIDER_NAMES.filter((p) => p !== "custom").join(", ")}`);
    }
    const secret = values.secret ?? io.env.HOOKSEAL_SECRET;
    if (!secret) throw new Error("Pass --secret or set HOOKSEAL_SECRET");
    if (!values.file && values.data === undefined) throw new Error("Pass --file <path> or --data <text>");
    const payload = values.file ? new Uint8Array(readFileSync(values.file)) : (values.data as string);

    if (command === "sign") {
      const timestamp = values.timestamp ? Number(values.timestamp) : undefined;
      const headers = await sign({ provider, payload, secret, url: values.url, timestamp });
      if (values.curl) {
        const parts = [`curl -X POST ${shellQuote(values.curl)}`, `-H 'content-type: application/json'`];
        for (const [name, value] of Object.entries(headers)) parts.push(`-H ${shellQuote(`${name}: ${value}`)}`);
        parts.push(values.file ? `--data-binary @${shellQuote(values.file)}` : `--data-binary ${shellQuote(values.data as string)}`);
        io.stdout(parts.join(" \\\n  "));
      } else if (values.json) {
        io.stdout(JSON.stringify(headers, null, 2));
      } else {
        for (const [name, value] of Object.entries(headers)) io.stdout(`${name}: ${value}`);
      }
      return 0;
    }

    const headers: Record<string, string> = {};
    for (const h of values.header ?? []) {
      const i = h.indexOf(":");
      if (i === -1) throw new Error(`--header must look like "Name: value" (got "${h}")`);
      headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
    }
    const tolerance = values.tolerance === undefined ? undefined : Number(values.tolerance) === 0 ? false : Number(values.tolerance);
    const result = await verify({ provider, payload, headers, secret, url: values.url, toleranceSeconds: tolerance });

    if (values.json) {
      io.stdout(JSON.stringify(result.valid ? { valid: true, provider, timestamp: result.timestamp } : result, null, 2));
    } else if (result.valid) {
      io.stdout(`✔ valid ${provider} signature`);
    } else {
      io.stdout(`✖ ${result.reason}: ${result.message}`);
    }
    return result.valid ? 0 : 1;
  } catch (error) {
    const message = error instanceof HooksealError || error instanceof Error ? error.message : String(error);
    io.stderr(`hookseal: ${message}`);
    return 2;
  }
}
