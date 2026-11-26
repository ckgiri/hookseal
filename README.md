# hookseal

**Verify webhook signatures from any provider with one API.**

[![npm](https://img.shields.io/npm/v/hookseal)](https://www.npmjs.com/package/hookseal)
![node](https://img.shields.io/node/v/hookseal)
![license](https://img.shields.io/npm/l/hookseal)

```ts
import { verify } from "hookseal";

const result = await verify({
  provider: "stripe",
  payload: rawBody,          // the raw request body
  headers: req.headers,
  secret: process.env.STRIPE_WEBHOOK_SECRET,
});

if (!result.valid) return res.status(401).send(result.reason);
console.log(result.event);   // parsed JSON
```

- **One API for 13 providers:** Stripe, GitHub, Shopify, Razorpay, Slack, Paddle, Lemon Squeezy, Square, Twilio, and Standard Webhooks (Svix, Clerk, Resend), plus your own HMAC scheme.
- **Secure by default:** constant-time comparison, replay protection with a timestamp window, key rotation.
- **Runs everywhere:** built on Web Crypto. Node 20+, Bun, Deno, Cloudflare Workers, Vercel Edge.
- **Never throws on bad input:** you get `{ valid: false, reason, message }` with a clear reason.
- **Test helpers:** `sign()` creates the exact headers a provider would send.
- **Zero dependencies.** ESM and CommonJS. Fully typed.

Checked against the official Stripe and Svix SDKs, in both directions.

## Install

```bash
npm i hookseal
```

## Providers

| `provider` | Header(s) | Scheme |
|---|---|---|
| `stripe` | `Stripe-Signature` | HMAC-SHA256 hex of `t.body`, timestamp checked |
| `github` | `X-Hub-Signature-256` | HMAC-SHA256 hex of body, `sha256=` prefix |
| `shopify` | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 base64 of body |
| `razorpay` | `X-Razorpay-Signature` | HMAC-SHA256 hex of body |
| `slack` | `X-Slack-Signature`, `X-Slack-Request-Timestamp` | HMAC-SHA256 of `v0:ts:body`, timestamp checked |
| `paddle` | `Paddle-Signature` | HMAC-SHA256 of `ts:body`, timestamp checked |
| `lemonsqueezy` | `X-Signature` | HMAC-SHA256 hex of body |
| `square` | `X-Square-HmacSha256-Signature` | HMAC-SHA256 base64 of `url + body` (needs `url`) |
| `twilio` | `X-Twilio-Signature` | HMAC-SHA1 base64 of URL + sorted params, or `bodySHA256` for JSON (needs `url`) |
| `standard-webhooks` | `webhook-id`, `webhook-timestamp`, `webhook-signature` | [Standard Webhooks](https://www.standardwebhooks.com/) |
| `svix`, `clerk`, `resend` | `svix-id`, `svix-timestamp`, `svix-signature` | Standard Webhooks (Svix headers) |
| `custom` | your header | your algorithm, encoding and prefix |

## Usage

### Express

```ts
import express from "express";
import { hooksealExpress } from "hookseal";

app.post(
  "/webhooks/stripe",
  express.raw({ type: "*/*" }),       // keep the raw body
  hooksealExpress({ provider: "stripe", secret: process.env.STRIPE_WEBHOOK_SECRET }),
  (req, res) => {
    const event = req.webhook.event;  // verified and parsed
    res.sendStatus(200);
  },
);
```

Rejected requests get `401` with `{ "error": "<reason>", "message": "..." }`.

### Next.js route handler, Hono, Cloudflare Workers, Bun, Deno

```ts
import { verifyRequest } from "hookseal";

export async function POST(request: Request) {
  const result = await verifyRequest(request, {
    provider: "github",
    secret: process.env.GITHUB_WEBHOOK_SECRET,
  });
  if (!result.valid) return new Response(result.reason, { status: 401 });
  // result.event, result.payload
  return new Response("ok");
}
```

Hono: `verifyRequest(c.req.raw, { ... })`.

### Fastify, Koa, anything else

Pass the raw body as a `string`, `Buffer`, `Uint8Array` or `ArrayBuffer`:

```ts
const result = await verify({ provider: "shopify", payload: rawBody, headers: request.headers, secret });
```

> **Always verify the raw body.** Parsing and re-serialising JSON changes the bytes and the signature will not match. If you pass a parsed object, hookseal returns `reason: "invalid_payload"` with a hint.

### Key rotation

```ts
await verify({ provider: "github", payload, headers, secret: [process.env.NEW_SECRET, process.env.OLD_SECRET] });
```

### Square and Twilio

They sign the URL as well, so pass the **public** URL the provider called (behind a proxy, `request.url` may differ):

```ts
await verify({ provider: "twilio", payload, headers, secret: authToken, url: "https://api.example.com/twilio/sms" });
```

For Twilio form posts, `result.event` holds the form fields.

### Your own scheme

```ts
await verify({
  provider: "custom",
  custom: { header: "x-acme-signature", algorithm: "sha512", encoding: "base64", prefix: "acme=" },
  payload, headers, secret,
});
```

### Throwing style

```ts
import { verifyOrThrow, HooksealError } from "hookseal";

try {
  const { event } = await verifyOrThrow({ provider: "slack", payload, headers, secret });
} catch (error) {
  if (error instanceof HooksealError) console.log(error.reason);
}
```

## API

### `verify(options): Promise<VerifyResult>`

| Option | Type | Default | Description |
|---|---|---|---|
| `provider` | `ProviderName` | — | Required. See the table above |
| `payload` | `string \| Uint8Array \| ArrayBuffer` | — | Required. Raw request body |
| `headers` | `Headers \| Record<string, string \| string[]>` | — | Required. Request headers, any case |
| `secret` | `string \| string[]` | — | Required. One secret, or several for rotation |
| `toleranceSeconds` | `number \| false` | `300` | Replay window for signed timestamps. `false` disables |
| `url` | `string` | — | Public URL. Required for `square` and `twilio` |
| `parse` | `boolean` | `true` | Parse the payload into `event` |
| `custom` | `{ header, algorithm?, encoding?, prefix? }` | — | Required for `provider: "custom"` |
| `now` | `Date \| number` | `Date.now()` | Clock override for tests |

Returns `{ valid: true, provider, event, payload, timestamp? }` or `{ valid: false, provider, reason, message }`.

**Failure reasons:** `missing_header`, `malformed_header`, `invalid_signature`, `timestamp_out_of_range`, `missing_secret`, `invalid_secret`, `missing_url`, `invalid_payload`, `invalid_options`, `unknown_provider`.

### Other exports

| Export | Description |
|---|---|
| `verifyRequest(request, options)` | Verify a Fetch API `Request`. Uses `request.url` as `url` by default |
| `verifyOrThrow(options)` | Same as `verify`, throws `HooksealError` on failure |
| `hooksealExpress(options)` | Express / Connect middleware. Sets `req.webhook` |
| `sign({ provider, payload, secret, timestamp?, url?, id? })` | Returns the headers the provider would send |
| `PROVIDER_NAMES` | List of supported providers |

## Testing your webhook handler

```ts
import { sign } from "hookseal";

const payload = JSON.stringify({ type: "checkout.session.completed" });
const headers = await sign({ provider: "stripe", payload, secret: "whsec_test" });

await fetch("http://localhost:3000/webhooks/stripe", { method: "POST", headers, body: payload });
```

## CLI

```bash
# Print a ready-to-run curl command with valid signature headers
npx hookseal sign --provider stripe --secret whsec_test --file event.json --curl http://localhost:3000/webhooks/stripe

# Check a signature you received
npx hookseal verify --provider github --secret s3cret --file body.json \
  --header "X-Hub-Signature-256: sha256=757107ea..."

npx hookseal providers
```

Set `HOOKSEAL_SECRET` instead of `--secret` to keep secrets out of your shell history. Exit codes: `0` valid, `1` invalid, `2` error.

## License

MIT
