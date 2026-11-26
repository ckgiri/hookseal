import { verify } from "./verify.js";
import type { VerifyOptions, VerifySuccess } from "./types.js";

/** The parts of an Express / Connect request that hookseal uses. */
export interface ExpressLikeRequest {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: unknown;
  webhook?: VerifySuccess;
}

export interface ExpressLikeResponse {
  status(code: number): { json(body: unknown): unknown };
}

export type ExpressMiddlewareOptions = Omit<VerifyOptions, "payload" | "headers" | "url"> & {
  /** Public URL (string or function of the request). Required for Square and Twilio. */
  url?: string | ((req: ExpressLikeRequest) => string);
  /** HTTP status for rejected requests. Default: 401 */
  failureStatus?: number;
};

/**
 * Express / Connect middleware. Mount it after `express.raw({ type: "*\/*" })`.
 * On success the result is available as `req.webhook` (`req.webhook.event` is the parsed payload).
 */
export function hooksealExpress(options: ExpressMiddlewareOptions) {
  const { url, failureStatus = 401, ...verifyOptions } = options;
  return async (req: ExpressLikeRequest, res: ExpressLikeResponse, next: (error?: unknown) => void) => {
    try {
      const raw = req.rawBody ?? req.body;
      if (!(raw instanceof Uint8Array) && typeof raw !== "string") {
        next(new Error("hookseal: raw body not found. Use express.raw({ type: '*/*' }) on the webhook route"));
        return;
      }
      const result = await verify({
        ...verifyOptions,
        payload: raw,
        headers: req.headers,
        url: typeof url === "function" ? url(req) : url,
      });
      if (!result.valid) {
        res.status(failureStatus).json({ error: result.reason, message: result.message });
        return;
      }
      req.webhook = result;
      next();
    } catch (error) {
      next(error);
    }
  };
}
