/**
 * Deployment-aware client identity resolution.
 *
 * NEVER falls back to a shared constant: collapsing every anonymous client
 * into one rate-limit bucket would let a single visitor lock out the whole
 * site (see the ip:unknown global-DoS issue).
 *
 * Resolution order:
 *   1. Vercel edge (VERCEL=1): x-real-ip is set by Vercel and cannot be
 *      spoofed by the client; x-forwarded-for is a fallback.
 *   2. Explicit trusted proxy (TRUSTED_PROXY_IPS): x-forwarded-for is only
 *      parsed when the operator has declared that requests pass through a
 *      trusted proxy which rewrites the header.
 *   3. Local development: trust whatever proxy headers are present.
 *   4. Production with no trustworthy source: return null so callers build a
 *      per-request fingerprint instead of a shared key.
 */

const TRUSTED_PROXY_IPS = new Set(
  (process.env.TRUSTED_PROXY_IPS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
);

const IS_VERCEL = process.env.VERCEL === "1";

let warnedUnconfigured = false;

function warnIfNoTrustedIpSource() {
  if (
    process.env.NODE_ENV === "production" &&
    !IS_VERCEL &&
    TRUSTED_PROXY_IPS.size === 0 &&
    !warnedUnconfigured
  ) {
    warnedUnconfigured = true;
    console.warn(
      "[getClientIp] Production deployment is not on Vercel and TRUSTED_PROXY_IPS is unset. " +
        "No trustworthy client-IP source is configured, so anonymous rate-limit keys will use a " +
        "per-request fingerprint instead of the real client IP. Set TRUSTED_PROXY_IPS to the IPs " +
        "of the proxies in front of this deployment (e.g. Render, Cloudflare) to enable IP-based limiting.",
    );
  }
}

// Warn at startup so an unconfigured deployment is loud, not silent.
warnIfNoTrustedIpSource();

function leftmostForwardedIp(headers) {
  const xff = headers.get("x-forwarded-for");
  if (!xff) return null;
  const first = xff.split(",")[0].trim();
  if (!first || first.toLowerCase() === "unknown") return null;
  return first;
}

function realIp(headers) {
  const value = headers.get("x-real-ip");
  return value && value.trim() ? value.trim() : null;
}

/**
 * Returns the client IP when a trustworthy source exists, otherwise null.
 * Callers must NOT substitute a shared constant for null; use
 * resolveClientId() to get a per-request identity instead.
 *
 * @param {Headers} headers  The request headers object.
 * @returns {string | null}  Verified IP address, or null when undeterminable.
 */
export function getClientIp(headers) {
  if (IS_VERCEL) {
    return realIp(headers) || leftmostForwardedIp(headers);
  }

  if (TRUSTED_PROXY_IPS.size > 0) {
    return leftmostForwardedIp(headers) || realIp(headers);
  }

  if (process.env.NODE_ENV !== "production") {
    return realIp(headers) || leftmostForwardedIp(headers);
  }

  warnIfNoTrustedIpSource();
  return null;
}

// FNV-1a 32-bit — synchronous and environment-agnostic (works in Node and
// Edge runtimes without importing node:crypto).
function fnv1a(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/**
 * Returns a stable per-client identifier for rate limiting: the trusted
 * client IP when one can be determined, otherwise a fingerprint of the
 * request headers (x-forwarded-for, user-agent, accept-language,
 * cf-connecting-ip). The result is never a shared constant, so anonymous
 * traffic never collapses into a single bucket.
 *
 * @param {Headers} headers  The request headers object.
 * @returns {string}  "1.2.3.4" or "fp:<8-hex-char-fingerprint>".
 */
export function resolveClientId(headers) {
  const ip = getClientIp(headers);
  if (ip) return ip;

  const parts = [
    headers.get("x-forwarded-for") || "",
    headers.get("user-agent") || "",
    headers.get("accept-language") || "",
    headers.get("cf-connecting-ip") || "",
  ];
  return `fp:${fnv1a(parts.join("|"))}`;
}
