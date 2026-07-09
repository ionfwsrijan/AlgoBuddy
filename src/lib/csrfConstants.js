export const CSRF_COOKIE_NAME = "csrf-token";
export const CSRF_HEADER_NAME = "x-csrf-token";

const TRUSTED_ORIGINS = (() => {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  const vercelUrl = process.env.NEXT_PUBLIC_VERCEL_URL;

  const origins = new Set([
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://algobuddy.me",
    "https://www.algobuddy.me",
    "https://algobuddy.vercel.app",
  ]);

  if (appUrl) origins.add(appUrl.replace(/\/+$/, ""));
  if (vercelUrl) {
    origins.add(`https://${vercelUrl.replace(/\/+$/, "")}`);
  }

  return origins;
})();

const VERCEL_URL = process.env.NEXT_PUBLIC_VERCEL_URL;

export function validateCsrfOrigin(request) {
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");

  const source = origin || referer || "";
  const normalized = source.replace(/\/+$/, "");

  if (TRUSTED_ORIGINS.has(normalized)) return true;

  if (process.env.NEXT_PUBLIC_VERCEL_ENV === "preview") {
    try {
      const url = new URL(normalized);
      if (url.hostname.endsWith(".vercel.app")) return true;
      if (VERCEL_URL && url.hostname.endsWith(VERCEL_URL)) return true;
    } catch {
      return false;
    }
  }

  return false;
}

const STATE_CHANGING_METHODS = new Set([
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
]);

export function isStateChangingMethod(method) {
  return STATE_CHANGING_METHODS.has(method);
}

export function isApiRoute(pathname) {
  return pathname.startsWith("/api/");
}