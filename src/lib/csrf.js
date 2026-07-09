import crypto from "crypto";
import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
} from "./csrfConstants";

const CSRF_SECRET =
  process.env.CSRF_SECRET || crypto.randomBytes(32).toString("hex");

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function validateCsrf(request) {
  const cookieToken = request.cookies?.get(CSRF_COOKIE_NAME)?.value;
  const headerToken = request.headers?.get(CSRF_HEADER_NAME);

  if (!cookieToken || !headerToken) {
    return false;
  }

  if (!timingSafeEqual(cookieToken, headerToken)) {
    return false;
  }

  if (cookieToken.includes(".")) {
    const parts = cookieToken.split(".");
    if (parts.length !== 2) return false;
    const [randomValue, signature] = parts;
    const expected = crypto
      .createHmac("sha256", CSRF_SECRET)
      .update(randomValue)
      .digest("hex");
    if (!timingSafeEqual(signature, expected)) return false;
    return true;
  }

  const parts = cookieToken.split(":");
  if (parts.length !== 3) return false;
  const [random, timestamp, hmac] = parts;
  const expectedHmac = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(`${random}:${timestamp}`)
    .digest("hex");
  if (!timingSafeEqual(hmac, expectedHmac)) return false;
  const tokenAge = Date.now() - parseInt(timestamp, 36);
  if (tokenAge > 24 * 60 * 60 * 1000) return false;
  return true;
}

export function setCsrfCookie(response) {
  const token = crypto.randomBytes(32).toString("hex");

  response.cookies.set(CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60,
  });

  return token;
}