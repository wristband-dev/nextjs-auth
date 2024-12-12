import { NextRequest } from 'next/server';

export const CLIENT_ID = 'clientId';
export const CLIENT_SECRET = 'clientSecret';
export const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

// Use the MockNextRequest class to simulate `nextUrl` and `searchParams`
export function createMockNextRequest(req: any): NextRequest {
  return {
    ...req,
    nextUrl: new URL(req.url), // Pass req.url directly to MockNextRequest
    geo: undefined, // Stub for unused properties
    page: undefined,
    ua: undefined,
    headers: new Headers(req.headers),
  } as unknown as NextRequest; // Use type assertion to satisfy the type
}

export function parseSetCookies(setCookieHeaders: string | string[]): {
  name: string;
  value: string;
  [key: string]: string | boolean;
}[] {
  if (!setCookieHeaders) {
    throw new Error('setCookieHeaders cannot be empty, null, or undefined');
  }

  const headers = (
    Array.isArray(setCookieHeaders)
      ? setCookieHeaders.flat() // Flatten nested arrays
      : [setCookieHeaders]
  ).filter((header) => {
    return typeof header === 'string';
  });

  return headers.map((header) => {
    const parts = header.split(';');
    const [nameValuePair, ...attributes] = parts;

    const [name, value] = nameValuePair.split('=').map((str) => {
      return str.trim();
    });

    // Explicit type with index signature
    const cookieObject: { name: string; value: string; [key: string]: string | boolean } = { name, value };

    attributes.forEach((attr) => {
      const [key, val] = attr.split('=').map((str) => {
        return str.trim();
      });
      const attributeKey = key.toLowerCase();
      cookieObject[attributeKey] = val === undefined ? true : val;
    });

    return cookieObject;
  });
}
