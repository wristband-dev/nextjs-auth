import { NextRequest } from 'next/server';

export const CLIENT_ID = 'clientId';
export const CLIENT_SECRET = 'clientSecret';
export const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

// Builds a real NextRequest from a node-mocks-http request. A plain object spread from the mock would carry the mock's
// Node `socket`, so the SDK would rightly treat it as a Node request rather than a Web request.
export function createMockNextRequest(req: any): NextRequest {
  return new NextRequest(req.url, { method: req.method, headers: new Headers(req.headers) });
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
