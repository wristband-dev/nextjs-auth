import * as httpMocks from 'node-mocks-http';

export type { MockResponse } from 'node-mocks-http';

/**
 * node-mocks-http's createMocks, plus a `Cookie` header built from `cookies`. Real Pages Router requests always carry
 * the header that `req.cookies` is parsed from, and @wristband/typescript-auth reads cookies from that header.
 */
export function createMocks(
  ...args: Parameters<typeof httpMocks.createMocks>
): ReturnType<typeof httpMocks.createMocks> {
  const [reqOptions, resOptions] = args;
  const cookies = reqOptions?.cookies;
  const cookieHeader = cookies
    ? Object.entries(cookies)
        .map(([name, value]) => {
          return `${name}=${value}`;
        })
        .join('; ')
    : '';
  return httpMocks.createMocks(
    {
      ...reqOptions,
      headers: { ...(cookieHeader ? { cookie: cookieHeader } : {}), ...reqOptions?.headers },
    },
    resOptions
  );
}
