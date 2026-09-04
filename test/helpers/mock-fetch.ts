/**
 * Shared `global.fetch` mocking utilities for tests that exercise flows which now call the
 * Wristband API (for example, tenant custom domain validation during login/callback/logout).
 */

interface MockedResponse {
  status: number;
  body?: unknown;
}

function toFetchResponse({ status, body }: MockedResponse) {
  const responseBodyText = body === undefined ? '' : JSON.stringify(body);
  return Promise.resolve({
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get: () => {
        return 'application/json';
      },
    },
    text: jest.fn().mockResolvedValue(responseBodyText),
  });
}

export interface WristbandFetchMockConfig {
  /** Value returned by the `/custom-domains/validate` endpoint. Defaults to `true`. */
  tenantCustomDomainValid?: boolean;
  /** Status returned by the `/custom-domains/validate` endpoint. Defaults to `200`. */
  validateStatus?: number;
  /** Status returned by any other endpoint (for example `/oauth2/revoke`). Defaults to `200`. */
  revokeStatus?: number;
  /** Body returned by the `/oauth2/token` endpoint. */
  tokens?: unknown;
  /** Body returned by the `/oauth2/userinfo` endpoint. */
  userinfo?: unknown;
}

/**
 * Installs a `global.fetch` mock that routes by URL so a single test can exercise both tenant
 * custom domain validation and refresh token revocation.
 *
 * @param config - Per-endpoint response overrides.
 * @returns The installed jest mock, for call assertions.
 */
export function mockWristbandFetch(config: WristbandFetchMockConfig = {}): jest.Mock {
  const { tenantCustomDomainValid = true, validateStatus = 200, revokeStatus = 200, tokens, userinfo } = config;

  const fetchMock = jest.fn().mockImplementation((url: string) => {
    if (url.includes('/custom-domains/validate')) {
      return toFetchResponse({ status: validateStatus, body: { valid: tenantCustomDomainValid } });
    }
    if (url.includes('/oauth2/token')) {
      return toFetchResponse({ status: 200, body: tokens });
    }
    if (url.includes('/oauth2/userinfo')) {
      return toFetchResponse({ status: 200, body: userinfo });
    }
    return toFetchResponse({ status: revokeStatus });
  });

  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

/**
 * Asserts that the tenant custom domain validation endpoint was called for the given vanity domain
 * with the expected tenant custom domain in the request body.
 *
 * @param vanityDomain - The Wristband application vanity domain the SDK was configured with.
 * @param tenantCustomDomain - The tenant custom domain expected in the request body.
 */
export function expectValidateCalled(vanityDomain: string, tenantCustomDomain: string): void {
  expect(global.fetch).toHaveBeenCalledWith(
    `https://${vanityDomain}/api/v1/custom-domains/validate`,
    expect.objectContaining({ method: 'POST', body: JSON.stringify({ tenantCustomDomain }) })
  );
}

/**
 * Asserts that the tenant custom domain validation endpoint was never called.
 */
export function expectValidateNotCalled(): void {
  expect(global.fetch).not.toHaveBeenCalledWith(expect.stringContaining('/custom-domains/validate'), expect.anything());
}
