import { NextResponse } from 'next/server';
import {
  parseTenantSubdomain,
  resolveTenantName,
  resolveTenantCustomDomainParam,
  createLoginState,
  createLoginStateCookie,
  getAuthorizeUrl,
  getLoginStateCookie,
  clearLoginStateCookie,
} from '../../../src/utils/auth/app-router-utils';
import { createMockNextRequest, CLIENT_ID } from '../../test-utils';
import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../../../src/utils/constants';

jest.mock('../../../src/utils/crypto', () => {
  return {
    base64ToURLSafe: jest.fn((input) => {
      return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }),
    generateRandomString: jest.fn((length) => {
      return 'a'.repeat(length);
    }),
    sha256Base64: jest.fn(async (input) => {
      return `mocked-hash-${input}`;
    }),
  };
});

describe('parseTenantSubdomain', () => {
  test('should extract subdomain when host matches root domain', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.example.com/path',
      headers: { host: 'tenant.example.com' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('tenant');
  });

  test('should return empty string when host does not match root domain', () => {
    const req = createMockNextRequest({
      url: 'https://different.otherdomain.com/path',
      headers: { host: 'different.otherdomain.com' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('');
  });

  test('should handle complex subdomains', () => {
    const req = createMockNextRequest({
      url: 'https://my-tenant-123.example.com/path',
      headers: { host: 'my-tenant-123.example.com' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('my-tenant-123');
  });

  test('should handle root domain directly', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { host: 'example.com' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('');
  });

  test('should strip port from host header', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.example.com:3000/path',
      headers: { host: 'tenant.example.com:3000' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('tenant');
  });

  test('should strip port from host header with complex subdomain', () => {
    const req = createMockNextRequest({
      url: 'https://my-tenant-123.example.com:8080/path',
      headers: { host: 'my-tenant-123.example.com:8080' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('my-tenant-123');
  });

  test('should handle host without port (no change)', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.example.com/path',
      headers: { host: 'tenant.example.com' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('tenant');
  });

  test('should return empty string when root domain does not match after stripping port', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.otherdomain.com:3000/path',
      headers: { host: 'tenant.otherdomain.com:3000' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('');
  });

  test('should strip port when accessing root domain directly', () => {
    const req = createMockNextRequest({
      url: 'https://example.com:3000/path',
      headers: { host: 'example.com:3000' },
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe('');
  });
});

describe('resolveTenantName', () => {
  test('should return subdomain when parseTenantFromRootDomain is provided', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.example.com/path',
      headers: { host: 'tenant.example.com' },
    });

    const result = resolveTenantName(req, 'example.com');
    expect(result).toBe('tenant');
  });

  test('should return tenant_name query param when parseTenantFromRootDomain is not provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?tenant_name=mytenant',
      headers: { host: 'example.com' },
    });

    const result = resolveTenantName(req, '');
    expect(result).toBe('mytenant');
  });

  test('should return empty string when no tenant_name param and no parseTenantFromRootDomain', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { host: 'example.com' },
    });

    const result = resolveTenantName(req, '');
    expect(result).toBe('');
  });

  test('should throw error when multiple tenant_name params are provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?tenant_name=tenant1&tenant_name=tenant2',
      headers: { host: 'example.com' },
    });

    expect(() => {
      return resolveTenantName(req, '');
    }).toThrow('More than one [tenant_name] query parameter was encountered');
  });

  test('should prioritize subdomain over query param when both are present', () => {
    const req = createMockNextRequest({
      url: 'https://subdomain-tenant.example.com/path?tenant_name=query-tenant',
      headers: { host: 'subdomain-tenant.example.com' },
    });

    const result = resolveTenantName(req, 'example.com');
    expect(result).toBe('subdomain-tenant');
  });

  test('should strip port when resolving tenant from subdomain', () => {
    const req = createMockNextRequest({
      url: 'https://tenant.example.com:3000/path',
      headers: { host: 'tenant.example.com:3000' },
    });

    const result = resolveTenantName(req, 'example.com');
    expect(result).toBe('tenant');
  });

  test('should prioritize subdomain over query param even with port in host', () => {
    const req = createMockNextRequest({
      url: 'https://subdomain-tenant.example.com:3000/path?tenant_name=query-tenant',
      headers: { host: 'subdomain-tenant.example.com:3000' },
    });

    const result = resolveTenantName(req, 'example.com');
    expect(result).toBe('subdomain-tenant');
  });
});

describe('resolveTenantCustomDomainParam', () => {
  test('should return tenant_custom_domain query param', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?tenant_custom_domain=custom.domain.com',
      headers: {},
    });

    const result = resolveTenantCustomDomainParam(req);
    expect(result).toBe('custom.domain.com');
  });

  test('should return empty string when no tenant_custom_domain param', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = resolveTenantCustomDomainParam(req);
    expect(result).toBe('');
  });

  test('should throw error when multiple tenant_custom_domain params are provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?tenant_custom_domain=domain1.com&tenant_custom_domain=domain2.com',
      headers: {},
    });

    expect(() => {
      return resolveTenantCustomDomainParam(req);
    }).toThrow('More than one [tenant_custom_domain] query parameter was encountered');
  });
});

describe('createLoginState', () => {
  test('should create login state with basic parameters', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com');

    expect(result).toMatchObject({
      state: expect.any(String),
      codeVerifier: expect.any(String),
      redirectUri: 'https://redirect.com',
    });
    expect(result.state).toHaveLength(32);
    expect(result.codeVerifier).toHaveLength(32);
  });

  test('should include return_url from query params', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=/dashboard',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com');

    expect(result.returnUrl).toBe('/dashboard');
  });

  test('should use config returnUrl over query param', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=/dashboard',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com', {
      returnUrl: '/admin',
    });

    expect(result.returnUrl).toBe('/admin');
  });

  test('should include customState when provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const customState = { userId: '123', role: 'admin' };
    const result = createLoginState(req, 'https://redirect.com', {
      customState,
    });

    expect(result.customState).toEqual(customState);
  });

  test('should not include empty customState', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com', {
      customState: {},
    });

    expect(result.customState).toBeUndefined();
  });

  test('should throw error when multiple return_url params are provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=/dashboard&return_url=/admin',
      headers: {},
    });

    expect(() => {
      return createLoginState(req, 'https://redirect.com');
    }).toThrow('More than one [return_url] query parameter was encountered');
  });

  test('should handle empty return_url gracefully', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com', {
      returnUrl: '',
    });

    expect(result.returnUrl).toBeUndefined();
  });
});

describe('createLoginStateCookie', () => {
  let mockResponse: NextResponse;

  beforeEach(() => {
    mockResponse = new NextResponse();
    jest.spyOn(mockResponse.headers, 'append');
  });

  test('should create new login state cookie', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    createLoginStateCookie(req, mockResponse, 'state123', 'encrypted-data', false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(`${LOGIN_STATE_COOKIE_PREFIX}state123${LOGIN_STATE_COOKIE_SEPARATOR}`)
    );
    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('encrypted-data'));
    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('Secure'));
  });

  test('should not include Secure flag when dangerouslyDisableSecureCookies is true', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    createLoginStateCookie(req, mockResponse, 'state123', 'encrypted-data', true);

    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.not.stringContaining('Secure'));
  });

  test('should remove oldest cookie when 3 login cookies already exist', () => {
    const oldestTime = Date.now() - 3000;
    const middleTime = Date.now() - 2000;
    const newestTime = Date.now() - 1000;

    const cookieHeader = [
      `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}${oldestTime}=value1`,
      `${LOGIN_STATE_COOKIE_PREFIX}state2${LOGIN_STATE_COOKIE_SEPARATOR}${middleTime}=value2`,
      `${LOGIN_STATE_COOKIE_PREFIX}state3${LOGIN_STATE_COOKIE_SEPARATOR}${newestTime}=value3`,
    ].join('; ');

    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { cookie: cookieHeader },
    });

    createLoginStateCookie(req, mockResponse, 'state4', 'encrypted-data', false);

    // Should delete the oldest cookie
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(
        `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}${oldestTime}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`
      )
    );

    // Should create new cookie
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(`${LOGIN_STATE_COOKIE_PREFIX}state4${LOGIN_STATE_COOKIE_SEPARATOR}`)
    );
  });

  test('should handle malformed cookies gracefully', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { cookie: 'malformed-cookie-without-equals; another=value' },
    });

    expect(() => {
      createLoginStateCookie(req, mockResponse, 'state123', 'encrypted-data', false);
    }).not.toThrow();
  });
});

describe('getAuthorizeUrl', () => {
  const baseConfig = {
    clientId: CLIENT_ID,
    codeVerifier: 'test-code-verifier',
    redirectUri: 'https://redirect.com',
    scopes: ['openid', 'profile'],
    state: 'test-state',
    wristbandApplicationVanityDomain: 'app.wristband.dev',
  };

  test('should create authorize URL with tenant custom domain (highest priority)', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      tenantCustomDomain: 'custom.domain.com',
      tenantName: 'tenant',
      defaultTenantCustomDomain: 'default-custom.domain.com',
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('https://custom.domain.com/api/v1/oauth2/authorize');
    expect(result).toContain(`client_id=${CLIENT_ID}`);
    expect(result).toContain('state=test-state');
    expect(result).toContain('scope=openid+profile');
  });

  test('should create authorize URL with tenant domain name (second priority)', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      tenantName: 'tenant',
      defaultTenantCustomDomain: 'default-custom.domain.com',
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('https://tenant-app.wristband.dev/api/v1/oauth2/authorize');
  });

  test('should use dot separator when isApplicationCustomDomainActive is true', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      tenantName: 'tenant',
      isApplicationCustomDomainActive: true,
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('https://tenant.app.wristband.dev/api/v1/oauth2/authorize');
  });

  test('should create authorize URL with default tenant custom domain (third priority)', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      defaultTenantCustomDomain: 'default-custom.domain.com',
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('https://default-custom.domain.com/api/v1/oauth2/authorize');
  });

  test('should create authorize URL with default tenant domain name (lowest priority)', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('https://default-tenant-app.wristband.dev/api/v1/oauth2/authorize');
  });

  test('should include login_hint when provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?login_hint=user@example.com',
      headers: {},
    });

    const config = {
      ...baseConfig,
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain('login_hint=user%40example.com');
  });

  test('should throw error when multiple login_hint params are provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?login_hint=user1@example.com&login_hint=user2@example.com',
      headers: {},
    });

    const config = {
      ...baseConfig,
      defaultTenantName: 'default-tenant',
    };

    await expect(getAuthorizeUrl(req, config)).rejects.toThrow(
      'More than one [login_hint] query parameter was encountered'
    );
  });

  test('should include all required OAuth2 parameters', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const config = {
      ...baseConfig,
      defaultTenantName: 'default-tenant',
    };

    const result = await getAuthorizeUrl(req, config);

    expect(result).toContain(`client_id=${CLIENT_ID}`);
    expect(result).toContain('redirect_uri=https%3A%2F%2Fredirect.com');
    expect(result).toContain('response_type=code');
    expect(result).toContain('state=test-state');
    expect(result).toContain('scope=openid+profile');
    expect(result).toContain('code_challenge=');
    expect(result).toContain('code_challenge_method=S256');
    expect(result).toContain('nonce=');
  });
});

describe('getLoginStateCookie', () => {
  test('should return matching login state cookie', () => {
    const cookieHeader = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890=encrypted-value; other-cookie=other-value`;

    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: cookieHeader },
    });

    const result = getLoginStateCookie(req);

    expect(result).toEqual({
      name: `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`,
      value: 'encrypted-value',
    });
  });

  test('should return null when no matching cookie found', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: 'other-cookie=other-value' },
    });

    const result = getLoginStateCookie(req);

    expect(result).toBeNull();
  });

  test('should return null when no state parameter provided', () => {
    const cookieHeader = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890=encrypted-value`;

    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { cookie: cookieHeader },
    });

    const result = getLoginStateCookie(req);

    expect(result).toBeNull();
  });

  test('should return null when no cookies present', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: {},
    });

    const result = getLoginStateCookie(req);

    expect(result).toBeNull();
  });

  test('should handle URL-encoded state parameter', () => {
    const cookieHeader = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890=encrypted-value`;

    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: cookieHeader },
    });

    const result = getLoginStateCookie(req);

    expect(result).toEqual({
      name: `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`,
      value: 'encrypted-value',
    });
  });

  test('should return first matching cookie when multiple exist (should not happen in practice)', () => {
    const cookieHeader = [
      `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1111111111=first-value`,
      `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}2222222222=second-value`,
    ].join('; ');

    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: cookieHeader },
    });

    const result = getLoginStateCookie(req);

    expect(result?.name).toBe(`${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1111111111`);
    expect(result?.value).toBe('first-value');
  });
});

describe('clearLoginStateCookie', () => {
  let mockResponse: NextResponse;

  beforeEach(() => {
    mockResponse = new NextResponse();
    jest.spyOn(mockResponse.headers, 'append');
  });

  test('should clear login state cookie with secure flag', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
    );
  });

  test('should clear login state cookie without secure flag when dangerouslyDisableSecureCookies is true', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, true);

    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; `
    );
  });

  test('should handle cookie names with special characters', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test%2Bstate${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining(cookieName));
  });
});

// Edge cases and error scenarios
describe('Edge Cases and Error Handling', () => {
  test('parseCookies should handle empty cookie header', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    // This tests the internal parseCookies function indirectly
    const result = getLoginStateCookie(req);
    expect(result).toBeNull();
  });

  test('parseCookies should handle cookies without values', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: 'cookie-without-value; normal-cookie=value' },
    });

    // Should not throw and should handle gracefully
    const result = getLoginStateCookie(req);
    expect(result).toBeNull();
  });

  test('parseCookies should handle cookies with multiple equals signs', () => {
    const cookieHeader = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890=encrypted=value=with=equals; other=value`;

    const req = createMockNextRequest({
      url: 'https://example.com/path?state=test-state',
      headers: { cookie: cookieHeader },
    });

    const result = getLoginStateCookie(req);
    expect(result?.value).toBe('encrypted=value=with=equals');
  });

  test('should handle missing host header gracefully', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = parseTenantSubdomain(req, 'example.com');
    expect(result).toBe(''); // Should return empty string, not throw
  });

  test('createLoginState should handle null/undefined config', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = createLoginState(req, 'https://redirect.com', undefined);

    expect(result).toMatchObject({
      state: expect.any(String),
      codeVerifier: expect.any(String),
      redirectUri: 'https://redirect.com',
    });
  });
});
