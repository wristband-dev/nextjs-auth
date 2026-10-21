import { NextResponse } from 'next/server';
import {
  parseTenantSubdomain,
  resolveTenantName,
  resolveTenantCustomDomainParam,
  resolveReturnUrl,
  validateReturnUrl,
  toAbsoluteUrl,
  createLoginStateCookie,
  getAuthorizationUrlParams,
  getLoginStateCookie,
  clearLoginStateCookie,
  createCallbackRedirectResponse,
} from '../../../src/utils/auth/app-router-utils';
import { createMockNextRequest, CLIENT_ID } from '../../test-utils';
import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../../../src/utils/constants';

jest.mock('../../../src/utils/auth/common-utils', () => {
  return {
    generateRandomString: jest.fn((length) => {
      return 'a'.repeat(length);
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

  test('should return empty string when host does not match parseTenantFromRootDomain', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: { host: 'example.com' },
    });

    const result = resolveTenantName(req, 'example.com');
    expect(result).toBe('');
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

describe('resolveReturnUrl', () => {
  test('Returns undefined when no return URL is provided anywhere', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    expect(resolveReturnUrl(req)).toBeUndefined();
  });

  test('Returns the return_url query parameter when no config is provided', () => {
    const req = createMockNextRequest({
      url: `https://example.com/path?return_url=${encodeURIComponent('https://example.com/dashboard')}`,
      headers: {},
    });

    expect(resolveReturnUrl(req)).toBe('https://example.com/dashboard');
  });

  test('Returns LoginConfig.returnUrl when no query parameter is present', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
  });

  test('LoginConfig.returnUrl takes precedence over the return_url query parameter', () => {
    const req = createMockNextRequest({
      url: `https://example.com/path?return_url=${encodeURIComponent('https://example.com/query')}`,
      headers: {},
    });

    expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
  });

  test('Falls back to the query parameter when LoginConfig.returnUrl is an empty string', () => {
    const req = createMockNextRequest({
      url: `https://example.com/path?return_url=${encodeURIComponent('https://example.com/query')}`,
      headers: {},
    });

    expect(resolveReturnUrl(req, { returnUrl: '' })).toBe('https://example.com/query');
  });

  test('Returns undefined when the return_url query parameter is an empty string', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=',
      headers: {},
    });

    expect(resolveReturnUrl(req)).toBeUndefined();
  });

  test('Throws error for multiple return_url query parameters', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=url1&return_url=url2',
      headers: {},
    });

    expect(() => {
      return resolveReturnUrl(req);
    }).toThrow('More than one [return_url] query parameter was encountered');
  });

  test('Does not throw for multiple return_url query parameters when LoginConfig.returnUrl is set', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?return_url=url1&return_url=url2',
      headers: {},
    });

    expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
  });
});

describe('validateReturnUrl', () => {
  // Minimal request mock exposing only what validateReturnUrl reads.
  // The request URL host is the server's own address, as Next.js reports it behind a proxy.
  const buildReq = (host: string, protocol: string = 'https') => {
    return createMockNextRequest({
      url: `${protocol}://localhost:3000/api/auth/callback`,
      headers: { host, 'x-forwarded-proto': protocol },
    });
  };

  const rootDomain = 'myapp.com';
  const tenantName = 'acme';

  describe('Input guards', () => {
    test('Throws when tenantName is empty', () => {
      const req = buildReq('acme.myapp.com');

      expect(() => {
        return validateReturnUrl(req, '/settings', '', true, rootDomain);
      }).toThrow('Tenant name is required to validate returnUrl');
    });

    test('Throws when tenantName is empty even if returnUrl is missing', () => {
      const req = buildReq('acme.myapp.com');

      expect(() => {
        return validateReturnUrl(req, undefined, '', true, rootDomain);
      }).toThrow('Tenant name is required to validate returnUrl');
    });

    test('Returns undefined when returnUrl is undefined', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, undefined, tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Returns undefined when returnUrl is an empty string', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, '', tenantName, true, rootDomain)).toBeUndefined();
    });
  });

  describe('Allowed hosts', () => {
    test('Allows a relative path and returns it unchanged', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, '/settings?tab=1#top', tenantName, true, rootDomain)).toBe('/settings?tab=1#top');
    });

    test('Allows an absolute URL on the same host as the request', () => {
      const req = buildReq('acme.myapp.com');
      const returnUrl = 'https://acme.myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Ignores port when comparing hostnames', () => {
      const req = buildReq('acme.myapp.com');
      const returnUrl = 'https://acme.myapp.com:9999/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Allows same-host URLs when parseTenantFromRootDomain is not set', () => {
      const req = buildReq('app.example.com');
      const returnUrl = 'https://app.example.com/home';

      expect(validateReturnUrl(req, returnUrl, tenantName, false)).toBe(returnUrl);
    });
  });

  describe('Rejected hosts', () => {
    test('Rejects a different domain', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a different tenant subdomain', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://other.myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a protocol-relative URL to another host', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, '//evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a backslash-prefixed URL to another host', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, '/\\evil.com/phish', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a lookalike domain that starts with the root domain', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://myapp.com.evil.com/', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a URL using userinfo to disguise the real host', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://acme.myapp.com@evil.com/', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a javascript: URL', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'javascript:alert(1)', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects the root domain when parseTenantFromRootDomain is not set', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://myapp.com/dashboard', tenantName, true)).toBeUndefined();
    });

    test('Returns undefined for a malformed URL', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://', tenantName, true, rootDomain)).toBeUndefined();
    });
  });

  describe('Root domain tenant rewrite', () => {
    test('Prepends the tenant subdomain to a root domain URL', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'https://myapp.com/dashboard?x=1#top', tenantName, true, rootDomain)).toBe(
        'https://acme.myapp.com/dashboard?x=1#top'
      );
    });

    test('Preserves the port when rewriting', () => {
      const req = buildReq('acme.localhost:6001', 'http');

      expect(validateReturnUrl(req, 'http://localhost:6001/home', tenantName, true, 'localhost')).toBe(
        'http://acme.localhost:6001/home'
      );
    });

    test('Does not rewrite when applicationAuthorizationRequestsEnabled is false', () => {
      const req = buildReq('acme.myapp.com');
      const returnUrl = 'https://myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, false, rootDomain)).toBe(returnUrl);
    });

    test('Does not rewrite a relative path even when rewrite is enabled', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, '/dashboard', tenantName, true, rootDomain)).toBe('/dashboard');
    });
  });

  describe('Protocol matching', () => {
    test('Rejects an http returnUrl when the request is https', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'http://acme.myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects an https returnUrl when the request is http', () => {
      const req = buildReq('acme.localhost:6001', 'http');

      expect(validateReturnUrl(req, 'https://acme.localhost:6001/home', tenantName, true, 'localhost')).toBeUndefined();
    });

    test('Rejects a root domain returnUrl with a mismatched protocol instead of rewriting it', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'http://myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Rejects a non-http protocol on an allowed host', () => {
      const req = buildReq('acme.myapp.com');

      expect(validateReturnUrl(req, 'ftp://acme.myapp.com/file', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Allows a relative path on an http request', () => {
      const req = buildReq('acme.localhost:6001', 'http');

      expect(validateReturnUrl(req, '/home', tenantName, true, 'localhost')).toBe('/home');
    });
  });

  describe('Request protocol resolution', () => {
    test('Falls back to an https request URL when x-forwarded-proto is missing', () => {
      const req = createMockNextRequest({
        url: 'https://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com' },
      });
      const returnUrl = 'https://acme.myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Falls back to an http request URL when x-forwarded-proto is missing', () => {
      const req = createMockNextRequest({
        url: 'http://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com' },
      });

      expect(validateReturnUrl(req, 'http://acme.myapp.com/dashboard', tenantName, true, rootDomain)).toBe(
        'http://acme.myapp.com/dashboard'
      );
      expect(validateReturnUrl(req, 'https://acme.myapp.com/dashboard', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Falls back to the request URL when x-forwarded-proto is not http or https', () => {
      const req = createMockNextRequest({
        url: 'https://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'ftp' },
      });
      const returnUrl = 'https://acme.myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Uses the first value of a comma-separated x-forwarded-proto', () => {
      const req = createMockNextRequest({
        url: 'http://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https, http' },
      });
      const returnUrl = 'https://acme.myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Accepts x-forwarded-proto regardless of case', () => {
      const req = createMockNextRequest({
        url: 'http://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'HTTPS' },
      });
      const returnUrl = 'https://acme.myapp.com/dashboard';

      expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
    });

    test('Uses the host header rather than the request URL host', () => {
      const req = createMockNextRequest({
        url: 'https://localhost:3000/api/auth/callback',
        headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https' },
      });

      expect(validateReturnUrl(req, 'https://localhost:3000/dashboard', tenantName, true, rootDomain)).toBeUndefined();
    });

    test('Returns undefined when the host header is missing', () => {
      const req = createMockNextRequest({
        url: 'https://localhost:3000/api/auth/callback',
        headers: { 'x-forwarded-proto': 'https' },
      });

      expect(validateReturnUrl(req, '/settings', tenantName, true, rootDomain)).toBeUndefined();
    });
  });
});

describe('toAbsoluteUrl', () => {
  test('Resolves a relative path against the host header and forwarded protocol', () => {
    const req = createMockNextRequest({
      url: 'http://localhost:3000/api/auth/callback',
      headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https' },
    });

    expect(toAbsoluteUrl(req, '/dashboard')).toBe('https://acme.myapp.com/dashboard');
  });

  test('Preserves the query string and hash of a relative path', () => {
    const req = createMockNextRequest({
      url: 'http://localhost:3000/api/auth/callback',
      headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https' },
    });

    expect(toAbsoluteUrl(req, '/settings?tab=1#top')).toBe('https://acme.myapp.com/settings?tab=1#top');
  });

  test('Preserves the port from the host header', () => {
    const req = createMockNextRequest({
      url: 'http://localhost:3000/api/auth/callback',
      headers: { host: 'acme.localhost:6001', 'x-forwarded-proto': 'http' },
    });

    expect(toAbsoluteUrl(req, '/home')).toBe('http://acme.localhost:6001/home');
  });

  test('Returns an absolute URL unchanged', () => {
    const req = createMockNextRequest({
      url: 'http://localhost:3000/api/auth/callback',
      headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https' },
    });

    expect(toAbsoluteUrl(req, 'https://onboarding.otherapp.com/start')).toBe('https://onboarding.otherapp.com/start');
  });

  test('Uses the host header rather than the request URL host', () => {
    const req = createMockNextRequest({
      url: 'https://localhost:3000/api/auth/callback',
      headers: { host: 'acme.myapp.com', 'x-forwarded-proto': 'https' },
    });

    expect(toAbsoluteUrl(req, '/dashboard')).toBe('https://acme.myapp.com/dashboard');
  });

  test('Falls back to the request URL protocol when x-forwarded-proto is missing', () => {
    const req = createMockNextRequest({
      url: 'https://localhost:3000/api/auth/callback',
      headers: { host: 'acme.myapp.com' },
    });

    expect(toAbsoluteUrl(req, '/dashboard')).toBe('https://acme.myapp.com/dashboard');
  });

  test('Falls back to the request URL when the host header is missing', () => {
    const req = createMockNextRequest({
      url: 'https://localhost:3000/api/auth/callback',
      headers: {},
    });

    expect(toAbsoluteUrl(req, '/dashboard')).toBe('https://localhost:3000/dashboard');
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

  test('should not include Domain attribute when domain is not provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    createLoginStateCookie(req, mockResponse, 'state123', 'encrypted-data', false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.not.stringContaining('Domain='));
  });

  test('should include Domain attribute on the new cookie when domain is provided', () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    createLoginStateCookie(req, mockResponse, 'state123', 'encrypted-data', false, '.business.invotastic.com');

    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(`${LOGIN_STATE_COOKIE_PREFIX}state123${LOGIN_STATE_COOKIE_SEPARATOR}`)
    );
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining('Domain=.business.invotastic.com')
    );
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
        `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}${oldestTime}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
      )
    );

    // Should create new cookie
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(`${LOGIN_STATE_COOKIE_PREFIX}state4${LOGIN_STATE_COOKIE_SEPARATOR}`)
    );
  });

  test('should not include Secure flag on the stale cookie removal when dangerouslyDisableSecureCookies is true', () => {
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

    createLoginStateCookie(req, mockResponse, 'state4', 'encrypted-data', true);

    // Stale cookie removal header should end right after Expires, with no Secure flag
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}${oldestTime}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    );
  });

  test('should include Domain attribute on both the stale cookie removal and the new cookie when domain is provided', () => {
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

    createLoginStateCookie(req, mockResponse, 'state4', 'encrypted-data', false, '.business.invotastic.com');

    // Stale cookie removal should carry the Domain attribute
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(
        `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}${oldestTime}=; Path=/; HttpOnly; Domain=.business.invotastic.com; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
      )
    );

    // New cookie should also carry the Domain attribute
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining(`${LOGIN_STATE_COOKIE_PREFIX}state4${LOGIN_STATE_COOKIE_SEPARATOR}`)
    );
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      expect.stringContaining('Domain=.business.invotastic.com')
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

describe('getAuthorizationUrlParams', () => {
  const baseConfig = {
    clientId: CLIENT_ID,
    codeVerifier: 'test-code-verifier',
    redirectUri: 'https://redirect.com',
    scopes: ['openid', 'profile'],
    state: 'test-state',
  };

  test('should include all required OAuth2 parameters', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = await getAuthorizationUrlParams(req, baseConfig);

    expect(result.get('client_id')).toBe(CLIENT_ID);
    expect(result.get('redirect_uri')).toBe('https://redirect.com');
    expect(result.get('response_type')).toBe('code');
    expect(result.get('state')).toBe('test-state');
    expect(result.get('scope')).toBe('openid profile');
    expect(result.get('code_challenge')).toBe('0FLIKahrX7kqxncwhV5WD82lu_wi5GA8FsRSLubaOpU');
    expect(result.get('code_challenge_method')).toBe('S256');
    expect(result.get('nonce')).toBeTruthy();
  });

  test('should not include login_hint or idp_hint when not provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path',
      headers: {},
    });

    const result = await getAuthorizationUrlParams(req, baseConfig);

    expect(result.has('login_hint')).toBe(false);
    expect(result.has('idp_hint')).toBe(false);
  });

  test('should include login_hint when provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?login_hint=user@example.com',
      headers: {},
    });

    const result = await getAuthorizationUrlParams(req, baseConfig);

    expect(result.get('login_hint')).toBe('user@example.com');
  });

  test('should throw error when multiple login_hint params are provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?login_hint=user1@example.com&login_hint=user2@example.com',
      headers: {},
    });

    await expect(getAuthorizationUrlParams(req, baseConfig)).rejects.toThrow(
      'More than one [login_hint] query parameter was encountered'
    );
  });

  test('should include idp_hint when provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?idp_hint=google',
      headers: {},
    });

    const result = await getAuthorizationUrlParams(req, baseConfig);

    expect(result.get('idp_hint')).toBe('google');
  });

  test('should throw error when multiple idp_hint params are provided', async () => {
    const req = createMockNextRequest({
      url: 'https://example.com/path?idp_hint=google&idp_hint=facebook',
      headers: {},
    });

    await expect(getAuthorizationUrlParams(req, baseConfig)).rejects.toThrow(
      'More than one [idp_hint] query parameter was encountered'
    );
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

    // NOTE: no trailing "; " here -- the Secure element is omitted from the array entirely
    // now that clearLoginStateCookie builds its header the same way pages-router-utils does,
    // rather than joining in an empty string for the disabled case.
    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    );
  });

  test('should not include Domain attribute when domain is not provided', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.not.stringContaining('Domain='));
  });

  test('should include Domain attribute when domain is provided', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, false, '.business.invotastic.com');

    expect(mockResponse.headers.append).toHaveBeenCalledWith(
      'Set-Cookie',
      `${cookieName}=; Path=/; HttpOnly; Domain=.business.invotastic.com; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
    );
  });

  test('should handle cookie names with special characters', () => {
    const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test%2Bstate${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;

    clearLoginStateCookie(mockResponse, cookieName, false);

    expect(mockResponse.headers.append).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining(cookieName));
  });
});

describe('createCallbackRedirectResponse', () => {
  const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890`;
  const loginStateCookie = { name: cookieName, value: 'encrypted-value' };

  test('should return a 302 redirect to the given URL with no-cache headers', () => {
    const response = createCallbackRedirectResponse('https://acme.myapp.com/home', loginStateCookie, false);

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://acme.myapp.com/home');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('pragma')).toBe('no-cache');
  });

  test('should clear the login state cookie when it exists', () => {
    const response = createCallbackRedirectResponse('https://acme.myapp.com/home', loginStateCookie, false);

    expect(response.headers.get('set-cookie')).toBe(
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
    );
  });

  test('should not set any cookie when the login state cookie does not exist', () => {
    const response = createCallbackRedirectResponse('https://acme.myapp.com/login', null, false);

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://acme.myapp.com/login');
    expect(response.headers.get('set-cookie')).toBeNull();
  });

  test('should include the Domain attribute when domain is provided', () => {
    const response = createCallbackRedirectResponse(
      'https://acme.myapp.com/home',
      loginStateCookie,
      false,
      '.business.invotastic.com'
    );

    expect(response.headers.get('set-cookie')).toBe(
      `${cookieName}=; Path=/; HttpOnly; Domain=.business.invotastic.com; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure`
    );
  });

  test('should not include the Secure flag when dangerouslyDisableSecureCookies is true', () => {
    const response = createCallbackRedirectResponse('https://acme.myapp.com/home', loginStateCookie, true);

    expect(response.headers.get('set-cookie')).toBe(
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
    );
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
});
