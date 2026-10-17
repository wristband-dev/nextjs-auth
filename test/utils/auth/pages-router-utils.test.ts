import httpMocks from 'node-mocks-http';
import { NextApiRequest, NextApiResponse } from 'next';
import {
  parseTenantSubdomain,
  resolveTenantName,
  resolveTenantCustomDomainParam,
  resolveReturnUrl,
  validateReturnUrl,
  createLoginStateCookie,
  getAuthorizationUrlParams,
  getLoginStateCookie,
  clearLoginStateCookie,
} from '../../../src/utils/auth/pages-router-utils';
import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../../../src/utils/constants';
import * as authCommonUtils from '../../../src/utils/auth/common-utils';

// Mock common utils
jest.mock('../../../src/utils/auth/common-utils');
const mockGenerateRandomString = authCommonUtils.generateRandomString as jest.MockedFunction<
  typeof authCommonUtils.generateRandomString
>;

describe('Page Router Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGenerateRandomString.mockReturnValue('mock-random-string');
  });

  describe('parseTenantSubdomain', () => {
    it('should extract tenant subdomain when host matches root domain', () => {
      const req = {
        headers: { host: 'tenant1.example.com' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('tenant1');
    });

    it('should return empty string when host does not match root domain', () => {
      const req = {
        headers: { host: 'tenant1.different.com' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('');
    });

    it('should handle nested subdomains correctly', () => {
      const req = {
        headers: { host: 'tenant1.app.example.com' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'app.example.com');
      expect(result).toBe('tenant1');
    });

    it('should return empty string for exact domain match', () => {
      const req = {
        headers: { host: 'example.com' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('');
    });

    it('should strip port from host header', () => {
      const req = {
        headers: { host: 'tenant1.example.com:3000' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('tenant1');
    });

    it('should strip port from host header with complex subdomain', () => {
      const req = {
        headers: { host: 'my-tenant-123.example.com:8080' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('my-tenant-123');
    });

    it('should handle host without port (no change)', () => {
      const req = {
        headers: { host: 'tenant1.example.com' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('tenant1');
    });

    it('should return empty string when root domain does not match after stripping port', () => {
      const req = {
        headers: { host: 'tenant1.otherdomain.com:3000' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('');
    });

    it('should strip port when accessing root domain directly', () => {
      const req = {
        headers: { host: 'example.com:3000' },
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('');
    });

    it('should return empty string when host header is missing', () => {
      const req = {
        headers: {},
      } as NextApiRequest;

      const result = parseTenantSubdomain(req, 'example.com');
      expect(result).toBe('');
    });
  });

  describe('resolveTenantName', () => {
    it('should return tenant subdomain when parseTenantFromRootDomain is provided', () => {
      const req = {
        headers: { host: 'tenant1.example.com' },
        query: { tenant_name: 'query-tenant' },
      } as unknown as NextApiRequest;

      const result = resolveTenantName(req, 'example.com');
      expect(result).toBe('tenant1');
    });

    it('should return empty string when no subdomain found and parseTenantFromRootDomain is provided', () => {
      const req = {
        headers: { host: 'example.com' },
        query: { tenant_name: 'query-tenant' },
      } as unknown as NextApiRequest;

      const result = resolveTenantName(req, 'example.com');
      expect(result).toBe('');
    });

    it('should return tenant_name query param when parseTenantFromRootDomain is empty', () => {
      const req = {
        headers: { host: 'tenant1.example.com' },
        query: { tenant_name: 'query-tenant' },
      } as unknown as NextApiRequest;

      const result = resolveTenantName(req, '');
      expect(result).toBe('query-tenant');
    });

    it('should return empty string when no tenant_name query param and no parseTenantFromRootDomain', () => {
      const req = {
        headers: { host: 'example.com' },
        query: {},
      } as NextApiRequest;

      const result = resolveTenantName(req, '');
      expect(result).toBe('');
    });

    it('should throw error when multiple tenant_name query params are provided', () => {
      const req = {
        headers: { host: 'example.com' },
        query: { tenant_name: ['tenant1', 'tenant2'] },
      } as unknown as NextApiRequest;

      expect(() => {
        return resolveTenantName(req, '');
      }).toThrow('More than one [tenant_name] query parameter was encountered');
    });

    it('should strip port when resolving tenant from subdomain', () => {
      const req = {
        headers: { host: 'tenant1.example.com:3000' },
        query: {},
      } as NextApiRequest;

      const result = resolveTenantName(req, 'example.com');
      expect(result).toBe('tenant1');
    });

    it('should prioritize subdomain over query param even with port in host', () => {
      const req = {
        headers: { host: 'subdomain-tenant.example.com:3000' },
        query: { tenant_name: 'query-tenant' },
      } as unknown as NextApiRequest;

      const result = resolveTenantName(req, 'example.com');
      expect(result).toBe('subdomain-tenant');
    });

    it('should return empty string when subdomain not found even with port', () => {
      const req = {
        headers: { host: 'example.com:3000' },
        query: { tenant_name: 'query-tenant' },
      } as unknown as NextApiRequest;

      const result = resolveTenantName(req, 'example.com');
      expect(result).toBe('');
    });
  });

  describe('resolveTenantCustomDomainParam', () => {
    it('should return tenant_custom_domain query param', () => {
      const req = {
        query: { tenant_custom_domain: 'custom.domain.com' },
      } as unknown as NextApiRequest;

      const result = resolveTenantCustomDomainParam(req);
      expect(result).toBe('custom.domain.com');
    });

    it('should return empty string when no tenant_custom_domain query param', () => {
      const req = {
        query: {},
      } as NextApiRequest;

      const result = resolveTenantCustomDomainParam(req);
      expect(result).toBe('');
    });

    it('should throw error when multiple tenant_custom_domain query params are provided', () => {
      const req = {
        query: { tenant_custom_domain: ['custom1.com', 'custom2.com'] },
      } as unknown as NextApiRequest;

      expect(() => {
        return resolveTenantCustomDomainParam(req);
      }).toThrow('More than one [tenant_custom_domain] query parameter was encountered');
    });
  });

  describe('resolveReturnUrl', () => {
    test('Returns undefined when no return URL is provided anywhere', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveReturnUrl(req)).toBeUndefined();
    });

    test('Returns the return_url query parameter when no config is provided', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/dashboard' },
      }) as any;

      expect(resolveReturnUrl(req)).toBe('https://example.com/dashboard');
    });

    test('Returns LoginConfig.returnUrl when no query parameter is present', () => {
      const req = httpMocks.createRequest() as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('LoginConfig.returnUrl takes precedence over the return_url query parameter', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });

    test('Falls back to the query parameter when LoginConfig.returnUrl is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: 'https://example.com/query' },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: '' })).toBe('https://example.com/query');
    });

    test('Returns undefined when the return_url query parameter is an empty string', () => {
      const req = httpMocks.createRequest({
        query: { return_url: '' },
      }) as any;

      expect(resolveReturnUrl(req)).toBeUndefined();
    });

    test('Throws error for multiple return_url query parameters', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(() => {
        return resolveReturnUrl(req);
      }).toThrow('More than one [return_url] query parameter was encountered');
    });

    test('Does not throw for multiple return_url query parameters when LoginConfig.returnUrl is set', () => {
      const req = httpMocks.createRequest({
        query: { return_url: ['url1', 'url2'] },
      }) as any;

      expect(resolveReturnUrl(req, { returnUrl: 'https://example.com/config' })).toBe('https://example.com/config');
    });
  });

  describe('validateReturnUrl', () => {
    // Minimal request mock exposing only what validateReturnUrl reads.
    const buildReq = (host: string, protocol: string = 'https') => {
      return {
        headers: { host, 'x-forwarded-proto': protocol },
      } as unknown as NextApiRequest;
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

        expect(
          validateReturnUrl(req, 'https://other.myapp.com/dashboard', tenantName, true, rootDomain)
        ).toBeUndefined();
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

        expect(
          validateReturnUrl(req, 'https://acme.myapp.com@evil.com/', tenantName, true, rootDomain)
        ).toBeUndefined();
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

        expect(
          validateReturnUrl(req, 'https://acme.localhost:6001/home', tenantName, true, 'localhost')
        ).toBeUndefined();
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
      // Request mock with raw headers and socket, for exercising how the protocol is resolved.
      const buildRawReq = (headers: Record<string, string | string[]>, encrypted?: boolean) => {
        return {
          headers,
          socket: encrypted === undefined ? {} : { encrypted },
        } as unknown as NextApiRequest;
      };

      test('Uses https from a TLS socket when x-forwarded-proto is missing', () => {
        const req = buildRawReq({ host: 'acme.myapp.com' }, true);
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Uses http from a plain socket when x-forwarded-proto is missing', () => {
        const req = buildRawReq({ host: 'acme.myapp.com' });

        expect(validateReturnUrl(req, 'http://acme.myapp.com/dashboard', tenantName, true, rootDomain)).toBe(
          'http://acme.myapp.com/dashboard'
        );
        expect(
          validateReturnUrl(req, 'https://acme.myapp.com/dashboard', tenantName, true, rootDomain)
        ).toBeUndefined();
      });

      test('Falls back to the socket when x-forwarded-proto is not http or https', () => {
        const req = buildRawReq({ host: 'acme.myapp.com', 'x-forwarded-proto': 'ftp' }, true);
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Falls back to the socket when x-forwarded-proto is an array', () => {
        const req = buildRawReq({ host: 'acme.myapp.com', 'x-forwarded-proto': ['https', 'http'] });

        expect(
          validateReturnUrl(req, 'https://acme.myapp.com/dashboard', tenantName, true, rootDomain)
        ).toBeUndefined();
      });

      test('Uses the first value of a comma-separated x-forwarded-proto', () => {
        const req = buildRawReq({ host: 'acme.myapp.com', 'x-forwarded-proto': 'https, http' });
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Accepts x-forwarded-proto regardless of case', () => {
        const req = buildRawReq({ host: 'acme.myapp.com', 'x-forwarded-proto': 'HTTPS' });
        const returnUrl = 'https://acme.myapp.com/dashboard';

        expect(validateReturnUrl(req, returnUrl, tenantName, true, rootDomain)).toBe(returnUrl);
      });

      test('Returns undefined when the host header is missing', () => {
        const req = buildRawReq({ 'x-forwarded-proto': 'https' });

        expect(validateReturnUrl(req, '/settings', tenantName, true, rootDomain)).toBeUndefined();
      });
    });
  });

  describe('createLoginStateCookie', () => {
    let mockRes: NextApiResponse;
    let mockSetHeader: jest.Mock;

    beforeEach(() => {
      mockSetHeader = jest.fn();
      mockRes = {
        setHeader: mockSetHeader,
      } as any;

      // Mock Date.now()
      jest.spyOn(Date, 'now').mockReturnValue(1234567890000);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should create new login state cookie when no existing cookies', () => {
      const req = {
        cookies: {},
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false);

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should create cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const req = {
        cookies: {},
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', true);

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should keep existing cookies when less than 3', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`]: 'data1',
          [`${LOGIN_STATE_COOKIE_PREFIX}state2${LOGIN_STATE_COOKIE_SEPARATOR}1234567885000`]: 'data2',
        },
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false);

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should remove oldest cookie when 3 or more exist', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`]: 'data1', // oldest
          [`${LOGIN_STATE_COOKIE_PREFIX}state2${LOGIN_STATE_COOKIE_SEPARATOR}1234567885000`]: 'data2',
          [`${LOGIN_STATE_COOKIE_PREFIX}state3${LOGIN_STATE_COOKIE_SEPARATOR}1234567888000`]: 'data3',
        },
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false);

      const oldestCookieName = `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`;
      const newCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      const staleCookieHeader = `${oldestCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`;
      const newCookieHeader = `${newCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [staleCookieHeader, newCookieHeader]);
    });

    it('should remove oldest cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`]: 'data1', // oldest
          [`${LOGIN_STATE_COOKIE_PREFIX}state2${LOGIN_STATE_COOKIE_SEPARATOR}1234567885000`]: 'data2',
          [`${LOGIN_STATE_COOKIE_PREFIX}state3${LOGIN_STATE_COOKIE_SEPARATOR}1234567888000`]: 'data3',
        },
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', true);

      const oldestCookieName = `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`;
      const newCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      const staleCookieHeader = `${oldestCookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
      const newCookieHeader = `${newCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [staleCookieHeader, newCookieHeader]);
    });

    it('should handle non-login-state cookies correctly', () => {
      const req = {
        cookies: {
          'regular-cookie': 'value',
          [`${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`]: 'data1',
          'another-cookie': 'value2',
        },
      } as unknown as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false);

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should include Domain attribute when domain is provided', () => {
      const req = {
        cookies: {},
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false, '.business.invotastic.com');

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; Path=/; HttpOnly; Domain=.business.invotastic.com; SameSite=Lax; Max-Age=3600; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should include Domain attribute on the stale cookie cleared when 3 or more exist', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`]: 'data1', // oldest
          [`${LOGIN_STATE_COOKIE_PREFIX}state2${LOGIN_STATE_COOKIE_SEPARATOR}1234567885000`]: 'data2',
          [`${LOGIN_STATE_COOKIE_PREFIX}state3${LOGIN_STATE_COOKIE_SEPARATOR}1234567888000`]: 'data3',
        },
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', false, '.business.invotastic.com');

      const oldestCookieName = `${LOGIN_STATE_COOKIE_PREFIX}state1${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`;
      const staleCookieHeader = `${oldestCookieName}=; Path=/; HttpOnly; Domain=.business.invotastic.com; SameSite=Lax; Max-Age=0; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        staleCookieHeader,
        expect.stringContaining('Domain=.business.invotastic.com'),
      ]);
    });
  });

  describe('getAuthorizationUrlParams', () => {
    const baseConfig = {
      clientId: 'test-client-id',
      codeVerifier: 'test-code-verifier',
      redirectUri: 'https://app.com/callback',
      scopes: ['openid', 'email'],
      state: 'test-state',
    };

    beforeEach(() => {
      mockGenerateRandomString.mockReturnValue('mock-nonce-32');
    });

    it('should include all required OAuth2 parameters', async () => {
      const req = { query: {} } as NextApiRequest;

      const params = await getAuthorizationUrlParams(req, baseConfig);

      expect(params.get('client_id')).toBe('test-client-id');
      expect(params.get('redirect_uri')).toBe('https://app.com/callback');
      expect(params.get('response_type')).toBe('code');
      expect(params.get('state')).toBe('test-state');
      expect(params.get('scope')).toBe('openid email');
      expect(params.get('code_challenge')).toBe('0FLIKahrX7kqxncwhV5WD82lu_wi5GA8FsRSLubaOpU');
      expect(params.get('code_challenge_method')).toBe('S256');
      expect(params.get('nonce')).toBe('mock-nonce-32');
    });

    it('should include login_hint when provided in query', async () => {
      const req = {
        query: { login_hint: 'user@example.com' },
      } as unknown as NextApiRequest;

      const params = await getAuthorizationUrlParams(req, baseConfig);

      expect(params.get('login_hint')).toBe('user@example.com');
    });

    it('should throw error when multiple login_hint query params are provided', async () => {
      const req = {
        query: { login_hint: ['hint1', 'hint2'] },
      } as unknown as NextApiRequest;

      await expect(getAuthorizationUrlParams(req, baseConfig)).rejects.toThrow(
        'More than one [login_hint] query parameter was encountered'
      );
    });

    it('should include idp_hint when provided in query', async () => {
      const req = {
        query: { idp_hint: 'google' },
      } as unknown as NextApiRequest;

      const params = await getAuthorizationUrlParams(req, baseConfig);

      expect(params.get('idp_hint')).toBe('google');
    });

    it('should throw error when multiple idp_hint query params are provided', async () => {
      const req = {
        query: { idp_hint: ['google', 'facebook'] },
      } as unknown as NextApiRequest;

      await expect(getAuthorizationUrlParams(req, baseConfig)).rejects.toThrow(
        'More than one [idp_hint] query parameter was encountered'
      );
    });

    it('should generate the nonce with 32 bytes', async () => {
      const req = { query: {} } as NextApiRequest;

      await getAuthorizationUrlParams(req, baseConfig);

      expect(mockGenerateRandomString).toHaveBeenCalledWith(32);
    });
  });

  describe('getLoginStateCookie', () => {
    it('should return cookie name and value when found', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const req = {
        cookies: {
          [cookieName]: 'encrypted-login-state-data',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(result).toEqual({ cookieName, loginStateCookie: 'encrypted-login-state-data' });
    });

    it('should return empty strings when no matching cookie found', () => {
      const req = {
        cookies: {
          'other-cookie': 'value',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(result).toEqual({ cookieName: '', loginStateCookie: '' });
    });

    it('should return empty strings when state query param is missing', () => {
      const req = {
        cookies: {},
        query: {},
      } as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(result).toEqual({ cookieName: '', loginStateCookie: '' });
    });

    it('should return empty strings when state query param is an array', () => {
      const req = {
        cookies: {},
        query: { state: ['state1', 'state2'] },
      } as unknown as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(result).toEqual({ cookieName: '', loginStateCookie: '' });
    });

    it('should ignore non-matching login state cookies', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}different-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`]: 'data1',
          [`${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`]: 'data2',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(result.loginStateCookie).toBe('data2');
    });

    it('should return the first matching cookie when multiple match', () => {
      const cookieName1 = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`;
      const cookieName2 = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      const req = {
        cookies: {
          [cookieName1]: 'data1',
          [cookieName2]: 'data2',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getLoginStateCookie(req);

      expect(['data1', 'data2']).toContain(result.loginStateCookie);
    });
  });

  describe('clearLoginStateCookie', () => {
    let mockRes: NextApiResponse;
    let mockSetHeader: jest.Mock;

    beforeEach(() => {
      mockSetHeader = jest.fn();
      mockRes = {
        setHeader: mockSetHeader,
      } as any;
    });

    it('should clear the cookie with Secure flag by default', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      clearLoginStateCookie(mockRes, cookieName, false);

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        `${cookieName}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`,
      ]);
    });

    it('should clear the cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      clearLoginStateCookie(mockRes, cookieName, true);

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        `${cookieName}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`,
      ]);
    });

    it('should include Domain attribute when domain is provided', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      clearLoginStateCookie(mockRes, cookieName, false, '.business.invotastic.com');

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        `${cookieName}=; HttpOnly; Domain=.business.invotastic.com; Path=/; Max-Age=0; SameSite=Lax; Secure`,
      ]);
    });
  });
});
