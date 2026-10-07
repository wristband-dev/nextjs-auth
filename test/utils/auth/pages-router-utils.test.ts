import { NextApiRequest, NextApiResponse } from 'next';
import {
  parseTenantSubdomain,
  resolveTenantName,
  resolveTenantCustomDomainParam,
  createLoginState,
  createLoginStateCookie,
  getAuthorizationUrlParams,
  getLoginStateCookie,
  clearLoginStateCookie,
} from '../../../src/utils/auth/pages-router-utils';
import { LoginStateMapConfig } from '../../../src/types';
import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../../../src/utils/constants';
import * as commonUtils from '../../../src/utils/crypto';

// Mock common utils
jest.mock('../../../src/utils/crypto');
const mockGenerateRandomString = commonUtils.generateRandomString as jest.MockedFunction<
  typeof commonUtils.generateRandomString
>;
const mockSha256Base64 = commonUtils.sha256Base64 as jest.MockedFunction<typeof commonUtils.sha256Base64>;
const mockBase64ToURLSafe = commonUtils.base64ToURLSafe as jest.MockedFunction<typeof commonUtils.base64ToURLSafe>;

describe('Page Router Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGenerateRandomString.mockReturnValue('mock-random-string');
    mockSha256Base64.mockResolvedValue('mock-sha256-hash');
    mockBase64ToURLSafe.mockReturnValue('mock-url-safe-hash');
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

  describe('createLoginState', () => {
    beforeEach(() => {
      mockGenerateRandomString.mockReset();
      mockGenerateRandomString
        .mockReturnValueOnce('mock-state-32')
        .mockReturnValueOnce('mock-code-verifier-32')
        .mockReturnValue('mock-nonce-32');
    });

    it('should create basic login state', () => {
      const req = {
        query: {},
      } as NextApiRequest;

      const result = createLoginState(req, 'https://app.com/callback');

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
      });
    });

    it('should include return_url from query params', () => {
      const req = {
        query: { return_url: 'https://app.com/dashboard' },
      } as unknown as NextApiRequest;

      const result = createLoginState(req, 'https://app.com/callback');

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
        returnUrl: 'https://app.com/dashboard',
      });
    });

    it('should include returnUrl from config over query param', () => {
      const req = {
        query: { return_url: 'https://app.com/dashboard' },
      } as unknown as NextApiRequest;

      const config: LoginStateMapConfig = {
        returnUrl: 'https://app.com/admin',
      };

      const result = createLoginState(req, 'https://app.com/callback', config);

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
        returnUrl: 'https://app.com/admin',
      });
    });

    it('should include customState from config', () => {
      const req = {
        query: {},
      } as NextApiRequest;

      const config: LoginStateMapConfig = {
        customState: { userId: '123', tenantId: 'tenant-456' },
      };

      const result = createLoginState(req, 'https://app.com/callback', config);

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
        customState: { userId: '123', tenantId: 'tenant-456' },
      });
    });

    it('should include both returnUrl and customState', () => {
      const req = {
        query: { return_url: 'https://app.com/dashboard' },
      } as unknown as NextApiRequest;

      const config: LoginStateMapConfig = {
        returnUrl: 'https://app.com/admin',
        customState: { role: 'admin' },
      };

      const result = createLoginState(req, 'https://app.com/callback', config);

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
        returnUrl: 'https://app.com/admin',
        customState: { role: 'admin' },
      });
    });

    it('should throw error when multiple return_url query params are provided', () => {
      const req = {
        query: { return_url: ['url1', 'url2'] },
      } as unknown as NextApiRequest;

      expect(() => {
        return createLoginState(req, 'https://app.com/callback');
      }).toThrow('More than one [return_url] query parameter was encountered');
    });

    it('should not include customState when empty object', () => {
      const req = { query: {} } as NextApiRequest;

      const config: LoginStateMapConfig = {
        customState: {},
      };

      const result = createLoginState(req, 'https://app.com/callback', config);

      expect(result).toEqual({
        state: 'mock-state-32',
        codeVerifier: 'mock-code-verifier-32',
        redirectUri: 'https://app.com/callback',
      });
      expect(result).not.toHaveProperty('customState');
    });

    it('should call generateRandomString with correct parameters', () => {
      const req = { query: {} } as NextApiRequest;

      createLoginState(req, 'https://app.com/callback');

      expect(mockGenerateRandomString).toHaveBeenCalledTimes(2);
      expect(mockGenerateRandomString).toHaveBeenNthCalledWith(1, 32);
      expect(mockGenerateRandomString).toHaveBeenNthCalledWith(2, 32);
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
      expect(params.get('code_challenge')).toBe('mock-url-safe-hash');
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

    it('should call crypto functions correctly', async () => {
      const req = { query: {} } as NextApiRequest;

      await getAuthorizationUrlParams(req, baseConfig);

      expect(mockSha256Base64).toHaveBeenCalledWith('test-code-verifier');
      expect(mockBase64ToURLSafe).toHaveBeenCalledWith('mock-sha256-hash');
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
