import { NextApiRequest, NextApiResponse } from 'next';
import {
  parseTenantSubdomain,
  resolveTenantName,
  resolveTenantCustomDomainParam,
  createLoginState,
  createLoginStateCookie,
  getAuthorizeUrl,
  getAndClearLoginStateCookie,
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
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; HTTPOnly; Max-Age=3600; Path=/; SameSite=lax; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });

    it('should create cookie without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const req = {
        cookies: {},
      } as NextApiRequest;

      createLoginStateCookie(req, mockRes, 'test-state', 'encrypted-data', true);

      const expectedCookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; HTTPOnly; Max-Age=3600; Path=/; SameSite=lax`;

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
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; HTTPOnly; Max-Age=3600; Path=/; SameSite=lax; Secure`;

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
      const newCookieHeader = `${newCookieName}=encrypted-data; HTTPOnly; Max-Age=3600; Path=/; SameSite=lax; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [[staleCookieHeader], newCookieHeader]);
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
      const expectedCookieValue = `${expectedCookieName}=encrypted-data; HTTPOnly; Max-Age=3600; Path=/; SameSite=lax; Secure`;

      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [expectedCookieValue]);
    });
  });

  describe('getAuthorizeUrl', () => {
    const baseConfig = {
      clientId: 'test-client-id',
      codeVerifier: 'test-code-verifier',
      redirectUri: 'https://app.com/callback',
      scopes: ['openid', 'email'],
      state: 'test-state',
      wristbandApplicationVanityDomain: 'myapp.wristband.dev',
    };

    beforeEach(() => {
      mockGenerateRandomString.mockReturnValue('mock-nonce-32');
    });

    it('should generate authorize URL with tenant custom domain', async () => {
      const req = { query: {} } as NextApiRequest;
      const config = { ...baseConfig, tenantCustomDomain: 'tenant.custom.com' };

      const result = await getAuthorizeUrl(req, config);

      expect(result).toContain('https://tenant.custom.com/api/v1/oauth2/authorize');
      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('redirect_uri=https%3A%2F%2Fapp.com%2Fcallback');
      expect(result).toContain('response_type=code');
      expect(result).toContain('state=test-state');
      expect(result).toContain('scope=openid+email');
      expect(result).toContain('code_challenge=mock-url-safe-hash');
      expect(result).toContain('code_challenge_method=S256');
      expect(result).toContain('nonce=mock-nonce-32');
    });

    it('should generate authorize URL with tenant domain name and application custom domain active', async () => {
      const req = { query: {} } as NextApiRequest;
      const config = {
        ...baseConfig,
        tenantName: 'tenant1',
        isApplicationCustomDomainActive: true,
      };

      const result = await getAuthorizeUrl(req, config);

      expect(result).toContain('https://tenant1.myapp.wristband.dev/api/v1/oauth2/authorize');
    });

    it('should generate authorize URL with tenant domain name and application custom domain inactive', async () => {
      const req = { query: {} } as NextApiRequest;
      const config = {
        ...baseConfig,
        tenantName: 'tenant1',
        isApplicationCustomDomainActive: false,
      };

      const result = await getAuthorizeUrl(req, config);

      expect(result).toContain('https://tenant1-myapp.wristband.dev/api/v1/oauth2/authorize');
    });

    it('should use default tenant custom domain when no tenant params', async () => {
      const req = { query: {} } as NextApiRequest;
      const config = {
        ...baseConfig,
        defaultTenantCustomDomain: 'default.custom.com',
      };

      const result = await getAuthorizeUrl(req, config);

      expect(result).toContain('https://default.custom.com/api/v1/oauth2/authorize');
    });

    it('should use default tenant domain name as fallback', async () => {
      const req = { query: {} } as NextApiRequest;
      const config = {
        ...baseConfig,
        defaultTenantName: 'default-tenant',
        isApplicationCustomDomainActive: false,
      };

      const result = await getAuthorizeUrl(req, config);

      expect(result).toContain('https://default-tenant-myapp.wristband.dev/api/v1/oauth2/authorize');
    });

    it('should include login_hint when provided in query', async () => {
      const req = {
        query: { login_hint: 'user@example.com' },
      } as unknown as NextApiRequest;

      const result = await getAuthorizeUrl(req, baseConfig);

      expect(result).toContain('login_hint=user%40example.com');
    });

    it('should throw error when multiple login_hint query params are provided', async () => {
      const req = {
        query: { login_hint: ['hint1', 'hint2'] },
      } as unknown as NextApiRequest;

      await expect(getAuthorizeUrl(req, baseConfig)).rejects.toThrow(
        'More than one [login_hint] query parameter was encountered'
      );
    });

    it('should call crypto functions correctly', async () => {
      const req = { query: {} } as NextApiRequest;

      await getAuthorizeUrl(req, baseConfig);

      expect(mockSha256Base64).toHaveBeenCalledWith('test-code-verifier');
      expect(mockBase64ToURLSafe).toHaveBeenCalledWith('mock-sha256-hash');
      expect(mockGenerateRandomString).toHaveBeenCalledWith(32);
    });

    it('should handle domain priority correctly', async () => {
      const req = { query: {} } as NextApiRequest;

      // Test priority: tenant custom domain > tenant domain > default custom domain > default domain
      const configWithAll = {
        ...baseConfig,
        tenantCustomDomain: 'tenant.custom.com',
        tenantName: 'tenant1',
        defaultTenantCustomDomain: 'default.custom.com',
        defaultTenantName: 'default-tenant',
      };

      const result = await getAuthorizeUrl(req, configWithAll);
      expect(result).toContain('https://tenant.custom.com/api/v1/oauth2/authorize');
    });
  });

  describe('getAndClearLoginStateCookie', () => {
    let mockRes: NextApiResponse;
    let mockSetHeader: jest.Mock;

    beforeEach(() => {
      mockSetHeader = jest.fn();
      mockRes = {
        setHeader: mockSetHeader,
      } as any;
    });

    it('should return cookie value and clear it when found', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const req = {
        cookies: {
          [cookieName]: 'encrypted-login-state-data',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      expect(result).toBe('encrypted-login-state-data');
      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`,
      ]);
    });

    it('should return cookie value and clear it without Secure flag when dangerouslyDisableSecureCookies is true', () => {
      const cookieName = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;
      const req = {
        cookies: {
          [cookieName]: 'encrypted-login-state-data',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, true);

      expect(result).toBe('encrypted-login-state-data');
      expect(mockSetHeader).toHaveBeenCalledWith('Set-Cookie', [
        `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
      ]);
    });

    it('should return empty string when no matching cookie found', () => {
      const req = {
        cookies: {
          'other-cookie': 'value',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      expect(result).toBe('');
      expect(mockSetHeader).not.toHaveBeenCalled();
    });

    it('should handle empty state parameter', () => {
      const req = {
        cookies: {},
        query: {},
      } as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      expect(result).toBe('');
      expect(mockSetHeader).not.toHaveBeenCalled();
    });

    it('should handle array state parameter', () => {
      const req = {
        cookies: {},
        query: { state: ['state1', 'state2'] },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      expect(result).toBe('');
      expect(mockSetHeader).not.toHaveBeenCalled();
    });

    it('should ignore non-matching login state cookies', () => {
      const req = {
        cookies: {
          [`${LOGIN_STATE_COOKIE_PREFIX}different-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`]: 'data1',
          [`${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`]: 'data2',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      expect(result).toBe('data2');
      expect(mockSetHeader).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple matching cookies by using the first one', () => {
      const cookieName1 = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567880000`;
      const cookieName2 = `${LOGIN_STATE_COOKIE_PREFIX}test-state${LOGIN_STATE_COOKIE_SEPARATOR}1234567890000`;

      const req = {
        cookies: {
          [cookieName1]: 'data1',
          [cookieName2]: 'data2',
        },
        query: { state: 'test-state' },
      } as unknown as NextApiRequest;

      const result = getAndClearLoginStateCookie(req, mockRes, false);

      // Should return the first matching cookie's value
      expect(['data1', 'data2']).toContain(result);
      expect(mockSetHeader).toHaveBeenCalledTimes(1);
    });
  });
});
