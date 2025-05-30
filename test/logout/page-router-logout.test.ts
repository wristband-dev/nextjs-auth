/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(
  mockRes: MockResponse<NextApiResponse>,
  logoutUrl: string,
  expectedOrigin: string,
  redirectUrl: string | null
) {
  expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
  expect(mockRes.getHeader('Pragma')).toBe('no-cache');

  const url = new URL(logoutUrl);
  const { pathname, origin, searchParams } = url;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/logout');
  expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
  expect(searchParams.get('redirect_url')).toEqual(redirectUrl);
}

describe('Multi Tenant Logout', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';

    // Reset fetch mock before each test
    global.fetch = jest.fn();
    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url.includes('/api/v1/oauth2/revoke')) {
        // Mock the revoke token response
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(undefined),
        });
      }

      return Promise.reject(new Error('Unexpected URL'));
    });
  });

  describe('Domain Resolution Priority Tests', () => {
    describe('Priority 1: logoutConfig.tenantCustomDomain (highest priority)', () => {
      test('tenantCustomDomain config overrides everything else', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=ignored.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          tenantCustomDomain: 'priority1.custom.com',
          tenantDomainName: 'ignored',
          refreshToken: 'refreshToken',
          redirectUrl: 'https://example.com',
        });

        validateRedirectResponse(mockRes, logoutUrl, 'https://priority1.custom.com', 'https://example.com');
      });
    });

    describe('Priority 2: logoutConfig.tenantDomainName', () => {
      test('tenantDomainName config with default separator', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=ignored.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          tenantDomainName: 'priority2tenant',
          refreshToken: 'refreshToken',
        });

        validateRedirectResponse(
          mockRes,
          logoutUrl,
          `https://priority2tenant-${wristbandApplicationVanityDomain}`,
          null
        );
      });

      test('tenantDomainName config with custom domain separator', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          isApplicationCustomDomainActive: true,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          tenantDomainName: 'priority2tenant',
        });

        validateRedirectResponse(
          mockRes,
          logoutUrl,
          `https://priority2tenant.${wristbandApplicationVanityDomain}`,
          null
        );
      });
    });

    describe('Priority 3: tenant_custom_domain query parameter', () => {
      test('tenant_custom_domain query param used when no config overrides', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=priority3.custom.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          refreshToken: 'refreshToken',
        });

        validateRedirectResponse(mockRes, logoutUrl, 'https://priority3.custom.com', null);
      });

      test('tenant_custom_domain query param with redirect URL', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=priority3.custom.com`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          redirectUrl: 'https://redirect.example.com',
        });

        validateRedirectResponse(mockRes, logoutUrl, 'https://priority3.custom.com', 'https://redirect.example.com');
      });
    });

    describe('Priority 4: tenant domain from request (subdomain or query param)', () => {
      describe('4a: Tenant subdomains enabled', () => {
        test('tenant subdomain from host header', async () => {
          parseTenantFromRootDomain = 'business.invotastic.com';
          loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
          redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

          wristbandAuth = createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl,
            redirectUri,
            parseTenantFromRootDomain,
            wristbandApplicationVanityDomain,
          });

          const { req, res } = createMocks({
            method: 'GET',
            url: `https://priority4a.${parseTenantFromRootDomain}/api/auth/logout`,
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          });
          const mockReq = req as unknown as NextApiRequest;
          const mockRes = res as unknown as MockResponse<NextApiResponse>;

          const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

          validateRedirectResponse(mockRes, logoutUrl, `https://priority4a-${wristbandApplicationVanityDomain}`, null);
        });

        test('tenant subdomain with custom domain separator', async () => {
          parseTenantFromRootDomain = 'business.invotastic.com';
          loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
          redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

          wristbandAuth = createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl,
            redirectUri,
            parseTenantFromRootDomain,
            isApplicationCustomDomainActive: true,
            wristbandApplicationVanityDomain,
          });

          const { req, res } = createMocks({
            method: 'GET',
            url: `https://priority4a.${parseTenantFromRootDomain}/api/auth/logout`,
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          });
          const mockReq = req as unknown as NextApiRequest;
          const mockRes = res as unknown as MockResponse<NextApiResponse>;

          const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

          validateRedirectResponse(mockRes, logoutUrl, `https://priority4a.${wristbandApplicationVanityDomain}`, null);
        });
      });

      describe('4b: Tenant subdomains disabled - query param', () => {
        test('tenant_domain query parameter with default separator', async () => {
          wristbandAuth = createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl,
            redirectUri,
            wristbandApplicationVanityDomain,
          });

          const { req, res } = createMocks({
            method: 'GET',
            url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_domain=priority4b`,
            headers: { host: `${parseTenantFromRootDomain}` },
          });
          const mockReq = req as unknown as NextApiRequest;
          const mockRes = res as unknown as MockResponse<NextApiResponse>;

          const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

          validateRedirectResponse(mockRes, logoutUrl, `https://priority4b-${wristbandApplicationVanityDomain}`, null);
        });

        test('tenant_domain query parameter with custom domain separator', async () => {
          wristbandAuth = createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl,
            redirectUri,
            wristbandApplicationVanityDomain,
            isApplicationCustomDomainActive: true,
          });

          const { req, res } = createMocks({
            method: 'GET',
            url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_domain=priority4b`,
            headers: { host: `${parseTenantFromRootDomain}` },
          });
          const mockReq = req as unknown as NextApiRequest;
          const mockRes = res as unknown as MockResponse<NextApiResponse>;

          const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

          validateRedirectResponse(mockRes, logoutUrl, `https://priority4b.${wristbandApplicationVanityDomain}`, null);
        });
      });
    });

    describe('Priority 5: Fallback scenarios', () => {
      test('fallback to default application login URL', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

        expect(logoutUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      });

      test('fallback to custom application login URL', async () => {
        const customLoginUrl = 'https://custom.login.com';
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          customApplicationLoginPageUrl: customLoginUrl,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

        expect(logoutUrl).toBe(`${customLoginUrl}?client_id=${CLIENT_ID}`);
      });

      test('fallback with redirect URL takes precedence over login URLs', async () => {
        const customLoginUrl = 'https://custom.login.com';
        const redirectUrl = 'https://redirect.priority.com';

        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          customApplicationLoginPageUrl: customLoginUrl,
        });

        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          redirectUrl,
        });

        expect(logoutUrl).toBe(redirectUrl);
      });
    });
  });

  describe('Refresh Token Edge Cases', () => {
    test('no refresh token provided', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'test-tenant',
      });

      // Should not call revoke since no refresh token
      expect(global.fetch).not.toHaveBeenCalled();
      validateRedirectResponse(mockRes, logoutUrl, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('refresh token revocation fails but logout continues', async () => {
      // Mock failed revoke response
      (global.fetch as jest.Mock).mockImplementationOnce(() => {
        return Promise.resolve({
          ok: false,
          status: 401,
          text: jest.fn().mockResolvedValueOnce('Unauthorized'),
        });
      });

      // Mock console.debug to verify it's called
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'invalid-token',
      });

      // Verify revoke was attempted but failed
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/api/v1/oauth2/revoke'), expect.any(Object));

      // Verify debug message was logged
      expect(consoleSpy).toHaveBeenCalledWith('Revoking the refresh token failed during logout');

      // Verify logout still completes successfully
      validateRedirectResponse(mockRes, logoutUrl, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);

      consoleSpy.mockRestore();
    });

    test('refresh token revocation network error but logout continues', async () => {
      // Mock network error
      (global.fetch as jest.Mock).mockImplementationOnce(() => {
        return Promise.reject(new Error('Network error'));
      });

      // Mock console.debug to verify it's called
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'valid-token',
      });

      // Verify debug message was logged
      expect(consoleSpy).toHaveBeenCalledWith('Revoking the refresh token failed during logout');

      // Verify logout still completes successfully
      validateRedirectResponse(mockRes, logoutUrl, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);

      consoleSpy.mockRestore();
    });

    test('successful refresh token revocation', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'valid-token',
        redirectUrl: 'https://success.com',
      });

      // Verify revoke was called successfully
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/api/v1/oauth2/revoke'), expect.any(Object));

      validateRedirectResponse(
        mockRes,
        logoutUrl,
        `https://test-tenant-${wristbandApplicationVanityDomain}`,
        'https://success.com'
      );
    });
  });

  describe('Response Headers', () => {
    test('cache control headers are always set', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'test-tenant',
      });

      expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
      expect(mockRes.getHeader('Pragma')).toBe('no-cache');
    });
  });

  describe('Edge Cases and Error Scenarios', () => {
    test('empty tenant subdomain resolves correctly', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
      });

      // Host matches parseTenantFromRootDomain exactly (no subdomain)
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

      // Should fallback to app login since no tenant can be resolved
      expect(logoutUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('all config options provided - priority order maintained', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://should.be.ignored.com',
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `https://subdomain.${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=query.custom.com&tenant_domain=query_tenant`,
        headers: { host: `subdomain.${parseTenantFromRootDomain}` },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'config.custom.com', // Should win (priority 1)
        tenantDomainName: 'config_tenant',
        refreshToken: 'token',
        redirectUrl: 'https://redirect.com',
      });

      // tenantCustomDomain config should take priority over everything else
      validateRedirectResponse(mockRes, logoutUrl, 'https://config.custom.com', 'https://redirect.com');
    });
  });
});
