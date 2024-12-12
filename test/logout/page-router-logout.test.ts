/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(
  mockRes: MockResponse<NextApiResponse>,
  expectedOrigin: string,
  redirectUrl: string | null
) {
  const { statusCode } = mockRes;
  expect(statusCode).toEqual(302);
  const location: string = mockRes._getRedirectUrl();
  expect(location).toBeTruthy();
  const locationUrl: URL = new URL(location);
  const { pathname, origin, searchParams } = locationUrl;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/logout');
  expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
  expect(mockRes.getHeader('Pragma')).toBe('no-cache');
  expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
  expect(searchParams.get('redirect_url')).toEqual(redirectUrl);
}

describe('Multi Tenant Logout', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
    wristbandApplicationDomain = 'invotasticb2c-invotastic.dev.wristband.dev';

    // Reset fetch mock before each test
    global.fetch = jest.fn();
    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${wristbandApplicationDomain}/api/v1/oauth2/revoke`) {
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

  describe('Logout Happy Path', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'devs4you',
        refreshToken: 'refreshToken',
        redirectUrl: 'https://google.com',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you-${wristbandApplicationDomain}`, 'https://google.com');
    });

    test('Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, { refreshToken: 'refreshToken' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you-${wristbandApplicationDomain}`, null);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, { refreshToken: 'refreshToken' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`, null);
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, no tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, with tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, no tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `devs4you${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, with tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: `devs4you${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://tenant.custom.com`, null);
    });

    describe('Refresh Token Edge Cases', () => {
      test('No Token to Revoke', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationDomain,
        });

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${rootDomain}/api/auth/logout`,
          headers: { host: rootDomain },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        await wristbandAuth.pageRouter.logout(mockReq, mockRes, { tenantDomainName: 'devs4you' });

        // Validate Redirect response
        validateRedirectResponse(mockRes, `https://devs4you-${wristbandApplicationDomain}`, null);
      });

      test('Revoke Token Failure', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationDomain,
        });

        global.fetch = jest.fn();
        (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
          if (url === `https://${rootDomain}/api/v1/oauth2/revoke`) {
            // Mock the revoke token response
            return Promise.resolve({
              status: 401,
              text: jest.fn().mockResolvedValueOnce(undefined),
            });
          }

          return Promise.reject(new Error('Unexpected URL'));
        });

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          url: `https://${rootDomain}/api/auth/logout`,
          headers: { host: rootDomain },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          refreshToken: 'refreshToken',
          tenantDomainName: 'devs4you',
        });

        // Validate Redirect response
        validateRedirectResponse(mockRes, `https://devs4you-${wristbandApplicationDomain}`, null);
      });
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenantDomainName logout config', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // tenantDomainName logout config is missing, which should redirect to app-level login.
      await wristbandAuth.pageRouter.logout(mockReq, mockRes);

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes);

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      expect(location).toBe(`https://${wristbandApplicationDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to custom app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes);

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual('https://google.com');
      expect(pathname).toEqual('/');
    });

    test('Logout redirect URL precedence over custom application login URL', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to logout redirectUrl.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${rootDomain}/api/auth/logout`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.logout(mockReq, mockRes, { redirectUrl: 'https://yahoo.com' });

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual('https://yahoo.com');
      expect(pathname).toEqual('/');
    });
  });
});
