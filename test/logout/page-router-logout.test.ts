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
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';

    // Reset fetch mock before each test
    global.fetch = jest.fn();
    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${wristbandApplicationVanityDomain}/api/v1/oauth2/revoke`) {
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantDomainName: 'devs4you',
        refreshToken: 'refreshToken',
        redirectUrl: 'https://google.com',
      });

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        logoutUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        'https://google.com'
      );
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, { refreshToken: 'refreshToken' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://devs4you-${wristbandApplicationVanityDomain}`, null);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, { refreshToken: 'refreshToken' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://devs4you.${wristbandApplicationVanityDomain}`, null);
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, no tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, without subdomains, with tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, no tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://tenant.custom.com`, null);
    });

    test('Custom Domains with Tenant Custom Domain, with subdomains, with tenantDomainName config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
        tenantCustomDomain: 'tenant.custom.com',
        tenantDomainName: 'global',
        refreshToken: 'refreshToken',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, logoutUrl, `https://tenant.custom.com`, null);
    });

    describe('Refresh Token Edge Cases', () => {
      test('No Token to Revoke', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
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

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, { tenantDomainName: 'devs4you' });

        // Validate Redirect response
        validateRedirectResponse(mockRes, logoutUrl, `https://devs4you-${wristbandApplicationVanityDomain}`, null);
      });

      test('Revoke Token Failure', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
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

        const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, {
          refreshToken: 'refreshToken',
          tenantDomainName: 'devs4you',
        });

        // Validate Redirect response
        validateRedirectResponse(mockRes, logoutUrl, `https://devs4you-${wristbandApplicationVanityDomain}`, null);
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
        wristbandApplicationVanityDomain,
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
      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);
      expect(logoutUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);

      // Validate Redirect response
      expect(logoutUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes);
      expect(logoutUrl).toEqual(`https://google.com?client_id=${CLIENT_ID}`);
    });

    test('Logout redirect URL precedence over custom application login URL', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        wristbandApplicationVanityDomain,
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

      const logoutUrl = await wristbandAuth.pageRouter.logout(mockReq, mockRes, { redirectUrl: 'https://yahoo.com' });

      // Validate Redirect response
      expect(logoutUrl).toEqual('https://yahoo.com');
    });
  });
});
