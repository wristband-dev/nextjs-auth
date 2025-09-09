/* eslint-disable no-underscore-dangle */

import { createMocks } from 'node-mocks-http';
import { NextResponse } from 'next/server';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { createMockNextRequest } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(response: NextResponse, expectedOrigin: string, redirectUrl: string | null) {
  const { headers, status } = response;
  const locationUrl: URL = new URL(headers.get('location')!);
  const { pathname, origin, searchParams } = locationUrl;

  expect(status).toBe(302);
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/logout');

  expect(headers.get('Cache-Control')).toBe('no-store');
  expect(headers.get('Pragma')).toBe('no-cache');

  expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
  expect(searchParams.get('redirect_url')).toEqual(redirectUrl);
}

function validateAppLoginRedirect(response: NextResponse, expectedUrl: string) {
  const { headers, status } = response;
  const location = headers.get('location');

  expect(status).toBe(302);
  expect(headers.get('Cache-Control')).toBe('no-store');
  expect(headers.get('Pragma')).toBe('no-cache');

  // Normalize URLs by creating URL objects to handle trailing slashes and encoding
  const actualUrl = new URL(location!);
  const expectedUrlObj = new URL(expectedUrl);

  expect(actualUrl.origin + actualUrl.pathname).toBe(expectedUrlObj.origin + expectedUrlObj.pathname);
  expect(actualUrl.searchParams.toString()).toBe(expectedUrlObj.searchParams.toString());
}

describe('App Router Multi Tenant Logout', () => {
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=ignored.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          tenantCustomDomain: 'priority1.custom.com',
          tenantDomainName: 'ignored',
          refreshToken: 'refreshToken',
          redirectUrl: 'https://example.com',
        });

        validateRedirectResponse(response, 'https://priority1.custom.com', 'https://example.com');
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=ignored.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          tenantDomainName: 'priority2tenant',
          refreshToken: 'refreshToken',
        });

        validateRedirectResponse(response, `https://priority2tenant-${wristbandApplicationVanityDomain}`, null);
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          tenantDomainName: 'priority2tenant',
        });

        validateRedirectResponse(response, `https://priority2tenant.${wristbandApplicationVanityDomain}`, null);
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=priority3.custom.com&tenant_domain=ignored`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          refreshToken: 'refreshToken',
        });

        validateRedirectResponse(response, 'https://priority3.custom.com', null);
      });

      test('tenant_custom_domain query param with redirect URL', async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=priority3.custom.com`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          redirectUrl: 'https://redirect.example.com',
        });

        validateRedirectResponse(response, 'https://priority3.custom.com', 'https://redirect.example.com');
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
            autoConfigureEnabled: false,
          });

          const { req } = createMocks({
            method: 'GET',
            url: `https://priority4a.${parseTenantFromRootDomain}/api/auth/logout`,
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          });
          const mockNextRequest = createMockNextRequest(req);

          const response = await wristbandAuth.appRouter.logout(mockNextRequest);

          validateRedirectResponse(response, `https://priority4a-${wristbandApplicationVanityDomain}`, null);
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
            autoConfigureEnabled: false,
          });

          const { req } = createMocks({
            method: 'GET',
            url: `https://priority4a.${parseTenantFromRootDomain}/api/auth/logout`,
            headers: { host: `priority4a.${parseTenantFromRootDomain}` },
          });
          const mockNextRequest = createMockNextRequest(req);

          const response = await wristbandAuth.appRouter.logout(mockNextRequest);

          validateRedirectResponse(response, `https://priority4a.${wristbandApplicationVanityDomain}`, null);
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
            autoConfigureEnabled: false,
          });

          const { req } = createMocks({
            method: 'GET',
            url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_domain=priority4b`,
            headers: { host: `${parseTenantFromRootDomain}` },
          });
          const mockNextRequest = createMockNextRequest(req);

          const response = await wristbandAuth.appRouter.logout(mockNextRequest);

          validateRedirectResponse(response, `https://priority4b-${wristbandApplicationVanityDomain}`, null);
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
            autoConfigureEnabled: false,
          });

          const { req } = createMocks({
            method: 'GET',
            url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_domain=priority4b`,
            headers: { host: `${parseTenantFromRootDomain}` },
          });
          const mockNextRequest = createMockNextRequest(req);

          const response = await wristbandAuth.appRouter.logout(mockNextRequest);

          validateRedirectResponse(response, `https://priority4b.${wristbandApplicationVanityDomain}`, null);
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest);

        validateAppLoginRedirect(response, `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest);

        validateAppLoginRedirect(response, `${customLoginUrl}?client_id=${CLIENT_ID}`);
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
          autoConfigureEnabled: false,
        });

        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: `${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
          redirectUrl,
        });

        validateAppLoginRedirect(response, redirectUrl);
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
      });

      // Should not call revoke since no refresh token
      expect(global.fetch).not.toHaveBeenCalled();
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'invalid-token',
      });

      // Verify revoke was attempted but failed
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/api/v1/oauth2/revoke'), expect.any(Object));

      // Verify debug message was logged
      expect(consoleSpy).toHaveBeenCalledWith('Revoking the refresh token failed during logout');

      // Verify logout still completes successfully
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);

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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'valid-token',
      });

      // Verify debug message was logged
      expect(consoleSpy).toHaveBeenCalledWith('Revoking the refresh token failed during logout');

      // Verify logout still completes successfully
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);

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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        refreshToken: 'valid-token',
        redirectUrl: 'https://success.com',
      });

      // Verify revoke was called successfully
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/api/v1/oauth2/revoke'), expect.any(Object));

      validateRedirectResponse(
        response,
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
      });

      expect(response.headers.get('Cache-Control')).toBe('no-store');
      expect(response.headers.get('Pragma')).toBe('no-cache');
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
        autoConfigureEnabled: false,
      });

      // Host matches parseTenantFromRootDomain exactly (no subdomain)
      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest);

      // Should fallback to app login since no tenant can be resolved
      validateAppLoginRedirect(response, `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://subdomain.${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=query.custom.com&tenant_domain=query_tenant`,
        headers: { host: `subdomain.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantCustomDomain: 'config.custom.com', // Should win (priority 1)
        tenantDomainName: 'config_tenant',
        refreshToken: 'token',
        redirectUrl: 'https://redirect.com',
      });

      // tenantCustomDomain config should take priority over everything else
      validateRedirectResponse(response, 'https://config.custom.com', 'https://redirect.com');
    });
  });

  describe('Existing Tests Coverage', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'devs4you',
        refreshToken: 'refreshToken',
        redirectUrl: 'https://google.com',
      });

      validateRedirectResponse(response, `https://devs4you-${wristbandApplicationVanityDomain}`, 'https://google.com');
    });

    test('Tenant Subdomains Configuration', async () => {
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, { refreshToken: 'refreshToken' });

      validateRedirectResponse(response, `https://devs4you-${wristbandApplicationVanityDomain}`, null);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, { refreshToken: 'refreshToken' });

      validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`, null);
    });

    test('Unresolved tenantDomainName logout config', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      // tenantDomainName logout config is missing, which should redirect to app-level login.
      const response = await wristbandAuth.appRouter.logout(mockNextRequest);

      validateAppLoginRedirect(response, `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest);

      validateAppLoginRedirect(response, `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest);

      validateAppLoginRedirect(response, `https://google.com?client_id=${CLIENT_ID}`);
    });

    test('Logout redirect URL precedence over custom application login URL', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
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
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, { redirectUrl: 'https://yahoo.com' });

      validateAppLoginRedirect(response, 'https://yahoo.com');
    });
  });

  describe('Multiple Query Parameters Error Handling', () => {
    test('multiple tenant_custom_domain parameters should be handled by utility function', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // This test verifies that the app router utility functions handle multiple query params
      // The actual error handling is done in resolveTenantCustomDomainParam
      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=first.com&tenant_custom_domain=second.com`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // This should throw an error due to multiple tenant_custom_domain parameters
      await expect(wristbandAuth.appRouter.logout(mockNextRequest)).rejects.toThrow(
        'More than one [tenant_custom_domain] query parameter was encountered'
      );
    });

    test('multiple tenant_domain parameters should be handled by utility function', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_domain=first&tenant_domain=second`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // This should throw an error due to multiple tenant_domain parameters
      await expect(wristbandAuth.appRouter.logout(mockNextRequest)).rejects.toThrow(
        'More than one [tenant_domain] query parameter was encountered'
      );
    });
  });

  describe('URL Construction Edge Cases', () => {
    test('empty redirect URL parameter handled correctly', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        redirectUrl: '', // Empty string
      });

      // Empty redirect URL should result in no redirect_url query param
      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('redirect_url')).toBeNull();
    });

    test('special characters in tenant domain name', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'tenant-with-hyphens',
        redirectUrl: 'https://example.com/path?param=value',
      });

      validateRedirectResponse(
        response,
        `https://tenant-with-hyphens-${wristbandApplicationVanityDomain}`,
        'https://example.com/path?param=value'
      );
    });
  });

  describe('State Parameter Tests', () => {
    test('should include state parameter in logout URL when provided', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        state: 'test-state-123',
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBe('test-state-123');
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('should not include state parameter when not provided', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBeNull();
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('should throw error when state exceeds 512 characters', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const longState = 'a'.repeat(513);

      await expect(wristbandAuth.appRouter.logout(mockNextRequest, { state: longState })).rejects.toThrow(
        'The [state] logout config cannot exceed 512 characters.'
      );
    });

    test('should accept state with exactly 512 characters', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const maxState = 'a'.repeat(512);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        state: maxState,
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBe(maxState);
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('should handle state with special characters', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const stateWithSpecialChars = 'state-with-special-chars!@$*()';

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        state: stateWithSpecialChars,
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBe(stateWithSpecialChars);
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('should handle empty string state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        state: '',
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBeNull();
      validateRedirectResponse(response, `https://test-tenant-${wristbandApplicationVanityDomain}`, null);
    });

    test('should include state parameter with all priority domains', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout?tenant_custom_domain=query.custom.com&tenant_domain=query_tenant`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantCustomDomain: 'config.custom.com',
        state: 'priority-test-state',
        redirectUrl: 'https://redirect.com',
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBe('priority-test-state');
      validateRedirectResponse(response, 'https://config.custom.com', 'https://redirect.com');
    });

    test('should include state parameter in fallback scenarios', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        state: 'fallback-state',
      });

      // Since no tenant can be resolved, it should fallback but not include state in the app login URL
      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBeNull();
      validateAppLoginRedirect(response, `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('should handle state parameter with redirect URL precedence', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const redirectUrl = 'https://redirect.priority.com';

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        redirectUrl,
        state: 'ignored-state',
      });

      // When redirectUrl takes precedence over fallback, state should be ignored
      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBeNull();
      validateAppLoginRedirect(response, redirectUrl);
    });

    test('should combine state with redirect URL correctly', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        tenantDomainName: 'test-tenant',
        state: 'combo-state',
        redirectUrl: 'https://example.com/after-logout',
      });

      const locationUrl = new URL(response.headers.get('location')!);
      expect(locationUrl.searchParams.get('state')).toBe('combo-state');
      expect(locationUrl.searchParams.get('redirect_url')).toBe('https://example.com/after-logout');
      validateRedirectResponse(
        response,
        `https://test-tenant-${wristbandApplicationVanityDomain}`,
        'https://example.com/after-logout'
      );
    });
  });
});
