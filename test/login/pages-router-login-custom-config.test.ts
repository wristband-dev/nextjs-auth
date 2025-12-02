/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import { createMocks, MockResponse } from 'node-mocks-http';

import { NextApiRequest, NextApiResponse } from 'next';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState } from '../../src/utils/crypto';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const CUSTOM_SCOPES = ['openid', 'roles'];
const CUSTOM_STATE = { test: 'abc' };
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(authorizeUrl: string, expectedOrigin: string) {
  const locationUrl: URL = new URL(authorizeUrl);
  const { pathname, origin } = locationUrl;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/oauth2/authorize');
}

async function validateLoginStateCookie(mockRes: MockResponse<NextApiResponse>) {
  const setCookieHeaders = mockRes.getHeader('Set-Cookie');
  expect(setCookieHeaders).toBeTruthy();
  expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

  const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
  const loginStateCookie = parsedCookies[0];
  const cookieKey: string = loginStateCookie.name;
  expect(cookieKey).toBeTruthy();
  const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
  expect(keyParts).toHaveLength(3);
  expect(keyParts[0]).toEqual('login');
  expect(keyParts[1]).toBeTruthy();
  expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

  expect(loginStateCookie.httponly).toBe(true);
  expect(loginStateCookie['max-age']).toBe('3600');
  expect(loginStateCookie.path).toBe('/');
  expect(loginStateCookie.samesite).toBe('lax');
  expect(loginStateCookie.secure).toBe(true);

  const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
  expect(loginState.state).toEqual(keyParts[1]);
  expect(loginState.customState).toBeUndefined();
}

describe('Custom Login Configurations', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'business.invotastic.com';
    wristbandApplicationVanityDomain = 'auth.invotastic.com';
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Basic tests with %s placeholder', (placeholderName, placeholder) => {
      beforeEach(() => {
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
      });

      test(`Custom Scopes Configuration at the Class Level using ${placeholderName}`, async () => {
        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          isApplicationCustomDomainActive: true,
          wristbandApplicationVanityDomain,
          scopes: CUSTOM_SCOPES,
          autoConfigureEnabled: false,
        });

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

        // Validate Redirect response
        const locationUrl: URL = new URL(authorizeUrl);
        const { pathname, origin, searchParams } = locationUrl;
        expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
        expect(pathname).toEqual('/api/v1/oauth2/authorize');

        // Validate query params of Authorize URL
        expect(searchParams.get('scope')).toEqual(CUSTOM_SCOPES.join(' '));

        // Validate login state cookie
        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        expect(setCookieHeaders).toBeTruthy();
        expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];
        const cookieKey: string = loginStateCookie.name;
        expect(cookieKey).toBeTruthy();
        const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
        expect(keyParts).toHaveLength(3);
        expect(keyParts[0]).toEqual('login');
        expect(keyParts[1]).toBeTruthy();
        expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

        expect(loginStateCookie.httponly).toBe(true);
        expect(loginStateCookie['max-age']).toBe('3600');
        expect(loginStateCookie.path).toBe('/');
        expect(loginStateCookie.samesite).toBe('lax');
        expect(loginStateCookie.secure).toBe(true);

        const cookieValue: string = loginStateCookie.value;
        expect(cookieValue).toBeTruthy();
        const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.state).toEqual(keyParts[1]);
        expect(searchParams.get('state')).toEqual(keyParts[1]);
        expect(loginState.codeVerifier).toBeTruthy();
        expect(loginState.redirectUri).toBe(redirectUri);
        expect(loginState.customState).toBeFalsy();
        expect(loginState.returnUrl).toBeUndefined();
      });

      test(`Custom State at the Function Level using ${placeholderName}`, async () => {
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

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { customState: CUSTOM_STATE });
        expect(
          authorizeUrl.startsWith(`https://devs4you.${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize`)
        ).toBeTruthy();

        // Validate login state cookie
        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        expect(setCookieHeaders).toBeTruthy();
        expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];
        const cookieKey: string = loginStateCookie.name;
        expect(cookieKey).toBeTruthy();
        const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
        expect(keyParts).toHaveLength(3);
        expect(keyParts[0]).toEqual('login');
        expect(keyParts[1]).toBeTruthy();
        expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

        expect(loginStateCookie.httponly).toBe(true);
        expect(loginStateCookie['max-age']).toBe('3600');
        expect(loginStateCookie.path).toBe('/');
        expect(loginStateCookie.samesite).toBe('lax');
        expect(loginStateCookie.secure).toBe(true);

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.state).toEqual(keyParts[1]);
        expect(loginState.customState).toEqual(CUSTOM_STATE);
      });
    });

    // ///////////////////////////////////////////
    //  PRIORITY ORDER #1 - TENANT CUSTOM DOMAIN
    // ///////////////////////////////////////////

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Priority 1 - Tenant Custom Domain with %s placeholder', (placeholderName, placeholder) => {
      test(`01: Tenant custom domain query param precedence over tenant subdomains using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
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

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { tenant_custom_domain: 'query.tenant.com' },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

        // Validate Redirect response
        validateRedirectResponse(authorizeUrl, 'https://query.tenant.com');
        await validateLoginStateCookie(mockRes);
      });
    });

    test('02: Tenant custom domain query param precedence over tenant domain query param', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com', tenant_name: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    test('03: Tenant custom domain query param precedence over default tenant custom domain Login config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    test('04: Tenant custom domain query param precedence over default tenant domain name Login config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { defaultTenantName: 'tenant' });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    // ///////////////////////////////////////
    //  PRIORITY ORDER #2 - TENANT SUBDOMAIN
    // ///////////////////////////////////////

    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Priority 2 - Tenant Subdomain with %s placeholder', (placeholderName, placeholder) => {
      test(`01: Tenant subdomain takes precedence over tenant domain query param using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
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

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { tenant_name: 'query' },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

        // Validate Redirect response
        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(mockRes);
      });

      test(`02: Tenant subdomain takes precedence over default tenant custom domain Login config using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
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

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
          defaultTenantCustomDomain: 'default.tenant.com',
        });

        // Validate Redirect response
        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(mockRes);
      });

      test(`03: Tenant subdomain takes precedence over default tenant domain name Login config using ${placeholderName}`, async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        wristbandApplicationVanityDomain = 'auth.invotastic.com';
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
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

        // Create mock request and response
        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        // Cast req and res to NextApiRequest and NextApiResponse
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { defaultTenantName: 'default' });

        // Validate Redirect response
        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(mockRes);
      });
    });

    // ////////////////////////////////////////////////
    //  PRIORITY ORDER #3 - TENANT DOMAIN QUERY PARAM
    // ////////////////////////////////////////////////

    test('01: Tenant domain query param takes precedence over default tenant custom domain Login config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_name: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'global.tenant.com',
      });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    test('02: Tenant domain query param takes precedence over default tenant domain name Login config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_name: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { defaultTenantName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #4 - DEFAULT TENANT CUSTOM DOMAIN CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant custom domain takes precedence over default tenant domain name Login config', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantName: 'global',
        defaultTenantCustomDomain: 'global.tenant.com',
      });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, `https://global.tenant.com`);
      await validateLoginStateCookie(mockRes);
    });

    test('02: Default tenant custom domain without any other Login config or query params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, `https://tenant.custom.com`);
      await validateLoginStateCookie(mockRes);
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #5 - DEFAULT TENANT DOMAIN NAME CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant domain name without any other Login config or query params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${parseTenantFromRootDomain}/api/auth/login`,
        redirectUri: `https://${parseTenantFromRootDomain}/api/auth/callback`,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { defaultTenantName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(authorizeUrl, `https://global.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(mockRes);
    });
  });

  describe('Return URL Configuration Tests', () => {
    describe.each([
      ['tenant_domain', '{tenant_domain}'],
      ['tenant_name', '{tenant_name}'],
    ])('Return URL tests with %s placeholder', (placeholderName, placeholder) => {
      beforeEach(() => {
        loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
      });

      test(`returnUrl config stored in login state using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const returnUrl = '/dashboard';
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        // Validate login state cookie contains returnUrl
        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
      });

      test(`returnUrl with absolute URL using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const returnUrl = 'https://external.example.com/after-login';
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
      });

      test(`returnUrl with query parameters using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const returnUrl = '/dashboard?tab=settings&view=detailed';
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
      });

      test(`returnUrl config takes precedence over return_url query param using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { return_url: '/query-return-url' },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const configReturnUrl = '/config-return-url';
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl: configReturnUrl });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(configReturnUrl);
      });

      test(`return_url query param used when no returnUrl config provided using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { return_url: '/query-return-url' },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {});

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe('/query-return-url');
      });

      test(`no returnUrl when neither config nor query param provided using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {});

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBeUndefined();
      });

      test(`empty string returnUrl config should not be stored using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
          query: { return_url: '/fallback-url' },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl: '' });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBeUndefined();
      });

      test(`returnUrl combined with customState using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const returnUrl = '/admin/dashboard';
        const customState = { role: 'admin', preferences: { theme: 'dark' } };

        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
          returnUrl,
          customState,
        });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
        expect(loginState.customState).toEqual(customState);
      });

      test(`returnUrl with special characters and encoding using ${placeholderName}`, async () => {
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

        const { req, res } = createMocks({
          method: 'GET',
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockReq = req as unknown as NextApiRequest;
        const mockRes = res as unknown as MockResponse<NextApiResponse>;

        const returnUrl = '/dashboard?name=John Doe&category=R&D';
        const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });

        validateRedirectResponse(authorizeUrl, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = mockRes.getHeader('Set-Cookie');
        const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
      });
    });
  });
});
