import { createMocks } from 'node-mocks-http';
import { NextResponse } from 'next/server';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState } from '../../src/utils/crypto';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { createMockNextRequest, parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const CUSTOM_SCOPES = ['openid', 'roles'];
const CUSTOM_STATE = { test: 'abc' };
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(response: NextResponse, expectedOrigin: string) {
  const { headers, status } = response;
  const locationUrl: URL = new URL(headers.get('location')!);
  const { pathname, origin } = locationUrl;

  expect(status).toBe(302);
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/oauth2/authorize');

  expect(headers.get('Cache-Control')).toBe('no-store');
  expect(headers.get('Pragma')).toBe('no-cache');
}

async function validateLoginStateCookie(response: NextResponse) {
  const setCookieHeaders = response.headers.getSetCookie();
  expect(setCookieHeaders).toBeTruthy();
  expect(setCookieHeaders).toHaveLength(1);
  const parsedCookies = parseSetCookies(setCookieHeaders);
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
  expect(loginStateCookie.samesite).toBe('Lax');
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest);

        // Validate Redirect response
        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const { headers } = response;
        const locationUrl: URL = new URL(headers.get('location')!);
        const { searchParams } = locationUrl;

        // Validate query params of Authorize URL
        expect(searchParams.get('scope')).toEqual(CUSTOM_SCOPES.join(' '));

        // Validate login state cookie
        const setCookieHeaders = response.headers.getSetCookie();
        expect(setCookieHeaders).toBeTruthy();
        expect(setCookieHeaders).toHaveLength(1);
        const parsedCookies = parseSetCookies(setCookieHeaders);
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
        expect(loginStateCookie.samesite).toBe('Lax');
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, { customState: CUSTOM_STATE });

        // Validate Redirect response
        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        // Validate login state cookie
        const setCookieHeaders = response.headers.getSetCookie();
        expect(setCookieHeaders).toBeTruthy();
        expect(setCookieHeaders).toHaveLength(1);
        const parsedCookies = parseSetCookies(setCookieHeaders);
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
        expect(loginStateCookie.samesite).toBe('Lax');
        expect(loginStateCookie.secure).toBe(true);

        const cookieValue: string = loginStateCookie.value;
        expect(cookieValue).toBeTruthy();

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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}?tenant_custom_domain=query.tenant.com`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest);

        // Validate Redirect response
        validateRedirectResponse(response, 'https://query.tenant.com');
        await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_custom_domain=query.tenant.com&tenant_name=devs4you`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);

      // Validate Redirect response
      validateRedirectResponse(response, 'https://query.tenant.com');
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_custom_domain=query.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      validateRedirectResponse(response, 'https://query.tenant.com');
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_custom_domain=query.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { defaultTenantName: 'tenant' });

      // Validate Redirect response
      validateRedirectResponse(response, 'https://query.tenant.com');
      await validateLoginStateCookie(response);
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}?tenant_name=query`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest);

        // Validate Redirect response
        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(response);
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, {
          defaultTenantCustomDomain: 'default.tenant.com',
        });

        // Validate Redirect response
        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(response);
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, { defaultTenantName: 'default' });

        // Validate Redirect response
        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);
        await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, {
        defaultTenantCustomDomain: 'global.tenant.com',
      });

      // Validate Redirect response
      validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { defaultTenantName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, {
        defaultTenantName: 'global',
        defaultTenantCustomDomain: 'global.tenant.com',
      });

      // Validate Redirect response
      validateRedirectResponse(response, `https://global.tenant.com`);
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      validateRedirectResponse(response, `https://tenant.custom.com`);
      await validateLoginStateCookie(response);
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

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { defaultTenantName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(response, `https://global.${wristbandApplicationVanityDomain}`);
      await validateLoginStateCookie(response);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const returnUrl = '/dashboard';
        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        // Validate login state cookie contains returnUrl
        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const returnUrl = 'https://external.example.com/after-login';
        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const returnUrl = '/dashboard?tab=settings&view=detailed';
        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}?return_url=/query-return-url`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const configReturnUrl = '/config-return-url';
        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl: configReturnUrl });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}?return_url=/query-return-url`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, {});

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, {});

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}?return_url=/fallback-url`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl: '' });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const returnUrl = '/admin/dashboard';
        const customState = { role: 'admin', preferences: { theme: 'dark' } };

        const response = await wristbandAuth.appRouter.login(mockNextRequest, {
          returnUrl,
          customState,
        });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
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

        const { req } = createMocks({
          method: 'GET',
          url: `${loginUrl}`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        const returnUrl = '/dashboard?name=John Doe&category=R&D';
        const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });

        validateRedirectResponse(response, `https://devs4you.${wristbandApplicationVanityDomain}`);

        const setCookieHeaders = response.headers.getSetCookie();
        const parsedCookies = parseSetCookies(setCookieHeaders);
        const loginStateCookie = parsedCookies[0];

        const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
        expect(loginState.returnUrl).toBe(returnUrl);
      });
    });
  });
});
