import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  createMockNextRequest,
  LOGIN_STATE_COOKIE_SECRET,
  parseSetCookies,
} from '../test-utils';
import { mockWristbandFetch } from '../helpers/mock-fetch';

const APP_HOME_URL = 'https://myapp.com/home';

const resolveRedirectUrl = () => {
  return APP_HOME_URL;
};

const mockTokens = {
  access_token: 'accessToken',
  expires_in: 1800,
  id_token: 'idToken',
  refresh_token: 'refreshToken',
  token_type: 'bearer',
};
const mockUserinfo = {
  sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
  tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
  app_id: 'dy42gabu5jebreq6jajskk2n34',
  idp_name: 'wristband',
};

describe('appRouter.callback() - Application-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    // The callback runs through the token exchange, since the App Router clears the cookie on the returned response
    mockWristbandFetch({ tokens: mockTokens, userinfo: mockUserinfo });
  });

  test('Clears the app-level login state cookie with a Domain attribute matching the root domain derived from loginUrl', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    // Step 1: login() with an unresolved tenant sets the app-level login state cookie
    const { req: loginReq } = createMocks({
      method: 'GET',
      url: `https://${parseTenantFromRootDomain}/api/auth/login`,
      headers: { host: parseTenantFromRootDomain },
    });
    const loginResponse = await wristbandAuth.appRouter.login(createMockNextRequest(loginReq));
    const state = new URL(loginResponse.headers.get('location')!).searchParams.get('state');
    const [loginStateCookie] = parseSetCookies(loginResponse.headers.getSetCookie());

    // Step 2: simulate the callback landing on a resolved tenant subdomain, carrying that same cookie
    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/callback?state=${state}&code=code`,
      headers: {
        host: `devs4you.${parseTenantFromRootDomain}`,
        cookie: `${loginStateCookie.name}=${loginStateCookie.value}`,
      },
    });

    const { response, type } = await wristbandAuth.appRouter.callback(
      createMockNextRequest(callbackReq),
      resolveRedirectUrl
    );
    expect(type).toBe('completed');

    const [clearedCookie] = parseSetCookies(response.headers.getSetCookie());
    expect(clearedCookie.name).toBe(loginStateCookie.name);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBe(`.${parseTenantFromRootDomain}`);
  });

  test('Clears the tenant-level login state cookie with a Domain attribute matching the root domain derived from loginUrl', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    // Step 1: login() on a resolved tenant subdomain (tenant-level flow) with the flag enabled still
    // sets the login state cookie on the root domain
    const { req: loginReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/login`,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    });
    const loginResponse = await wristbandAuth.appRouter.login(createMockNextRequest(loginReq));
    const state = new URL(loginResponse.headers.get('location')!).searchParams.get('state');
    const [loginStateCookie] = parseSetCookies(loginResponse.headers.getSetCookie());
    expect(loginStateCookie.domain).toBe(`.${parseTenantFromRootDomain}`);

    // Step 2: the callback clears that cookie with the matching root Domain
    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/callback?state=${state}&code=code`,
      headers: {
        host: `devs4you.${parseTenantFromRootDomain}`,
        cookie: `${loginStateCookie.name}=${loginStateCookie.value}`,
      },
    });

    const { response, type } = await wristbandAuth.appRouter.callback(
      createMockNextRequest(callbackReq),
      resolveRedirectUrl
    );
    expect(type).toBe('completed');

    const [clearedCookie] = parseSetCookies(response.headers.getSetCookie());
    expect(clearedCookie.name).toBe(loginStateCookie.name);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBe(`.${parseTenantFromRootDomain}`);
  });

  test('Clears the login state cookie without a Domain attribute when loginUrl has no tenant placeholder', async () => {
    const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    const { req: loginReq } = createMocks({
      method: 'GET',
      url: loginUrl,
      headers: { host: 'localhost:6001' },
    });
    const loginResponse = await wristbandAuth.appRouter.login(createMockNextRequest(loginReq));
    const state = new URL(loginResponse.headers.get('location')!).searchParams.get('state');
    const [loginStateCookie] = parseSetCookies(loginResponse.headers.getSetCookie());

    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `${redirectUri}?state=${state}&code=code&tenant_name=devs4you`,
      headers: { host: 'localhost:6001', cookie: `${loginStateCookie.name}=${loginStateCookie.value}` },
    });

    const { response, type } = await wristbandAuth.appRouter.callback(
      createMockNextRequest(callbackReq),
      resolveRedirectUrl
    );
    expect(type).toBe('completed');

    const [clearedCookie] = parseSetCookies(response.headers.getSetCookie());
    expect(clearedCookie.name).toBe(loginStateCookie.name);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBeUndefined();
  });

  test('Clears the tenant-level login state cookie without a Domain attribute when loginUrl has no tenant placeholder', async () => {
    const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    // Login resolves the tenant via the tenant_name query param (tenant-level flow, not app-level)
    const { req: loginReq } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_name=devs4you`,
      headers: { host: 'localhost:6001' },
    });
    const loginResponse = await wristbandAuth.appRouter.login(createMockNextRequest(loginReq));
    const state = new URL(loginResponse.headers.get('location')!).searchParams.get('state');
    const [loginStateCookie] = parseSetCookies(loginResponse.headers.getSetCookie());
    expect(loginStateCookie.domain).toBeUndefined();

    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `${redirectUri}?state=${state}&code=code&tenant_name=devs4you`,
      headers: { host: 'localhost:6001', cookie: `${loginStateCookie.name}=${loginStateCookie.value}` },
    });

    const { response, type } = await wristbandAuth.appRouter.callback(
      createMockNextRequest(callbackReq),
      resolveRedirectUrl
    );
    expect(type).toBe('completed');

    const [clearedCookie] = parseSetCookies(response.headers.getSetCookie());
    expect(clearedCookie.name).toBe(loginStateCookie.name);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBeUndefined();
  });

  test('Clears the login state cookie without a Domain attribute when applicationAuthorizationRequestsEnabled is false', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    // applicationAuthorizationRequestsEnabled explicitly disabled (it defaults to true)
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      isApplicationCustomDomainActive: true,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: false,
      autoConfigureEnabled: false,
    });

    // Login resolves the tenant subdomain normally here (tenant-level flow, not app-level)
    const { req: loginReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/login`,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    });
    const loginResponse = await wristbandAuth.appRouter.login(createMockNextRequest(loginReq));
    const state = new URL(loginResponse.headers.get('location')!).searchParams.get('state');
    const [loginStateCookie] = parseSetCookies(loginResponse.headers.getSetCookie());
    expect(loginStateCookie.domain).toBeUndefined();

    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/callback?state=${state}&code=code`,
      headers: {
        host: `devs4you.${parseTenantFromRootDomain}`,
        cookie: `${loginStateCookie.name}=${loginStateCookie.value}`,
      },
    });

    const { response, type } = await wristbandAuth.appRouter.callback(
      createMockNextRequest(callbackReq),
      resolveRedirectUrl
    );
    expect(type).toBe('completed');

    const [clearedCookie] = parseSetCookies(response.headers.getSetCookie());
    expect(clearedCookie.name).toBe(loginStateCookie.name);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBeUndefined();
  });

  test('No login state cookie present - nothing to clear regardless of the domain logic', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      autoConfigureEnabled: false,
    });

    const { req: callbackReq } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/callback?state=some-state`,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    });

    const result = await wristbandAuth.appRouter.callback(createMockNextRequest(callbackReq), resolveRedirectUrl);

    expect(result.type).toBe('redirect_required');
    expect(result.reason).toBe('missing_login_state');
    expect(result.response.headers.getSetCookie()).toHaveLength(0);
  });
});
