/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, LOGIN_STATE_COOKIE_SECRET, parseSetCookies } from '../test-utils';
import { mockWristbandFetch } from '../helpers/mock-fetch';

describe('pagesRouter.callback() - Application-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    mockWristbandFetch();
  });

  test('Clears the app-level login state cookie with a Domain attribute matching parseTenantFromRootDomain', async () => {
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
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
      autoConfigureEnabled: false,
    });

    // Step 1: login() with an unresolved tenant sets the app-level login state cookie
    const { req: loginReq, res: loginRes } = createMocks({
      method: 'GET',
      url: loginUrl,
      headers: { host: parseTenantFromRootDomain },
    });
    const mockLoginReq = loginReq as unknown as NextApiRequest;
    const mockLoginRes = loginRes as unknown as MockResponse<NextApiResponse>;

    const authorizeUrl = await wristbandAuth.pagesRouter.login(mockLoginReq, mockLoginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');

    const loginSetCookieHeaders = mockLoginRes.getHeader('Set-Cookie');
    const [loginStateCookie] = parseSetCookies(loginSetCookieHeaders as string | string[]);

    // Step 2: simulate the callback landing on a resolved tenant subdomain, carrying that same cookie
    const { req: callbackReq, res: callbackRes } = createMocks({
      method: 'GET',
      url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/callback`,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      cookies: { [loginStateCookie.name]: loginStateCookie.value },
      query: { state },
    });
    const mockCallbackReq = callbackReq as unknown as NextApiRequest;
    const mockCallbackRes = callbackRes as unknown as MockResponse<NextApiResponse>;

    // Deliberately omit [code] so we stop right after the cookie is cleared, before any token exchange
    await expect(wristbandAuth.pagesRouter.callback(mockCallbackReq, mockCallbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedSetCookieHeaders = mockCallbackRes.getHeader('Set-Cookie');
    const [clearedCookie] = parseSetCookies(clearedSetCookieHeaders as string | string[]);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBe(`.${parseTenantFromRootDomain}`);
  });

  test('Clears the login state cookie without a Domain attribute when parseTenantFromRootDomain is not set', async () => {
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

    const { req: loginReq, res: loginRes } = createMocks({
      method: 'GET',
      url: loginUrl,
      headers: { host: 'localhost:6001' },
    });
    const mockLoginReq = loginReq as unknown as NextApiRequest;
    const mockLoginRes = loginRes as unknown as MockResponse<NextApiResponse>;

    const authorizeUrl = await wristbandAuth.pagesRouter.login(mockLoginReq, mockLoginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');

    const loginSetCookieHeaders = mockLoginRes.getHeader('Set-Cookie');
    const [loginStateCookie] = parseSetCookies(loginSetCookieHeaders as string | string[]);

    const { req: callbackReq, res: callbackRes } = createMocks({
      method: 'GET',
      url: redirectUri,
      headers: { host: 'localhost:6001' },
      cookies: { [loginStateCookie.name]: loginStateCookie.value },
      query: { state, tenant_name: 'devs4you' },
    });
    const mockCallbackReq = callbackReq as unknown as NextApiRequest;
    const mockCallbackRes = callbackRes as unknown as MockResponse<NextApiResponse>;

    await expect(wristbandAuth.pagesRouter.callback(mockCallbackReq, mockCallbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedSetCookieHeaders = mockCallbackRes.getHeader('Set-Cookie');
    const [clearedCookie] = parseSetCookies(clearedSetCookieHeaders as string | string[]);
    expect(clearedCookie['max-age']).toBe('0');
    expect(clearedCookie.domain).toBeUndefined();
  });

  test('Clears the login state cookie without a Domain attribute when applicationAuthorizationRequestsEnabled is false', async () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const wristbandApplicationVanityDomain = 'auth.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    // applicationAuthorizationRequestsEnabled intentionally omitted (defaults to false)
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

    // Login resolves the tenant subdomain normally here (tenant-level flow, not app-level)
    const { req: loginReq, res: loginRes } = createMocks({
      method: 'GET',
      url: loginUrl,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
    });
    const mockLoginReq = loginReq as unknown as NextApiRequest;
    const mockLoginRes = loginRes as unknown as MockResponse<NextApiResponse>;

    const authorizeUrl = await wristbandAuth.pagesRouter.login(mockLoginReq, mockLoginRes);
    const state = new URL(authorizeUrl).searchParams.get('state');

    const loginSetCookieHeaders = mockLoginRes.getHeader('Set-Cookie');
    const [loginStateCookie] = parseSetCookies(loginSetCookieHeaders as string | string[]);

    const { req: callbackReq, res: callbackRes } = createMocks({
      method: 'GET',
      url: redirectUri,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      cookies: { [loginStateCookie.name]: loginStateCookie.value },
      query: { state },
    });
    const mockCallbackReq = callbackReq as unknown as NextApiRequest;
    const mockCallbackRes = callbackRes as unknown as MockResponse<NextApiResponse>;

    await expect(wristbandAuth.pagesRouter.callback(mockCallbackReq, mockCallbackRes)).rejects.toThrow(
      'Invalid query parameter [code] passed from Wristband during callback'
    );

    const clearedSetCookieHeaders = mockCallbackRes.getHeader('Set-Cookie');
    const [clearedCookie] = parseSetCookies(clearedSetCookieHeaders as string | string[]);
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
      parseTenantFromRootDomain,
      wristbandApplicationVanityDomain,
      applicationAuthorizationRequestsEnabled: true,
      fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
      autoConfigureEnabled: false,
    });

    const { req: callbackReq, res: callbackRes } = createMocks({
      method: 'GET',
      url: redirectUri,
      headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      query: { state: 'some-state' },
    });
    const mockCallbackReq = callbackReq as unknown as NextApiRequest;
    const mockCallbackRes = callbackRes as unknown as MockResponse<NextApiResponse>;

    const result = await wristbandAuth.pagesRouter.callback(mockCallbackReq, mockCallbackRes);

    expect(result.type).toBe('redirect_required');
    expect((result as any).reason).toBe('missing_login_state');
    expect(mockCallbackRes.getHeader('Set-Cookie')).toBeUndefined();
  });
});
