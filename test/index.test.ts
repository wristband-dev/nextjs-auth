import { createWristbandAuth } from '../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const LOGIN_URL_WITH_SUBDOMAIN = 'http://{tenant_domain}.business.invotastic.com/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const REDIRECT_URI_WITH_SUBDOMAIN = 'http://{tenant_domain}.business.invotastic.com/api/auth/callback';
const ROOT_DOMAIN = 'business.invotastic.com';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2b-invotastic.dev.wristband.dev';

describe('WristbandAuth Instantiation Errors', () => {
  test('Empty clientId', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: '',
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Empty clientSecret', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: '',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Empty loginStateSecret', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: '',
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Empty loginUrl', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: '',
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Empty redirectUri', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: '',
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Empty wristbandApplicationVanityDomain', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: '',
      });
    }).toThrow(TypeError);
  });

  test('Empty rootDomain with tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        useTenantSubdomains: true,
        rootDomain: '',
      });
    }).toThrow(TypeError);
  });

  test('Missing tenant domain token in loginUrl with tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI_WITH_SUBDOMAIN,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        useTenantSubdomains: true,
        rootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Missing tenant domain token in redirectUri with tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL_WITH_SUBDOMAIN,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        useTenantSubdomains: true,
        rootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Invalid tenant domain token in loginUrl with no tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL_WITH_SUBDOMAIN,
        redirectUri: REDIRECT_URI,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        useTenantSubdomains: false,
        rootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });

  test('Invalid tenant domain token in redirectUri with no tenant subdomains', async () => {
    expect(() => {
      return createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: LOGIN_URL,
        redirectUri: REDIRECT_URI_WITH_SUBDOMAIN,
        wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        useTenantSubdomains: false,
        rootDomain: ROOT_DOMAIN,
      });
    }).toThrow(TypeError);
  });
});
