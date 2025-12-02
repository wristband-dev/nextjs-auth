import { createWristbandAuth } from '../src/index';
import { TENANT_DOMAIN_PLACEHOLDER, TENANT_NAME_PLACEHOLDER, TENANT_PLACEHOLDER_MSG } from '../src/utils/constants';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const ROOT_DOMAIN = 'business.invotastic.com';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2b-invotastic.dev.wristband.dev';

// Helper function to create URLs with placeholders
const getLoginUrlWithPlaceholder = (placeholder: string) => {
  return `http://${placeholder}.business.invotastic.com/api/auth/login`;
};
const getRedirectUriWithPlaceholder = (placeholder: string) => {
  return `http://${placeholder}.business.invotastic.com/api/auth/callback`;
};

describe('WristbandAuth Instantiation Errors', () => {
  describe('Required Configuration Validation', () => {
    test('Empty clientId', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: '',
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [clientId] config must have a value.');
    });

    test('Whitespace-only clientId', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: '   ',
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [clientId] config must have a value.');
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
          autoConfigureEnabled: false,
        });
      }).toThrow('The [clientSecret] config must have a value.');
    });

    test('Whitespace-only clientSecret', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: '   ',
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [clientSecret] config must have a value.');
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
          autoConfigureEnabled: false,
        });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });

    test('Whitespace-only wristbandApplicationVanityDomain', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: '   ',
          autoConfigureEnabled: false,
        });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });
  });

  describe('Login State Secret Validation', () => {
    test('Short loginStateSecret (less than 32 characters)', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: 'short-secret',
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [loginStateSecret] config must have a value of at least 32 characters.');
    });

    test('Exactly 32 characters loginStateSecret should pass', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: '12345678901234567890123456789012', // 32 chars
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Undefined loginStateSecret should use clientSecret as fallback', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });
  });

  describe('Token Expiration Buffer Validation', () => {
    test('Negative tokenExpirationBuffer', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          tokenExpirationBuffer: -10,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [tokenExpirationBuffer] config must be greater than or equal to 0.');
    });

    test('Zero tokenExpirationBuffer should pass', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          tokenExpirationBuffer: 0,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });
  });

  describe('Auto-Configure Disabled Validation', () => {
    test('Empty loginUrl when auto-configure disabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: '',
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [loginUrl] config must have a value when auto-configure is disabled.');
    });

    test('Empty redirectUri when auto-configure disabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: '',
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [redirectUri] config must have a value when auto-configure is disabled.');
    });

    test('Missing loginUrl when auto-configure disabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [loginUrl] config must have a value when auto-configure is disabled.');
    });

    test('Missing redirectUri when auto-configure disabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow('The [redirectUri] config must have a value when auto-configure is disabled.');
    });
  });

  describe.each([
    ['tenant_domain', TENANT_DOMAIN_PLACEHOLDER],
    ['tenant_name', TENANT_NAME_PLACEHOLDER],
  ])('Tenant Domain Token Validation with Auto-Configure Disabled - %s placeholder', (placeholderName, placeholder) => {
    test(`Missing ${placeholderName} placeholder in loginUrl with tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: getRedirectUriWithPlaceholder(placeholder),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(
        `The [loginUrl] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
      );
    });

    test(`Missing ${placeholderName} placeholder in redirectUri with tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(placeholder),
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(
        `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
      );
    });

    test(`Invalid ${placeholderName} placeholder in loginUrl with no tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(placeholder),
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(
        `The [loginUrl] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
      );
    });

    test(`Invalid ${placeholderName} placeholder in redirectUri with no tenant subdomains`, async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: getRedirectUriWithPlaceholder(placeholder),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).toThrow(
        `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
      );
    });
  });

  describe('Mixed Placeholder Support with Auto-Configure Disabled', () => {
    test('tenant_domain in loginUrl and tenant_name in redirectUri', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('tenant_name in loginUrl and tenant_domain in redirectUri', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Both tenant_name placeholders', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Both tenant_domain placeholders (backward compatibility)', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });
  });

  describe.each([
    ['tenant_domain', TENANT_DOMAIN_PLACEHOLDER],
    ['tenant_name', TENANT_NAME_PLACEHOLDER],
  ])(
    'Partial Configuration Validation with Auto-Configure Enabled - %s placeholder',
    (placeholderName, placeholder) => {
      test(`Manual loginUrl with parseTenantFromRootDomain but missing ${placeholderName} placeholder`, async () => {
        expect(() => {
          return createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl: LOGIN_URL, // Missing placeholder
            wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
            parseTenantFromRootDomain: ROOT_DOMAIN,
            autoConfigureEnabled: true,
          });
        }).toThrow(
          `The [loginUrl] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      });

      test(`Manual redirectUri with parseTenantFromRootDomain but missing ${placeholderName} placeholder`, async () => {
        expect(() => {
          return createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            redirectUri: REDIRECT_URI, // Missing placeholder
            wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
            parseTenantFromRootDomain: ROOT_DOMAIN,
            autoConfigureEnabled: true,
          });
        }).toThrow(
          `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      });

      test(`Manual loginUrl with ${placeholderName} placeholder but no parseTenantFromRootDomain`, async () => {
        expect(() => {
          return createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            loginUrl: getLoginUrlWithPlaceholder(placeholder), // Has placeholder
            wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
            autoConfigureEnabled: true,
          });
        }).toThrow(
          `The [loginUrl] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      });

      test(`Manual redirectUri with ${placeholderName} placeholder but no parseTenantFromRootDomain`, async () => {
        expect(() => {
          return createWristbandAuth({
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
            redirectUri: getRedirectUriWithPlaceholder(placeholder), // Has placeholder
            wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
            autoConfigureEnabled: true,
          });
        }).toThrow(
          `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      });
    }
  );

  describe('Mixed Placeholder Support with Auto-Configure Enabled', () => {
    test('Manual tenant_domain loginUrl and tenant_name redirectUri with parseTenantFromRootDomain', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: true,
        });
      }).not.toThrow();
    });

    test('Manual tenant_name loginUrl only with parseTenantFromRootDomain', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: true,
        });
      }).not.toThrow();
    });
  });

  describe('Successful Instantiation Cases', () => {
    test('Minimal valid configuration with auto-configure enabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
        });
      }).not.toThrow();
    });

    test('Complete configuration with auto-configure disabled', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          scopes: ['openid', 'profile'],
          tokenExpirationBuffer: 60,
          dangerouslyDisableSecureCookies: false,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Valid tenant subdomain configuration with tenant_domain placeholder', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_DOMAIN_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Valid tenant subdomain configuration with tenant_name placeholder', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: getLoginUrlWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          redirectUri: getRedirectUriWithPlaceholder(TENANT_NAME_PLACEHOLDER),
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          parseTenantFromRootDomain: ROOT_DOMAIN,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Custom application login page URL', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          customApplicationLoginPageUrl: 'https://custom.login.example.com',
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });

    test('Application custom domain active', async () => {
      expect(() => {
        return createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: LOGIN_URL,
          redirectUri: REDIRECT_URI,
          wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
          isApplicationCustomDomainActive: true,
          autoConfigureEnabled: false,
        });
      }).not.toThrow();
    });
  });
});
