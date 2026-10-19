import { ConfigResolver } from '../src/config-resolver';
import { WristbandService } from '../src/wristband-service';
import { AuthConfig, SdkConfiguration } from '../src/types';
import { WristbandError } from '../src/error';
import { TENANT_NAME_PLACEHOLDER, TENANT_PLACEHOLDER_MSG } from '../src/utils/constants';

// Mock WristbandService
jest.mock('../src/wristband-service');
const MockWristbandService = WristbandService as jest.MockedClass<typeof WristbandService>;

const validAuthConfig: AuthConfig = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  loginStateSecret: 'this-is-a-very-long-login-state-secret-that-meets-requirements',
  wristbandApplicationVanityDomain: 'test.wristband.dev',
};

const validSdkConfig: SdkConfiguration = {
  applicationAuthorizationRequestsEnabled: false,
  fallbackLoginUrl: null,
  loginUrl: 'https://test.example.com/auth/login',
  redirectUri: 'https://test.example.com/auth/callback',
  customApplicationLoginPageUrl: 'https://test.example.com/custom-login',
  isApplicationCustomDomainActive: true,
  loginUrlTenantDomainSuffix: null,
};

let mockWristbandService: jest.Mocked<WristbandService>;

const initWristbandServiceMock = (sdkConfig: SdkConfiguration) => {
  mockWristbandService = {
    getSdkConfiguration: jest.fn().mockResolvedValue(sdkConfig),
  } as unknown as jest.Mocked<WristbandService>;
  MockWristbandService.mockImplementation(() => {
    return mockWristbandService;
  });
};

describe('ConfigResolver', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor - Required Fields Validation', () => {
    it('should validate clientId is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientId: '' });
      }).toThrow('The [clientId] config must have a value.');
    });

    it('should validate clientId is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientId: '   ' });
      }).toThrow('The [clientId] config must have a value.');
    });

    it('should validate clientSecret is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientSecret: '' });
      }).toThrow('The [clientSecret] config must have a value.');
    });

    it('should validate clientSecret is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, clientSecret: '   ' });
      }).toThrow('The [clientSecret] config must have a value.');
    });

    it('should validate loginStateSecret length when provided', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, loginStateSecret: 'short' });
      }).toThrow('The [loginStateSecret] config must have a value of at least 32 characters.');
    });

    it('should allow undefined loginStateSecret (falls back to clientSecret)', () => {
      const config = { ...validAuthConfig };
      delete config.loginStateSecret;
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });

    it('should validate wristbandApplicationVanityDomain is present', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, wristbandApplicationVanityDomain: '' });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });

    it('should validate wristbandApplicationVanityDomain is not just whitespace', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, wristbandApplicationVanityDomain: '   ' });
      }).toThrow('The [wristbandApplicationVanityDomain] config must have a value.');
    });

    it('should validate tokenExpirationBuffer is not negative when provided', () => {
      expect(() => {
        return new ConfigResolver({ ...validAuthConfig, tokenExpirationBuffer: -1 });
      }).toThrow('The [tokenExpirationBuffer] config must be greater than or equal to 0.');
    });
  });

  describe('Constructor - Auto-configure Disabled Validation', () => {
    const disabledConfig = { ...validAuthConfig, autoConfigureEnabled: false };

    it('should validate loginUrl is present when auto-configure disabled', () => {
      expect(() => {
        return new ConfigResolver(disabledConfig);
      }).toThrow('The [loginUrl] config must have a value when auto-configure is disabled.');
    });

    it('should validate redirectUri is present when auto-configure disabled', () => {
      const config = { ...disabledConfig, loginUrl: 'https://test.com/login' };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow('The [redirectUri] config must have a value when auto-configure is disabled.');
    });

    it('should require the tenant_name placeholder in redirectUri when loginUrl has it', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: 'https://test.com/callback',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(`The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] contains it.`);
    });

    it('should reject the tenant_name placeholder in redirectUri when loginUrl does not have it', () => {
      const config = {
        ...disabledConfig,
        loginUrl: 'https://test.com/login',
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] does not contain it.`
      );
    });

    it('should reject a loginUrl where the tenant_name placeholder is not the leftmost part of the hostname', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://app.${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [loginUrl] can only contain the ${TENANT_PLACEHOLDER_MSG} once, as the leftmost part of its hostname.`
      );
    });

    it('should reject a redirectUri where the tenant_name placeholder is not the leftmost part of the hostname', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://test.com/${TENANT_NAME_PLACEHOLDER}/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [redirectUri] can only contain the ${TENANT_PLACEHOLDER_MSG} once, as the leftmost part of its hostname.`
      );
    });

    it('should pass validation with correct configuration using tenant_name', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
        applicationAuthorizationRequestsEnabled: false,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });
  });

  describe('Mixed Placeholder Support', () => {
    const disabledConfig = {
      ...validAuthConfig,
      autoConfigureEnabled: false,
      applicationAuthorizationRequestsEnabled: false,
    };

    it('should accept both tenant_name placeholders', () => {
      const config = {
        ...disabledConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });
  });

  describe('Constructor - Auto-configure Enabled Partial Validation', () => {
    it('should require the tenant_name placeholder in a manually provided redirectUri when the manual loginUrl has it', () => {
      const config = {
        ...validAuthConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: 'https://test.com/callback',
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(`The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] contains it.`);
    });

    it('should reject the tenant_name placeholder in a manually provided redirectUri when the manual loginUrl does not have it', () => {
      const config = {
        ...validAuthConfig,
        loginUrl: 'https://test.com/login',
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] does not contain it.`
      );
    });

    it('should defer the placeholder comparison when only loginUrl is provided manually', () => {
      const config = { ...validAuthConfig, loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login` };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });

    it('should defer the placeholder comparison when only redirectUri is provided manually', () => {
      const config = { ...validAuthConfig, redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback` };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });

    it('should reject a manually provided loginUrl where the tenant_name placeholder is not the leftmost part of the hostname', () => {
      const config = { ...validAuthConfig, loginUrl: `https://app.${TENANT_NAME_PLACEHOLDER}.test.com/login` };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [loginUrl] can only contain the ${TENANT_PLACEHOLDER_MSG} once, as the leftmost part of its hostname.`
      );
    });

    it('should reject a manually provided redirectUri where the tenant_name placeholder is not the leftmost part of the hostname', () => {
      const config = { ...validAuthConfig, redirectUri: `https://test.com/${TENANT_NAME_PLACEHOLDER}/callback` };
      expect(() => {
        return new ConfigResolver(config);
      }).toThrow(
        `The [redirectUri] can only contain the ${TENANT_PLACEHOLDER_MSG} once, as the leftmost part of its hostname.`
      );
    });

    it('should pass validation with correct manual overrides using tenant_name', () => {
      const config = {
        ...validAuthConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      expect(() => {
        return new ConfigResolver(config);
      }).not.toThrow();
    });
  });

  describe('Static Configuration Getters', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should return clientId', () => {
      expect(resolver.getClientId()).toBe('test-client-id');
    });

    it('should return clientSecret', () => {
      expect(resolver.getClientSecret()).toBe('test-client-secret');
    });

    it('should return loginStateSecret when provided', () => {
      expect(resolver.getLoginStateSecret()).toBe('this-is-a-very-long-login-state-secret-that-meets-requirements');
    });

    it('should return clientSecret as loginStateSecret when not provided', () => {
      const config = { ...validAuthConfig };
      delete config.loginStateSecret;
      resolver = new ConfigResolver(config);
      expect(resolver.getLoginStateSecret()).toBe('test-client-secret');
    });

    it('should return wristbandApplicationVanityDomain', () => {
      expect(resolver.getWristbandApplicationVanityDomain()).toBe('test.wristband.dev');
    });

    it('should return dangerouslyDisableSecureCookies default false', () => {
      expect(resolver.getDangerouslyDisableSecureCookies()).toBe(false);
    });

    it('should return dangerouslyDisableSecureCookies when set to true', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, dangerouslyDisableSecureCookies: true });
      expect(resolver.getDangerouslyDisableSecureCookies()).toBe(true);
    });

    it('should return default scopes', () => {
      expect(resolver.getScopes()).toEqual(['openid', 'offline_access', 'email']);
    });

    it('should return custom scopes when provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, scopes: ['custom', 'scope'] });
      expect(resolver.getScopes()).toEqual(['custom', 'scope']);
    });

    it('should return default scopes when empty array provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, scopes: [] });
      expect(resolver.getScopes()).toEqual(['openid', 'offline_access', 'email']);
    });

    it('should return autoConfigureEnabled default true', () => {
      expect(resolver.getAutoConfigureEnabled()).toBe(true);
    });

    it('should return autoConfigureEnabled when explicitly set to true', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, autoConfigureEnabled: true });
      expect(resolver.getAutoConfigureEnabled()).toBe(true);
    });

    it('should return autoConfigureEnabled when set to false', () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
      };
      resolver = new ConfigResolver(config);
      expect(resolver.getAutoConfigureEnabled()).toBe(false);
    });

    it('should return default tokenExpirationBuffer', () => {
      expect(resolver.getTokenExpirationBuffer()).toBe(60);
    });

    it('should return custom tokenExpirationBuffer when provided', () => {
      resolver = new ConfigResolver({ ...validAuthConfig, tokenExpirationBuffer: 120 });
      expect(resolver.getTokenExpirationBuffer()).toBe(120);
    });
  });

  describe('Dynamic Configuration Getters - Auto-configure Disabled', () => {
    describe('With tenant domain configuration', () => {
      let resolver: ConfigResolver;

      beforeEach(() => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.manual.com/login`,
          redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.manual.com/callback`,
          customApplicationLoginPageUrl: 'https://manual.com/custom-login',
          isApplicationCustomDomainActive: true,
          applicationAuthorizationRequestsEnabled: false,
        };
        resolver = new ConfigResolver(config);
      });

      it('should return manual customApplicationLoginPageUrl', async () => {
        expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('https://manual.com/custom-login');
      });

      it('should return manual isApplicationCustomDomainActive', async () => {
        expect(await resolver.getIsApplicationCustomDomainActive()).toBe(true);
      });

      it('should return manual loginUrl', async () => {
        expect(await resolver.getLoginUrl()).toBe(`https://${TENANT_NAME_PLACEHOLDER}.manual.com/login`);
      });

      it('should derive parseTenantFromRootDomain from the manual loginUrl', async () => {
        expect(await resolver.getParseTenantFromRootDomain()).toBe('manual.com');
      });

      it('should derive fallbackLoginUrl from the manual loginUrl', async () => {
        expect(await resolver.getFallbackLoginUrl()).toBe('https://manual.com/login');
      });

      it('should return manual redirectUri', async () => {
        expect(await resolver.getRedirectUri()).toBe(`https://${TENANT_NAME_PLACEHOLDER}.manual.com/callback`);
      });
    });

    describe('Without tenant domain configuration', () => {
      let resolver: ConfigResolver;

      beforeEach(() => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://manual.com/login',
          redirectUri: 'https://manual.com/callback',
        };
        resolver = new ConfigResolver(config);
      });

      it('should return empty string for missing customApplicationLoginPageUrl', async () => {
        expect(await resolver.getCustomApplicationLoginPageUrl()).toBe('');
      });

      it('should return false for missing isApplicationCustomDomainActive', async () => {
        expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);
      });

      it('should return manual loginUrl', async () => {
        expect(await resolver.getLoginUrl()).toBe('https://manual.com/login');
      });

      it('should return empty string for missing parseTenantFromRootDomain', async () => {
        expect(await resolver.getParseTenantFromRootDomain()).toBe('');
      });

      it('should return manual redirectUri', async () => {
        expect(await resolver.getRedirectUri()).toBe('https://manual.com/callback');
      });

      it('should return true for missing applicationAuthorizationRequestsEnabled', async () => {
        expect(await resolver.getApplicationAuthorizationRequestsEnabled()).toBe(true);
      });

      it('should return manually provided applicationAuthorizationRequestsEnabled', async () => {
        const config = {
          ...validAuthConfig,
          autoConfigureEnabled: false,
          loginUrl: 'https://manual.com/login',
          redirectUri: 'https://manual.com/callback',
          applicationAuthorizationRequestsEnabled: true,
        };
        const manualResolver = new ConfigResolver(config);
        expect(await manualResolver.getApplicationAuthorizationRequestsEnabled()).toBe(true);
      });

      it('should return empty string for missing fallbackLoginUrl', async () => {
        expect(await resolver.getFallbackLoginUrl()).toBe('');
      });
    });
  });

  describe('Dynamic Configuration - Auto-configure Enabled', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should return auto-configured values', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      const [applicationAuthorizationRequestsEnabled, customUrl, isCustomDomain, loginUrl, parseTenant, redirectUri] =
        await Promise.all([
          resolver.getApplicationAuthorizationRequestsEnabled(),
          resolver.getCustomApplicationLoginPageUrl(),
          resolver.getIsApplicationCustomDomainActive(),
          resolver.getLoginUrl(),
          resolver.getParseTenantFromRootDomain(),
          resolver.getRedirectUri(),
        ]);

      expect(applicationAuthorizationRequestsEnabled).toBe(false);
      expect(customUrl).toBe('https://test.example.com/custom-login');
      expect(isCustomDomain).toBe(true);
      expect(loginUrl).toBe('https://test.example.com/auth/login');
      expect(parseTenant).toBe('');
      expect(redirectUri).toBe('https://test.example.com/auth/callback');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should return manual values over auto-configured values', async () => {
      const config = {
        ...validAuthConfig,
        loginUrl: 'https://manual.com/login',
        customApplicationLoginPageUrl: 'https://manual.com/custom-login',
      };
      resolver = new ConfigResolver(config);
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      const [customUrl, loginUrl, redirectUri] = await Promise.all([
        resolver.getCustomApplicationLoginPageUrl(),
        resolver.getLoginUrl(),
        resolver.getRedirectUri(),
      ]);

      expect(customUrl).toBe('https://manual.com/custom-login');
      expect(loginUrl).toBe('https://manual.com/login');
      expect(redirectUri).toBe('https://test.example.com/auth/callback');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should handle null values in auto-config response', async () => {
      const partialSdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: 'https://test.example.com/auth/login',
        redirectUri: 'https://test.example.com/auth/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(partialSdkConfig);

      const [customUrl, isCustomDomain, parseTenant] = await Promise.all([
        resolver.getCustomApplicationLoginPageUrl(),
        resolver.getIsApplicationCustomDomainActive(),
        resolver.getParseTenantFromRootDomain(),
      ]);

      expect(customUrl).toBe('');
      expect(isCustomDomain).toBe(false);
      expect(parseTenant).toBe('');
    });

    it('should throw error when loginUrl missing from auto-config and not manually provided', async () => {
      const invalidSdkConfig = { redirectUri: 'https://test.example.com/auth/callback' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);

      await expect(resolver.getLoginUrl()).rejects.toThrow(
        'SDK configuration response missing required field: loginUrl'
      );
    });

    it('should throw error when redirectUri missing from auto-config and not manually provided', async () => {
      const invalidSdkConfig = { loginUrl: 'https://test.example.com/auth/login' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
      await expect(resolver.getRedirectUri()).rejects.toThrow(
        'The [redirectUri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.'
      );
    });

    it('should not throw when redirectUri missing from auto-config but manually provided', async () => {
      const invalidSdkConfig = { loginUrl: 'https://test.example.com/auth/login' } as SdkConfiguration;
      initWristbandServiceMock(invalidSdkConfig);
      const config = { ...validAuthConfig, redirectUri: 'https://manual.com/callback' };
      resolver = new ConfigResolver(config);

      await expect(resolver.getRedirectUri()).resolves.toBe('https://manual.com/callback');
    });

    it('should return manual applicationAuthorizationRequestsEnabled over auto-configured value', async () => {
      const config = { ...validAuthConfig, applicationAuthorizationRequestsEnabled: true };
      resolver = new ConfigResolver(config);
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        applicationAuthorizationRequestsEnabled: false,
      });

      expect(await resolver.getApplicationAuthorizationRequestsEnabled()).toBe(true);
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(0);
    });

    it('should return auto-configured fallbackLoginUrl value', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        fallbackLoginUrl: 'https://sdk.com/fallback',
      });

      expect(await resolver.getFallbackLoginUrl()).toBe('https://sdk.com/fallback');
    });

    it('should derive fallbackLoginUrl from the manual loginUrl over the auto-configured value', async () => {
      const config = { ...validAuthConfig, loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.manual.com/login` };
      resolver = new ConfigResolver(config);
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        fallbackLoginUrl: 'https://sdk.com/fallback',
      });

      expect(await resolver.getFallbackLoginUrl()).toBe('https://manual.com/login');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(0);
    });
  });

  describe('fetchSdkConfiguration - Error Handling', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should succeed on first attempt', async () => {
      const result = await resolver.getLoginUrl();
      expect(result).toBe('https://test.example.com/auth/login');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    // Retrying on transient failures (5xx errors, network errors) is handled one layer down by
    // WristbandService -- see withRetry() in utils/retry.ts. ConfigResolver itself only ever
    // calls getSdkConfiguration once and maps whatever error (if any) surfaces after that.
    it('should propagate the error immediately without retrying', async () => {
      const error = new Error('Network error');
      mockWristbandService.getSdkConfiguration.mockRejectedValue(error);

      await expect(resolver.getLoginUrl()).rejects.toThrow('Failed to fetch SDK configuration: Network error');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should handle unknown error type', async () => {
      mockWristbandService.getSdkConfiguration.mockRejectedValue('string error');

      await expect(resolver.getLoginUrl()).rejects.toThrow('Failed to fetch SDK configuration: Unknown error');
    });

    it('should handle null error', async () => {
      mockWristbandService.getSdkConfiguration.mockRejectedValue(null);

      await expect(resolver.getLoginUrl()).rejects.toThrow('Failed to fetch SDK configuration: Unknown error');
    });

    it('should handle error without message', async () => {
      const errorWithoutMessage = new Error();
      (errorWithoutMessage as any).message = undefined;
      mockWristbandService.getSdkConfiguration.mockRejectedValue(errorWithoutMessage);

      await expect(resolver.getLoginUrl()).rejects.toThrow('Failed to fetch SDK configuration: Unknown error');
    });
  });

  describe('validateAllDynamicConfigs', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should validate required fields in SDK config', () => {
      const invalidSdkConfig = { redirectUri: 'https://test.com/callback' } as SdkConfiguration;
      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow('SDK configuration response missing required field: loginUrl');
    });

    it('should validate redirectUri is present', () => {
      const invalidSdkConfig = { loginUrl: 'https://test.com/login' } as SdkConfiguration;
      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).toThrow(
        'The [redirectUri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.'
      );
    });

    it('should not throw when redirectUri missing from SDK config but manually provided', () => {
      const manualConfig = { ...validAuthConfig, redirectUri: 'https://manual.com/callback' };
      resolver = new ConfigResolver(manualConfig);

      const invalidSdkConfig = { loginUrl: 'https://test.com/login' } as SdkConfiguration;
      expect(() => {
        return resolver['validateAllDynamicConfigs'](invalidSdkConfig);
      }).not.toThrow();
    });

    it('should require the tenant_name placeholder in the resolved redirectUri when the manual loginUrl has it', () => {
      const manualConfig = { ...validAuthConfig, loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login` };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).toThrow(
        `The resolved [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the resolved [loginUrl] contains it.`
      );
    });

    it('should reject the tenant_name placeholder in the manual redirectUri when the resolved loginUrl does not have it', () => {
      const manualConfig = {
        ...validAuthConfig,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).toThrow(
        `The resolved [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the resolved [loginUrl] does not contain it.`
      );
    });

    it('should trust the SDK config placeholders when both URLs come from the SDK Auto-Configuration Endpoint', () => {
      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: 'https://test.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: 'test.com',
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).not.toThrow();
    });

    it('should pass validation when the manual redirectUri and resolved loginUrl both have the tenant_name placeholder', () => {
      const manualConfig = {
        ...validAuthConfig,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
      };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.test.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.test.com/callback`,
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: 'test.com',
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).not.toThrow();
    });

    it('should use manual config values over SDK config values for validation with tenant_name', () => {
      const manualConfig = {
        ...validAuthConfig,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.manual.com/login`,
      };
      resolver = new ConfigResolver(manualConfig);

      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: 'https://sdk.com/login', // This would fail validation, but manual takes precedence
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.sdk.com/callback`,
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: 'sdk.com',
      };

      expect(() => {
        return resolver['validateAllDynamicConfigs'](sdkConfig);
      }).not.toThrow();
    });
  });

  describe('Caching and Promise Deduplication', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should cache SDK config after first successful fetch', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      await resolver.getLoginUrl();
      await resolver.getRedirectUri();
      await resolver.getCustomApplicationLoginPageUrl();

      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should deduplicate concurrent requests', async () => {
      let resolvePromise: (value: SdkConfiguration) => void;
      const configPromise = new Promise<SdkConfiguration>((resolve) => {
        resolvePromise = resolve;
      });

      mockWristbandService.getSdkConfiguration.mockReturnValue(configPromise);

      const promises = [resolver.getLoginUrl(), resolver.getRedirectUri(), resolver.getCustomApplicationLoginPageUrl()];

      // Resolve after a short delay to ensure all promises are created
      setTimeout(() => {
        return resolvePromise!(validSdkConfig);
      }, 10);

      await Promise.all(promises);
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });

    it('should reset promise on error to allow retry', async () => {
      mockWristbandService.getSdkConfiguration
        .mockRejectedValueOnce(new Error('First error'))
        .mockResolvedValue(validSdkConfig);

      // First call should fail immediately -- retrying transient failures is handled one layer
      // down by WristbandService, so ConfigResolver itself only ever calls
      // getSdkConfiguration once per loadSdkConfig() invocation.
      await expect(resolver.getLoginUrl()).rejects.toThrow();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);

      // Second call should succeed since the cached promise was reset after the error
      const result = await resolver.getRedirectUri();
      expect(result).toBe('https://test.example.com/auth/callback');
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(2);
    });

    it('should use preloadSdkConfig to eagerly load config', async () => {
      mockWristbandService.getSdkConfiguration.mockResolvedValue(validSdkConfig);

      await resolver.preloadSdkConfig();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);

      // Subsequent calls should use cache
      await resolver.getLoginUrl();
      expect(mockWristbandService.getSdkConfiguration).toHaveBeenCalledTimes(1);
    });
  });

  describe('Integration Edge Cases', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should handle boolean values correctly for isApplicationCustomDomainActive', async () => {
      // Test explicit false value
      let config = { ...validAuthConfig, isApplicationCustomDomainActive: false };
      let testResolver = new ConfigResolver(config);
      expect(await testResolver.getIsApplicationCustomDomainActive()).toBe(false);

      // Test explicit true value
      config = { ...validAuthConfig, isApplicationCustomDomainActive: true };
      testResolver = new ConfigResolver(config);
      expect(await testResolver.getIsApplicationCustomDomainActive()).toBe(true);

      // Test undefined value with auto-config false value
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        isApplicationCustomDomainActive: false,
      });
      expect(await resolver.getIsApplicationCustomDomainActive()).toBe(false);

      // Test undefined value with auto-config true value
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        isApplicationCustomDomainActive: true,
      });
      // Create new resolver to reset cache
      testResolver = new ConfigResolver(validAuthConfig);
      expect(await testResolver.getIsApplicationCustomDomainActive()).toBe(true);
    });

    it('should handle boolean values correctly for applicationAuthorizationRequestsEnabled', async () => {
      // Test explicit false value
      let config = { ...validAuthConfig, applicationAuthorizationRequestsEnabled: false };
      let testResolver = new ConfigResolver(config);
      expect(await testResolver.getApplicationAuthorizationRequestsEnabled()).toBe(false);

      // Test explicit true value
      config = { ...validAuthConfig, applicationAuthorizationRequestsEnabled: true };
      testResolver = new ConfigResolver(config);
      expect(await testResolver.getApplicationAuthorizationRequestsEnabled()).toBe(true);

      // Test undefined value with auto-config false value
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        applicationAuthorizationRequestsEnabled: false,
      });
      expect(await resolver.getApplicationAuthorizationRequestsEnabled()).toBe(false);

      // Test undefined value with auto-config true value
      mockWristbandService.getSdkConfiguration.mockResolvedValue({
        ...validSdkConfig,
        applicationAuthorizationRequestsEnabled: true,
      });
      // Create new resolver to reset cache
      testResolver = new ConfigResolver(validAuthConfig);
      expect(await testResolver.getApplicationAuthorizationRequestsEnabled()).toBe(true);
    });

    it('should handle empty string values correctly', async () => {
      const emptySdkConfig = { ...validSdkConfig, customApplicationLoginPageUrl: null };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(emptySdkConfig);

      const config = { ...validAuthConfig, customApplicationLoginPageUrl: '' };
      const testResolver = new ConfigResolver(config);

      expect(await testResolver.getCustomApplicationLoginPageUrl()).toBe('');
      expect(await testResolver.getParseTenantFromRootDomain()).toBe('');
    });

    it('should handle mixed manual and auto-config with empty SDK values', async () => {
      const config = { ...validAuthConfig, loginUrl: 'https://manual.com/login' };
      const testResolver = new ConfigResolver(config);

      const sdkConfig: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: 'https://sdk.com/login',
        redirectUri: 'https://sdk.com/callback',
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(sdkConfig);

      expect(await testResolver.getLoginUrl()).toBe('https://manual.com/login'); // Manual
      expect(await testResolver.getRedirectUri()).toBe('https://sdk.com/callback'); // Auto-config
      expect(await testResolver.getCustomApplicationLoginPageUrl()).toBe(''); // Auto-config empty
      expect(await testResolver.getParseTenantFromRootDomain()).toBe(''); // Derived from manual loginUrl
    });

    it('should handle SDK config with loginUrlTenantDomainSuffix', async () => {
      const sdkConfigWithTenantSuffix: SdkConfiguration = {
        applicationAuthorizationRequestsEnabled: false,
        fallbackLoginUrl: null,
        loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.example.com/login`,
        redirectUri: `https://${TENANT_NAME_PLACEHOLDER}.example.com/callback`,
        customApplicationLoginPageUrl: 'https://example.com/custom-login',
        isApplicationCustomDomainActive: true,
        loginUrlTenantDomainSuffix: 'example.com',
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(sdkConfigWithTenantSuffix);

      expect(await resolver.getParseTenantFromRootDomain()).toBe('example.com');
    });

    it('should derive parseTenantFromRootDomain from the manual loginUrl over SDK loginUrlTenantDomainSuffix', async () => {
      const config = { ...validAuthConfig, loginUrl: `https://${TENANT_NAME_PLACEHOLDER}.manual.com/login` };
      const testResolver = new ConfigResolver(config);

      const sdkConfigWithTenantSuffix: SdkConfiguration = {
        ...validSdkConfig,
        loginUrlTenantDomainSuffix: 'sdk.example.com',
      };
      mockWristbandService.getSdkConfiguration.mockResolvedValue(sdkConfigWithTenantSuffix);

      expect(await testResolver.getParseTenantFromRootDomain()).toBe('manual.com');
    });
  });

  describe('Error Handling Edge Cases', () => {
    let resolver: ConfigResolver;

    beforeEach(() => {
      initWristbandServiceMock(validSdkConfig);
      resolver = new ConfigResolver(validAuthConfig);
    });

    it('should throw TypeError when getLoginUrl called with auto-configure disabled and no manual value', () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        redirectUri: 'https://test.com/callback', // Only redirectUri provided
      };

      expect(() => {
        return new ConfigResolver(config);
      }).toThrow('The [loginUrl] config must have a value when auto-configure is disabled.');
    });

    it('should throw TypeError when getRedirectUri called with auto-configure disabled and no manual value', () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        loginUrl: 'https://test.com/login', // Only loginUrl provided
      };

      expect(() => {
        return new ConfigResolver(config);
      }).toThrow('The [redirectUri] config must have a value when auto-configure is disabled.');
    });

    // With auto-configure disabled, the constructor requires loginUrl, so the final fallbacks in these getters
    // can only be reached by clearing loginUrl after construction.
    it('should return empty string for parseTenantFromRootDomain when auto-configure is disabled and loginUrl is absent', async () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
      };
      const testResolver = new ConfigResolver(config);
      testResolver['authConfig'].loginUrl = undefined;

      expect(await testResolver.getParseTenantFromRootDomain()).toBe('');
      expect(mockWristbandService.getSdkConfiguration).not.toHaveBeenCalled();
    });

    it('should return empty string for fallbackLoginUrl when auto-configure is disabled and loginUrl is absent', async () => {
      const config = {
        ...validAuthConfig,
        autoConfigureEnabled: false,
        loginUrl: 'https://test.com/login',
        redirectUri: 'https://test.com/callback',
      };
      const testResolver = new ConfigResolver(config);
      testResolver['authConfig'].loginUrl = undefined;

      expect(await testResolver.getFallbackLoginUrl()).toBe('');
      expect(mockWristbandService.getSdkConfiguration).not.toHaveBeenCalled();
    });

    it('should throw WristbandError when SDK response validation fails during dynamic config access', async () => {
      const invalidSdkConfig = {
        // Missing required fields
        customApplicationLoginPageUrl: null,
        isApplicationCustomDomainActive: false,
        loginUrlTenantDomainSuffix: null,
      } as SdkConfiguration;

      mockWristbandService.getSdkConfiguration.mockResolvedValue(invalidSdkConfig);

      await expect(resolver.getLoginUrl()).rejects.toThrow(WristbandError);
    });
  });
});
