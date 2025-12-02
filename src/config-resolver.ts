import { WristbandError } from './error';
import { AuthConfig, SdkConfiguration } from './types';
import { TENANT_PLACEHOLDER_MSG, TENANT_PLACEHOLDER_REGEX } from './utils/constants';
import { WristbandService } from './wristband-service';

const DEFAULT_SCOPES = ['openid', 'offline_access', 'email'];
const DEFAULT_TOKEN_EXPIRATION_BUFFER = 60; // 60 seconds
const MAX_FETCH_ATTEMPTS = 3;
const ATTEMPT_DELAY_MS = 100; // 100 milliseconds

export class ConfigResolver {
  private authConfig: AuthConfig;
  private wristbandService: WristbandService;
  private sdkConfigCache: SdkConfiguration | null = null;
  private configPromise: Promise<SdkConfiguration> | null = null;

  constructor(authConfig: AuthConfig) {
    this.authConfig = authConfig;

    // Always validate the following:
    // - ClientId
    // - ClientSecret
    // - LoginStateSecret
    // - WristbandApplicationVanityDomain
    this.validateRequiredAuthConfigs();

    if (!this.getAutoConfigureEnabled()) {
      // Validate the following if auto-configure is disabled:
      // - loginUrl
      // - redirectUri
      // - parseTenantFromRootDomain
      this.validateStrictUrlAuthConfigs();
    } else {
      // Only validate manually provided values when auto-configure is enabled
      this.validatePartialUrlAuthConfigs();
    }

    this.wristbandService = new WristbandService(
      authConfig.wristbandApplicationVanityDomain,
      authConfig.clientId,
      authConfig.clientSecret
    );
  }

  async preloadSdkConfig(): Promise<void> {
    await this.loadSdkConfig();
  }

  private async loadSdkConfig(): Promise<SdkConfiguration> {
    // Return cached config if available
    if (this.sdkConfigCache) {
      return this.sdkConfigCache;
    }

    // Return existing promise if already fetching
    if (this.configPromise) {
      const result = await this.configPromise;
      return result;
    }

    try {
      this.configPromise = this.fetchSdkConfiguration();
      this.sdkConfigCache = await this.configPromise;
      this.validateAllDynamicConfigs(this.sdkConfigCache);
      return this.sdkConfigCache;
    } catch (error) {
      // Reset promise on error so retry is possible
      this.configPromise = null;
      throw error;
    }
  }

  private async fetchSdkConfiguration(): Promise<SdkConfiguration> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= MAX_FETCH_ATTEMPTS; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const config = await this.wristbandService.getSdkConfiguration();
        return config;
      } catch (error) {
        lastError = error as Error;

        // Final attempt failed, throw the error
        if (attempt === MAX_FETCH_ATTEMPTS) {
          break;
        }

        // Wait before retrying
        // eslint-disable-next-line no-await-in-loop
        await new Promise<void>((resolve) => {
          setTimeout(resolve, ATTEMPT_DELAY_MS);
        });
      }
    }

    throw new WristbandError(
      `Failed to fetch SDK configuration after ${MAX_FETCH_ATTEMPTS} attempts: ${lastError?.message || 'Unknown error'}`
    );
  }

  private validateRequiredAuthConfigs(): void {
    if (!this.authConfig.clientId || !this.authConfig.clientId.trim()) {
      throw new TypeError('The [clientId] config must have a value.');
    }
    if (!this.authConfig.clientSecret || !this.authConfig.clientSecret.trim()) {
      throw new TypeError('The [clientSecret] config must have a value.');
    }
    if (this.authConfig.loginStateSecret && this.authConfig.loginStateSecret.length < 32) {
      throw new TypeError('The [loginStateSecret] config must have a value of at least 32 characters.');
    }
    if (!this.authConfig.wristbandApplicationVanityDomain || !this.authConfig.wristbandApplicationVanityDomain.trim()) {
      throw new TypeError('The [wristbandApplicationVanityDomain] config must have a value.');
    }
    if (this.authConfig.tokenExpirationBuffer && this.authConfig.tokenExpirationBuffer < 0) {
      throw new TypeError('The [tokenExpirationBuffer] config must be greater than or equal to 0.');
    }
    if (this.authConfig.parseTenantFromRootDomain && this.authConfig.parseTenantFromRootDomain.includes(':')) {
      throw new TypeError(`The [parseTenantFromRootDomain] config should not include a port.`);
    }
  }

  private validateStrictUrlAuthConfigs(): void {
    if (!this.authConfig.loginUrl || !this.authConfig.loginUrl.trim()) {
      throw new TypeError('The [loginUrl] config must have a value when auto-configure is disabled.');
    }
    if (!this.authConfig.redirectUri || !this.authConfig.redirectUri.trim()) {
      throw new TypeError('The [redirectUri] config must have a value when auto-configure is disabled.');
    }

    if (this.authConfig.parseTenantFromRootDomain) {
      if (!TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl)) {
        throw new TypeError(
          `The [loginUrl] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      }
      if (!TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri)) {
        throw new TypeError(
          `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      }
    } else {
      if (TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl)) {
        throw new TypeError(
          `The [loginUrl] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      }
      if (TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri)) {
        throw new TypeError(
          `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      }
    }
  }

  private validatePartialUrlAuthConfigs(): void {
    if (this.authConfig.loginUrl) {
      if (this.authConfig.parseTenantFromRootDomain && !TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl)) {
        throw new TypeError(
          `The [loginUrl] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      }
      if (!this.authConfig.parseTenantFromRootDomain && TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl)) {
        throw new TypeError(
          `The [loginUrl] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      }
    }

    if (this.authConfig.redirectUri) {
      if (this.authConfig.parseTenantFromRootDomain && !TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri)) {
        throw new TypeError(
          `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when using the [parseTenantFromRootDomain] config.`
        );
      }
      if (!this.authConfig.parseTenantFromRootDomain && TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri)) {
        throw new TypeError(
          `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [parseTenantFromRootDomain] is absent.`
        );
      }
    }
  }

  // Method to preload and validate all configurations
  private validateAllDynamicConfigs(sdkConfiguration: SdkConfiguration): void {
    // Validate that required fields are present in the SDK config response
    if (!sdkConfiguration.loginUrl) {
      throw new WristbandError('SDK configuration response missing required field: loginUrl');
    }
    if (!sdkConfiguration.redirectUri) {
      throw new WristbandError('SDK configuration response missing required field: redirectUri');
    }

    // Use manual config values if provided, otherwise use SDK config values
    const loginUrl = this.authConfig.loginUrl || sdkConfiguration.loginUrl;
    const redirectUri = this.authConfig.redirectUri || sdkConfiguration.redirectUri;
    const parseTenantFromRootDomain =
      this.authConfig.parseTenantFromRootDomain || sdkConfiguration.loginUrlTenantDomainSuffix || '';

    // Validate the tenant name placeholder logic with final resolved values
    if (parseTenantFromRootDomain) {
      if (!TENANT_PLACEHOLDER_REGEX.test(loginUrl)) {
        throw new WristbandError(
          `The resolved [loginUrl] must contain the ${TENANT_PLACEHOLDER_MSG} when using [parseTenantFromRootDomain].`
        );
      }
      if (!TENANT_PLACEHOLDER_REGEX.test(redirectUri)) {
        throw new WristbandError(
          `The resolved [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when using [parseTenantFromRootDomain].`
        );
      }
    } else {
      if (TENANT_PLACEHOLDER_REGEX.test(loginUrl)) {
        throw new WristbandError(
          `The resolved [loginUrl] cannot contain the ${TENANT_PLACEHOLDER_MSG} when [parseTenantFromRootDomain] is absent.`
        );
      }
      if (TENANT_PLACEHOLDER_REGEX.test(redirectUri)) {
        throw new WristbandError(
          `The resolved [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when [parseTenantFromRootDomain] is absent.`
        );
      }
    }
  }

  // ////////////////////////////////////
  //  STATIC CONFIGURATIONS
  // ////////////////////////////////////

  public getClientId(): string {
    return this.authConfig.clientId;
  }

  public getClientSecret(): string {
    return this.authConfig.clientSecret;
  }

  public getLoginStateSecret(): string {
    return this.authConfig.loginStateSecret || this.authConfig.clientSecret;
  }

  public getWristbandApplicationVanityDomain(): string {
    return this.authConfig.wristbandApplicationVanityDomain;
  }

  public getDangerouslyDisableSecureCookies(): boolean {
    return this.authConfig.dangerouslyDisableSecureCookies ?? false;
  }

  public getScopes(): string[] {
    return this.authConfig.scopes?.length ? this.authConfig.scopes : DEFAULT_SCOPES;
  }

  public getAutoConfigureEnabled(): boolean {
    return this.authConfig.autoConfigureEnabled !== false;
  }

  public getTokenExpirationBuffer(): number {
    return this.authConfig.tokenExpirationBuffer ?? DEFAULT_TOKEN_EXPIRATION_BUFFER;
  }

  // ////////////////////////////////////
  //  DYNAMIC CONFIGURATIONS
  // ////////////////////////////////////

  public async getCustomApplicationLoginPageUrl(): Promise<string> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.customApplicationLoginPageUrl) {
      return this.authConfig.customApplicationLoginPageUrl;
    }

    // 2. If auto-configure is enabled, get from SDK config
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.customApplicationLoginPageUrl || '';
    }

    // 3. Default fallback
    return '';
  }

  public async getIsApplicationCustomDomainActive(): Promise<boolean> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.isApplicationCustomDomainActive !== undefined) {
      return this.authConfig.isApplicationCustomDomainActive;
    }

    // 2. If auto-configure is enabled, get from SDK config
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.isApplicationCustomDomainActive ?? false;
    }

    // 3. Default fallback
    return false;
  }

  public async getLoginUrl(): Promise<string> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.loginUrl) {
      return this.authConfig.loginUrl;
    }

    // 2. If auto-configure is enabled, get from SDK config cache
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.loginUrl;
    }

    // 3. This should not happen if validation is done properly
    throw new TypeError('The [loginUrl] config must have a value');
  }

  public async getParseTenantFromRootDomain(): Promise<string> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.parseTenantFromRootDomain) {
      return this.authConfig.parseTenantFromRootDomain;
    }

    // 2. If auto-configure is enabled, get from SDK config
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.loginUrlTenantDomainSuffix || '';
    }

    // 3. Default fallback
    return '';
  }

  public async getRedirectUri(): Promise<string> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.redirectUri) {
      return this.authConfig.redirectUri;
    }

    // 2. If auto-configure is enabled, get from SDK config cache
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.redirectUri;
    }

    // 3. This should not happen if validation is done properly
    throw new TypeError('The [redirectUri] config must have a value');
  }
}
