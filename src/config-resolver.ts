import { WristbandError } from './error';
import { AuthConfig, SdkConfiguration } from './types';
import {
  deriveFallbackLoginUrl,
  deriveTenantRootDomain,
  isTenantPlaceholderPositionValid,
} from './utils/auth/common-utils';
import { TENANT_PLACEHOLDER_MSG, TENANT_PLACEHOLDER_REGEX } from './utils/constants';
import { WristbandService } from './wristband-service';

const DEFAULT_SCOPES = ['openid', 'offline_access', 'email'];
const DEFAULT_TOKEN_EXPIRATION_BUFFER = 60; // 60 seconds

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

  // Retrying on transient failures (5xx errors, network errors) is already handled one layer
  // down by WristbandService -- see withRetry() in utils/retry.ts. By the time an error surfaces
  // here, retries (if any applied) have already been exhausted.
  private async fetchSdkConfiguration(): Promise<SdkConfiguration> {
    try {
      return await this.wristbandService.getSdkConfiguration();
    } catch (error) {
      const message = error instanceof Error ? error.message : undefined;
      throw new WristbandError(`Failed to fetch SDK configuration: ${message || 'Unknown error'}`);
    }
  }

  private validateTenantPlaceholderPosition(configName: 'loginUrl' | 'redirectUri', url: string): void {
    if (!isTenantPlaceholderPositionValid(url)) {
      throw new TypeError(
        `The [${configName}] can only contain the ${TENANT_PLACEHOLDER_MSG} once, as the leftmost part of its hostname.`
      );
    }
  }

  /**
   * Validates the configs that are always required, regardless of whether auto-configure is enabled.
   *
   * These values cannot come from the SDK Auto-Configuration Endpoint, so they are checked up front. This method
   * checks that:
   * - [clientId], [clientSecret], and [wristbandApplicationVanityDomain] each have a non-blank value.
   * - [loginStateSecret], when provided, is at least 32 characters long.
   * - [tokenExpirationBuffer], when provided, is greater than or equal to 0.
   *
   * @throws {TypeError} If any config fails the checks above.
   */
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
  }

  /**
   * Validates the URL configs when auto-configure is disabled.
   *
   * With auto-configure disabled, the SDK has no other source for [loginUrl] and [redirectUri], so both are
   * required. This method checks that:
   * - Both [loginUrl] and [redirectUri] have a value.
   * - Each URL can only contain the {tenant_name} placeholder once, as the leftmost part of its hostname.
   * - Either both URLs contain the {tenant_name} placeholder or neither does.
   *
   * @throws {TypeError} If either URL is missing or fails any of the checks above.
   */
  private validateStrictUrlAuthConfigs(): void {
    if (!this.authConfig.loginUrl || !this.authConfig.loginUrl.trim()) {
      throw new TypeError('The [loginUrl] config must have a value when auto-configure is disabled.');
    }
    if (!this.authConfig.redirectUri || !this.authConfig.redirectUri.trim()) {
      throw new TypeError('The [redirectUri] config must have a value when auto-configure is disabled.');
    }

    this.validateTenantPlaceholderPosition('loginUrl', this.authConfig.loginUrl);
    this.validateTenantPlaceholderPosition('redirectUri', this.authConfig.redirectUri);

    const loginUrlHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl);
    const redirectUriHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri);

    if (loginUrlHasPlaceholder && !redirectUriHasPlaceholder) {
      throw new TypeError(
        `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] contains it.`
      );
    }
    if (!loginUrlHasPlaceholder && redirectUriHasPlaceholder) {
      throw new TypeError(
        `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] does not contain it.`
      );
    }
  }

  /**
   * Validates the manually provided URL configs when auto-configure is enabled.
   *
   * With auto-configure enabled, [loginUrl] and [redirectUri] are optional, and any value that is not provided
   * comes from the SDK Auto-Configuration Endpoint later. This method only checks the values that are provided:
   * - Each provided URL can only contain the {tenant_name} placeholder once, as the leftmost part of its hostname.
   * - When both URLs are provided, either both contain the {tenant_name} placeholder or neither does.
   *
   * When only one of the two URLs is provided, the placeholder comparison happens in validateAllDynamicConfigs()
   * instead, once the other URL is available from the SDK Auto-Configuration Endpoint.
   *
   * @throws {TypeError} If a provided URL fails any of the checks above.
   */
  private validatePartialUrlAuthConfigs(): void {
    if (this.authConfig.loginUrl) {
      this.validateTenantPlaceholderPosition('loginUrl', this.authConfig.loginUrl);
    }
    if (this.authConfig.redirectUri) {
      this.validateTenantPlaceholderPosition('redirectUri', this.authConfig.redirectUri);
    }

    if (this.authConfig.loginUrl && this.authConfig.redirectUri) {
      const loginUrlHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(this.authConfig.loginUrl);
      const redirectUriHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(this.authConfig.redirectUri);
      if (loginUrlHasPlaceholder && !redirectUriHasPlaceholder) {
        throw new TypeError(
          `The [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] contains it.`
        );
      }
      if (!loginUrlHasPlaceholder && redirectUriHasPlaceholder) {
        throw new TypeError(
          `The [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the [loginUrl] does not contain it.`
        );
      }
    }
  }

  /**
   * Validates the final resolved URL configs after the SDK Auto-Configuration Endpoint responds.
   *
   * Each of [loginUrl] and [redirectUri] resolves to the manually provided value if there is one, otherwise to
   * the value returned by the SDK Auto-Configuration Endpoint. This method checks that:
   * - Both resolved URLs have a value.
   * - When at least one of the two URLs was provided manually, either both resolved URLs contain the
   *   {tenant_name} placeholder or neither does.
   *
   * When both URLs come from the SDK Auto-Configuration Endpoint, their placeholders are trusted as-is.
   *
   * @param {SdkConfiguration} sdkConfiguration The response from the SDK Auto-Configuration Endpoint.
   * @throws {WristbandError} If either resolved URL is missing or fails the check above.
   */
  private validateAllDynamicConfigs(sdkConfiguration: SdkConfiguration): void {
    // Use manual config values if provided, otherwise use SDK config values
    const loginUrl = this.authConfig.loginUrl || sdkConfiguration.loginUrl || '';
    const redirectUri = this.authConfig.redirectUri || sdkConfiguration.redirectUri || '';

    // Validate that required fields are present in the SDK config response
    if (!loginUrl) {
      throw new WristbandError('SDK configuration response missing required field: loginUrl');
    }
    if (!redirectUri) {
      throw new WristbandError(
        'The [redirectUri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.'
      );
    }

    // Only one of loginUrl and redirectUri may have come from the manual config, so compare the final
    // resolved values. Values that both come from the SDK Auto-Configuration Endpoint are trusted as-is.
    if (this.authConfig.loginUrl || this.authConfig.redirectUri) {
      const loginUrlHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(loginUrl);
      const redirectUriHasPlaceholder = TENANT_PLACEHOLDER_REGEX.test(redirectUri);
      if (loginUrlHasPlaceholder && !redirectUriHasPlaceholder) {
        throw new WristbandError(
          `The resolved [redirectUri] must contain the ${TENANT_PLACEHOLDER_MSG} when the resolved [loginUrl] contains it.`
        );
      }
      if (!loginUrlHasPlaceholder && redirectUriHasPlaceholder) {
        throw new WristbandError(
          `The resolved [redirectUri] cannot contain the ${TENANT_PLACEHOLDER_MSG} when the resolved [loginUrl] does not contain it.`
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
    // 1. Derive from the manually provided loginUrl
    if (this.authConfig.loginUrl) {
      return deriveTenantRootDomain(this.authConfig.loginUrl);
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

  public async getApplicationAuthorizationRequestsEnabled(): Promise<boolean> {
    // 1. Check if manually provided in authConfig
    if (this.authConfig.applicationAuthorizationRequestsEnabled !== undefined) {
      return this.authConfig.applicationAuthorizationRequestsEnabled;
    }

    // 2. If auto-configure is enabled, get from SDK config
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.applicationAuthorizationRequestsEnabled ?? true;
    }

    // 3. Default fallback
    return true;
  }

  public async getFallbackLoginUrl(): Promise<string> {
    // 1. Derive from the manually provided loginUrl
    if (this.authConfig.loginUrl) {
      return deriveFallbackLoginUrl(this.authConfig.loginUrl);
    }

    // 2. If auto-configure is enabled, get from SDK config
    if (this.getAutoConfigureEnabled()) {
      const sdkConfig = await this.loadSdkConfig();
      return sdkConfig.fallbackLoginUrl || '';
    }

    // 3. Default fallback
    return '';
  }
}
