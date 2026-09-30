import type { NextApiRequest, NextApiResponse } from 'next';

import {
  LoginConfig,
  CallbackData,
  LogoutConfig,
  LoginState,
  CallbackResult,
  UserInfo,
  TokenResponse,
} from '../../types';
import { WristbandService } from '../../wristband-service';
import {
  createLoginState,
  createLoginStateCookie,
  getAndClearLoginStateCookie,
  getAuthorizationUrlParams,
  resolveTenantCustomDomainParam,
  resolveTenantName,
} from '../../utils/auth/pages-router-utils';
import { InvalidGrantError, WristbandError } from '../../error';
import { LOGIN_REQUIRED_ERROR, TENANT_PLACEHOLDER_REGEX } from '../../utils/constants';
import { decryptLoginState, encryptLoginState } from '../../utils/crypto';
import { ConfigResolver } from '../../config-resolver';
import {
  getAppLevelAuthorizationUrl,
  getAppLevelLoginUrl,
  getTenantLevelAuthorizationUrl,
  resolveValidTenantCustomDomain,
} from '../../utils/auth/common-utils';

export class PagesRouterAuthHandler {
  private configResolver: ConfigResolver;
  private wristbandService: WristbandService;

  constructor(configResolver: ConfigResolver, wristbandService: WristbandService) {
    this.configResolver = configResolver;
    this.wristbandService = wristbandService;
  }

  async login(request: NextApiRequest, response: NextApiResponse, loginConfig: LoginConfig = {}): Promise<string> {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');

    // Fetch our SDK configs
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
    const loginStateSecret = this.configResolver.getLoginStateSecret();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const redirectUri = await this.configResolver.getRedirectUri();
    const scopes = this.configResolver.getScopes();
    const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();

    // Determine if a tenant custom domain is present as it will be needed for the authorize URL, if provided.
    const tenantCustomDomain: string = await resolveValidTenantCustomDomain(
      resolveTenantCustomDomainParam(request),
      this.wristbandService
    );
    const tenantName: string = resolveTenantName(request, parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = loginConfig.defaultTenantCustomDomain || '';
    const defaultTenantName: string = loginConfig.defaultTenantName || '';

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(request, redirectUri, {
      customState,
      returnUrl: loginConfig.returnUrl,
    });

    // Create the authroization request params needed, regardless if using app-level or tenant-level Authorize Endpoint.
    const { codeVerifier, state } = loginState;
    const authorizationParamConfig = { clientId, codeVerifier, redirectUri, scopes, state };

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantName && !defaultTenantCustomDomain && !defaultTenantName) {
      if (applicationAuthorizationRequestsEnabled) {
        // Clear any stale login state cookies and add a new one for the current request.
        const domain = parseTenantFromRootDomain ? `.${parseTenantFromRootDomain}` : undefined;
        const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
        createLoginStateCookie(
          request,
          response,
          loginState.state,
          encryptedLoginState,
          dangerouslyDisableSecureCookies,
          domain
        );

        // Send users to the app-level Authorize Endpoint with a login state cookie instead of going to login URL.
        const authorizationParams = await getAuthorizationUrlParams(request, authorizationParamConfig);
        return getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, authorizationParams);
      }

      // For the login URL scenario, we don't actually want to touch any login state cookies.
      return getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, customApplicationLoginPageUrl);
    }

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
    createLoginStateCookie(request, response, loginState.state, encryptedLoginState, dangerouslyDisableSecureCookies);

    // Return the tenant-level Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizationParams = await getAuthorizationUrlParams(request, authorizationParamConfig);
    return getTenantLevelAuthorizationUrl(wristbandApplicationVanityDomain, authorizationParams, {
      isApplicationCustomDomainActive,
      tenantCustomDomain,
      tenantName,
      defaultTenantCustomDomain,
      defaultTenantName,
    });
  }

  async callback(request: NextApiRequest, response: NextApiResponse): Promise<CallbackResult> {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');

    // Fetch our SDK configs
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();
    const loginStateSecret = this.configResolver.getLoginStateSecret();
    const loginUrl = await this.configResolver.getLoginUrl();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

    // Safety checks -- Wristband backend should never send bad query params
    const {
      code,
      state: paramState,
      error,
      error_description: errorDescription,
      tenant_custom_domain: rawTenantCustomDomainParam,
    } = request.query;
    if (!paramState || typeof paramState !== 'string') {
      throw new TypeError('Invalid query parameter [state] passed from Wristband during callback');
    }
    if (!!code && typeof code !== 'string') {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    if (!!error && typeof error !== 'string') {
      throw new TypeError('Invalid query parameter [error] passed from Wristband during callback');
    }
    if (!!errorDescription && typeof errorDescription !== 'string') {
      throw new TypeError('Invalid query parameter [error_description] passed from Wristband during callback');
    }
    if (!!rawTenantCustomDomainParam && typeof rawTenantCustomDomainParam !== 'string') {
      throw new TypeError('Invalid query parameter [tenant_custom_domain] passed from Wristband during callback');
    }

    // An unverified tenant custom domain is skipped so the flow falls through to the next
    // entry in the domain precedence order.
    const tenantCustomDomainParam: string = await resolveValidTenantCustomDomain(
      rawTenantCustomDomainParam || '',
      this.wristbandService
    );

    // Resolve and validate the tenant name
    const resolvedTenantName: string = resolveTenantName(request, parseTenantFromRootDomain);
    if (!resolvedTenantName) {
      throw new WristbandError(
        parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_name',
        parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_name] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = parseTenantFromRootDomain
      ? loginUrl.replace(TENANT_PLACEHOLDER_REGEX, resolvedTenantName)
      : `${loginUrl}?tenant_name=${resolvedTenantName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const domain =
      applicationAuthorizationRequestsEnabled && parseTenantFromRootDomain
        ? `.${parseTenantFromRootDomain}`
        : undefined;
    const loginStateCookie: string = getAndClearLoginStateCookie(
      request,
      response,
      dangerouslyDisableSecureCookies,
      domain
    );
    if (!loginStateCookie) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'missing_login_state' };
    }

    const loginState: LoginState = await decryptLoginState(loginStateCookie, loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'invalid_login_state' };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'login_required' };
      }
      throw new WristbandError(error, errorDescription || '');
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }

    let tokenResponse: TokenResponse;
    try {
      tokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
    } catch (err: unknown) {
      if (err instanceof InvalidGrantError) {
        return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'invalid_grant' };
      }
      throw new WristbandError('unexpected_error', 'Unexpected error', err instanceof Error ? err : undefined);
    }

    const {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
    } = tokenResponse;

    // Fetch the userinfo for the user logging in.
    const userinfo: UserInfo = await this.wristbandService.getUserinfo(accessToken);

    const resolvedExpiresIn = expiresIn - (tokenExpirationBuffer || 0);
    const resolvedExpiresAt = Date.now() + resolvedExpiresIn * 1000;

    const callbackData: CallbackData = {
      accessToken,
      ...(!!customState && { customState }),
      expiresAt: resolvedExpiresAt,
      expiresIn: resolvedExpiresIn,
      idToken,
      ...(!!refreshToken && { refreshToken }),
      ...(!!returnUrl && { returnUrl }),
      ...(!!tenantCustomDomainParam && { tenantCustomDomain: tenantCustomDomainParam }),
      tenantName: resolvedTenantName,
      userinfo,
    };
    return { type: 'completed', callbackData };
  }

  async logout(
    request: NextApiRequest,
    response: NextApiResponse,
    logoutConfig: LogoutConfig = { tenantCustomDomain: '' }
  ): Promise<string> {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');

    // Fetch our SDK configs
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const fallbackLoginUrl = await this.configResolver.getFallbackLoginUrl();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
    const loginUrl = await this.configResolver.getLoginUrl();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();

    // Revoke the refresh token only if present.
    if (logoutConfig.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(logoutConfig.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    if (logoutConfig.state && logoutConfig.state.length > 512) {
      throw new TypeError('The [state] logout config cannot exceed 512 characters.');
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = logoutConfig.redirectUrl ? `&redirect_url=${logoutConfig.redirectUrl}` : '';
    const state = logoutConfig.state ? `&state=${logoutConfig.state}` : '';
    const logoutPath: string = `/api/v1/logout?client_id=${clientId}${logoutRedirectUrl}${state}`;
    const separator = isApplicationCustomDomainActive ? '.' : '-';
    const tenantCustomDomainParam: string = await resolveValidTenantCustomDomain(
      resolveTenantCustomDomainParam(request),
      this.wristbandService
    );
    const tenantName: string = resolveTenantName(request, parseTenantFromRootDomain);

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    if (logoutConfig.tenantCustomDomain) {
      return `https://${logoutConfig.tenantCustomDomain}${logoutPath}`;
    }

    // 2) If the LogoutConfig has a tenant name defined, then use that.
    if (logoutConfig.tenantName) {
      return `https://${logoutConfig.tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // 3) If the tenant_custom_domain query param exists, then use that.
    if (tenantCustomDomainParam) {
      return `https://${tenantCustomDomainParam}${logoutPath}`;
    }

    // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
    if (tenantName) {
      return `https://${tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // 5) First try falling back to the Logout Redirect URL (if the LogoutConfig has it) when tenant cannot be resolved.
    if (logoutConfig.redirectUrl) {
      return logoutConfig.redirectUrl;
    }

    // 6) If app-level authorization requests are enabled, then redirect to appropriate app-level Login Endpoint
    // to start a new app-level Authorize Endpoint flow.
    if (applicationAuthorizationRequestsEnabled) {
      return TENANT_PLACEHOLDER_REGEX.test(loginUrl) ? fallbackLoginUrl : loginUrl;
    }

    // 7a) If a custom page URL is set, fallback to that appropriate Application-Level Login when tenant cannot be resolved.
    // 7b) Finally, fallback to the Wristband-hosted Application-Level Login Page when tenant cannot be resolved.
    return getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, customApplicationLoginPageUrl);
  }
}
