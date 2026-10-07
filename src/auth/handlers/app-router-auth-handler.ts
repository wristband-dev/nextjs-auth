import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { SessionData, SessionOptions } from '@wristband/typescript-session';

import { ConfigResolver } from '../../config-resolver';
import { InvalidGrantError, WristbandError } from '../../error';
import { getMutableSessionFromCookies, saveSessionWithCookies } from '../../session';
import {
  CallbackResult,
  LoginConfig,
  LogoutConfig,
  LoginState,
  TokenResponse,
  UserInfo,
  CallbackData,
  AppRouterLoginStateCookie,
  NextJsCookieStore,
  ServerActionAuthResult,
} from '../../types';
import {
  clearLoginStateCookie,
  createLoginState,
  createLoginStateCookie,
  getAuthorizationUrlParams,
  getLoginStateCookie,
  resolveTenantCustomDomainParam,
  resolveTenantName,
} from '../../utils/auth/app-router-utils';
import {
  getAppLevelAuthorizationUrl,
  getAppLevelLoginUrl,
  getTenantLevelAuthorizationUrl,
  refreshExpiredToken,
  resolveValidTenantCustomDomain,
} from '../../utils/auth/common-utils';
import { decryptLoginState, encryptLoginState } from '../../utils/crypto';
import { LOGIN_REQUIRED_ERROR, REDIRECT_RESPONSE_INIT, TENANT_PLACEHOLDER_REGEX } from '../../utils/constants';
import { WristbandService } from '../../wristband-service';

export class AppRouterAuthHandler {
  private configResolver: ConfigResolver;
  private wristbandService: WristbandService;

  constructor(configResolver: ConfigResolver, wristbandService: WristbandService) {
    this.configResolver = configResolver;
    this.wristbandService = wristbandService;
  }

  async login(request: NextRequest, loginConfig: LoginConfig = {}): Promise<NextResponse> {
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

    // Create the authorization request params needed, regardless if using app-level or tenant-level Authorize Endpoint.
    const { codeVerifier, state } = loginState;
    const authorizationParamConfig = { clientId, codeVerifier, redirectUri, scopes, state };

    // Determine whether to use the root domain for the login state cookie.
    const cookieDomain =
      applicationAuthorizationRequestsEnabled && parseTenantFromRootDomain
        ? `.${parseTenantFromRootDomain}`
        : undefined;

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantName && !defaultTenantCustomDomain && !defaultTenantName) {
      if (applicationAuthorizationRequestsEnabled) {
        // Send users to the app-level Authorize Endpoint with a login state cookie instead of going to login URL.
        const authorizationParams = await getAuthorizationUrlParams(request, authorizationParamConfig);
        const appAuthorizeUrl = getAppLevelAuthorizationUrl(wristbandApplicationVanityDomain, authorizationParams);
        const appAuthorizeResponse = NextResponse.redirect(appAuthorizeUrl, REDIRECT_RESPONSE_INIT);

        // Clear any stale login state cookies and add a new one for the current request.
        const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
        createLoginStateCookie(
          request,
          appAuthorizeResponse,
          loginState.state,
          encryptedLoginState,
          dangerouslyDisableSecureCookies,
          cookieDomain
        );

        return appAuthorizeResponse;
      }

      // For the login URL scenario, we don't actually want to touch any login state cookies.
      const apploginUrl = getAppLevelLoginUrl(
        wristbandApplicationVanityDomain,
        clientId,
        customApplicationLoginPageUrl
      );
      return NextResponse.redirect(apploginUrl, REDIRECT_RESPONSE_INIT);
    }

    // Create the tenant-level Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizationParams = await getAuthorizationUrlParams(request, authorizationParamConfig);
    const tenantAuthorizeUrl: string = getTenantLevelAuthorizationUrl(
      wristbandApplicationVanityDomain,
      authorizationParams,
      {
        isApplicationCustomDomainActive,
        tenantCustomDomain,
        tenantName,
        defaultTenantCustomDomain,
        defaultTenantName,
      }
    );
    const tenantAuthorizeResponse = NextResponse.redirect(tenantAuthorizeUrl, REDIRECT_RESPONSE_INIT);

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
    createLoginStateCookie(
      request,
      tenantAuthorizeResponse,
      loginState.state,
      encryptedLoginState,
      dangerouslyDisableSecureCookies,
      cookieDomain
    );

    return tenantAuthorizeResponse;
  }

  async callback(request: NextRequest): Promise<CallbackResult> {
    // Fetch our SDK configs
    const loginStateSecret = this.configResolver.getLoginStateSecret();
    const loginUrl = await this.configResolver.getLoginUrl();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

    const codeArray = request.nextUrl.searchParams.getAll('code');
    const paramStateArray = request.nextUrl.searchParams.getAll('state');
    const errorArray = request.nextUrl.searchParams.getAll('error');
    const errorDescriptionArray = request.nextUrl.searchParams.getAll('error_description');
    const tenantCustomDomainParamArray = request.nextUrl.searchParams.getAll('tenant_custom_domain');

    // Safety checks -- Wristband backend should never send bad query params
    if (paramStateArray.length !== 1) {
      throw new TypeError('Invalid query parameter [state] passed from Wristband during callback');
    }
    if (codeArray.length > 1) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    if (errorArray.length > 1) {
      throw new TypeError('Invalid query parameter [error] passed from Wristband during callback');
    }
    if (errorDescriptionArray.length > 1) {
      throw new TypeError('Invalid query parameter [error_description] passed from Wristband during callback');
    }
    if (tenantCustomDomainParamArray.length > 1) {
      throw new TypeError('Invalid query parameter [tenant_custom_domain] passed from Wristband during callback');
    }

    const code = codeArray[0] || '';
    const paramState = paramStateArray[0] || '';
    const error = errorArray[0] || '';
    const errorDescription = errorDescriptionArray[0] || '';
    // An unverified tenant custom domain is skipped so the flow falls through to the next
    // entry in the domain precedence order.
    const tenantCustomDomainParam = await resolveValidTenantCustomDomain(
      tenantCustomDomainParamArray[0] || '',
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

    // Make sure the login state cookie exists.
    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(request);
    if (!loginStateCookie) {
      return { type: 'redirect_required', redirectUrl: tenantLoginUrl, reason: 'missing_login_state' };
    }

    // Extract the login state from the cookie.
    const loginState: LoginState = await decryptLoginState(loginStateCookie.value, loginStateSecret);
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

    // Get a minimal set of the user's data to store in their session data.
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

  async createCallbackResponse(request: NextRequest, redirectUrl: string): Promise<NextResponse> {
    // Fetch our SDK configs
    const applicationAuthorizationRequestsEnabled =
      await this.configResolver.getApplicationAuthorizationRequestsEnabled();
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();
    const parseTenantFromRootDomain = await this.configResolver.getParseTenantFromRootDomain();

    if (!redirectUrl) {
      throw new TypeError('redirectUrl cannot be null or empty');
    }

    const redirectResponse = NextResponse.redirect(redirectUrl, REDIRECT_RESPONSE_INIT);

    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(request);
    if (loginStateCookie) {
      // Determine whether to use the root domain for clearing the login state cookie.
      const cookieDomain =
        applicationAuthorizationRequestsEnabled && parseTenantFromRootDomain
          ? `.${parseTenantFromRootDomain}`
          : undefined;
      await clearLoginStateCookie(
        redirectResponse,
        loginStateCookie.name,
        dangerouslyDisableSecureCookies,
        cookieDomain
      );
    }

    return redirectResponse;
  }

  async logout(request: NextRequest, logoutConfig: LogoutConfig = {}): Promise<NextResponse> {
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
      } catch {
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
      return NextResponse.redirect(`https://${logoutConfig.tenantCustomDomain}${logoutPath}`, REDIRECT_RESPONSE_INIT);
    }

    // 2) If the LogoutConfig has a tenant name defined, then use that.
    if (logoutConfig.tenantName) {
      return NextResponse.redirect(
        `https://${logoutConfig.tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`,
        REDIRECT_RESPONSE_INIT
      );
    }

    // 3) If the tenant_custom_domain query param exists, then use that.
    if (tenantCustomDomainParam) {
      return NextResponse.redirect(`https://${tenantCustomDomainParam}${logoutPath}`, REDIRECT_RESPONSE_INIT);
    }

    // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
    if (tenantName) {
      return NextResponse.redirect(
        `https://${tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`,
        REDIRECT_RESPONSE_INIT
      );
    }

    // 5) First try falling back to the Logout Redirect URL (if the LogoutConfig has it) when tenant cannot be resolved.
    if (logoutConfig.redirectUrl) {
      return NextResponse.redirect(logoutConfig.redirectUrl, REDIRECT_RESPONSE_INIT);
    }

    // 6) If app-level authorization requests are enabled, then redirect to appropriate app-level Login Endpoint
    // to start a new app-level Authorize Endpoint flow.
    if (applicationAuthorizationRequestsEnabled) {
      return NextResponse.redirect(
        TENANT_PLACEHOLDER_REGEX.test(loginUrl) ? fallbackLoginUrl : loginUrl,
        REDIRECT_RESPONSE_INIT
      );
    }

    // 7a) If a custom page URL is set, fallback to that appropriate Application-Level Login when tenant cannot be resolved.
    // 7b) Finally, fallback to the Wristband-hosted Application-Level Login Page when tenant cannot be resolved.
    const apploginUrl = getAppLevelLoginUrl(wristbandApplicationVanityDomain, clientId, customApplicationLoginPageUrl);
    return NextResponse.redirect(apploginUrl, REDIRECT_RESPONSE_INIT);
  }

  /**
   * Validates authentication for Server Actions by checking session validity and refreshing tokens if needed.
   *
   * This method:
   * - Retrieves the session from cookies
   * - Checks if the user is authenticated
   * - Automatically refreshes expired access tokens
   * - Saves updated tokens back to cookies
   *
   * Note: CSRF validation is not performed as Next.js Server Actions have built-in
   * CSRF protection via Origin/Host header comparison.
   *
   * @template T - Session data type extending SessionData
   * @param cookieStore - Next.js cookie store from await cookies()
   * @param sessionOptions - Session configuration options
   * @returns Promise resolving to authentication result with session data or failure reason
   */
  async createServerActionAuth<T extends SessionData = SessionData>(
    cookieStore: NextJsCookieStore,
    sessionOptions: SessionOptions
  ): Promise<ServerActionAuthResult<T>> {
    try {
      // Get mutable session from cookies
      const session = await getMutableSessionFromCookies<T>(cookieStore, sessionOptions);
      const { expiresAt, isAuthenticated, refreshToken } = session;

      // Check if user is authenticated
      if (!isAuthenticated) {
        return { authenticated: false, reason: 'not_authenticated' };
      }

      // Refresh token if expired
      if (refreshToken && expiresAt !== undefined) {
        try {
          const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();
          const newTokenData = await refreshExpiredToken(
            refreshToken,
            expiresAt,
            this.wristbandService,
            tokenExpirationBuffer
          );

          if (newTokenData) {
            // Update session with new tokens
            session.accessToken = newTokenData.accessToken;
            session.refreshToken = newTokenData.refreshToken;
            session.expiresAt = newTokenData.expiresAt;
          }
        } catch {
          return { authenticated: false, reason: 'token_refresh_failed' };
        }
      }

      // Always save session with or without token refresh ("touch" for rolling session expiration)
      await saveSessionWithCookies(cookieStore, session);

      // Authentication successful
      return { authenticated: true, session };
    } catch {
      return { authenticated: false, reason: 'unexpected_error' };
    }
  }
}
