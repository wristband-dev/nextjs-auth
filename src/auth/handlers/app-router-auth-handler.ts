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
  CallbackResultType,
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
  getLoginStateCookie,
  getAuthorizeUrl,
  resolveTenantCustomDomainParam,
  resolveTenantName,
} from '../../utils/auth/app-router-utils';
import { refreshExpiredToken } from '../../utils/auth/common-utils';
import { decryptLoginState, encryptLoginState } from '../../utils/crypto';
import { LOGIN_REQUIRED_ERROR, REDIRECT_RESPONSE_INIT, TENANT_DOMAIN_TOKEN } from '../../utils/constants';
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
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(request);
    const tenantName: string = resolveTenantName(request, parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = loginConfig.defaultTenantCustomDomain || '';
    const defaultTenantName: string = loginConfig.defaultTenantName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantName && !defaultTenantCustomDomain && !defaultTenantName) {
      const apploginUrl = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
      return NextResponse.redirect(`${apploginUrl}?client_id=${clientId}`, REDIRECT_RESPONSE_INIT);
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(request, redirectUri, {
      customState,
      returnUrl: loginConfig.returnUrl,
    });

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = await getAuthorizeUrl(request, {
      wristbandApplicationVanityDomain,
      isApplicationCustomDomainActive,
      clientId,
      redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes,
      tenantCustomDomain,
      tenantName,
      defaultTenantName,
      defaultTenantCustomDomain,
    });

    // Prepare a response object for cookies and redirect
    const response = NextResponse.redirect(authorizeUrl, REDIRECT_RESPONSE_INIT);

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, loginStateSecret);
    createLoginStateCookie(request, response, loginState.state, encryptedLoginState, dangerouslyDisableSecureCookies);

    // Perform the redirect to Wristband's Authorize Endpoint.
    return response;
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
    const tenantCustomDomainParam = tenantCustomDomainParamArray[0] || '';

    // Resolve and validate the tenant name
    const resolvedTenantName: string = resolveTenantName(request, parseTenantFromRootDomain);
    if (!resolvedTenantName) {
      throw new WristbandError(
        parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_domain',
        parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_domain] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = parseTenantFromRootDomain
      ? loginUrl.replace(TENANT_DOMAIN_TOKEN, resolvedTenantName)
      : `${loginUrl}?tenant_domain=${resolvedTenantName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(request);
    if (!loginStateCookie) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }

    const loginState: LoginState = await decryptLoginState(loginStateCookie.value, loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
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
        return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
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
    return { type: CallbackResultType.COMPLETED, callbackData };
  }

  async logout(request: NextRequest, logoutConfig: LogoutConfig = {}): Promise<NextResponse> {
    // Fetch our SDK configs
    const clientId = this.configResolver.getClientId();
    const customApplicationLoginPageUrl = await this.configResolver.getCustomApplicationLoginPageUrl();
    const isApplicationCustomDomainActive = await this.configResolver.getIsApplicationCustomDomainActive();
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
    const tenantCustomDomainParam: string = resolveTenantCustomDomainParam(request);
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
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
    if (tenantName) {
      return NextResponse.redirect(
        `https://${tenantName}${separator}${wristbandApplicationVanityDomain}${logoutPath}`,
        REDIRECT_RESPONSE_INIT
      );
    }

    // Fallback to the appropriate Application-Level Login or Redirect URL if tenant cannot be resolved.
    const appLoginUrl: string = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
    return NextResponse.redirect(
      logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${clientId}`,
      REDIRECT_RESPONSE_INIT
    );
  }

  async createCallbackResponse(request: NextRequest, redirectUrl: string): Promise<NextResponse> {
    // Fetch our SDK configs
    const dangerouslyDisableSecureCookies = this.configResolver.getDangerouslyDisableSecureCookies();

    if (!redirectUrl) {
      throw new TypeError('redirectUrl cannot be null or empty');
    }

    const redirectResponse = NextResponse.redirect(redirectUrl, REDIRECT_RESPONSE_INIT);

    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(request);
    if (loginStateCookie) {
      await clearLoginStateCookie(redirectResponse, loginStateCookie.name, dangerouslyDisableSecureCookies);
    }

    return redirectResponse;
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
        } catch (error) {
          return { authenticated: false, reason: 'token_refresh_failed' };
        }
      }

      // Always save session with or without token refresh ("touch" for rolling session expiration)
      await saveSessionWithCookies(cookieStore, session);

      // Authentication successful
      return { authenticated: true, session };
    } catch (error) {
      return { authenticated: false, reason: 'unexpected_error' };
    }
  }
}
