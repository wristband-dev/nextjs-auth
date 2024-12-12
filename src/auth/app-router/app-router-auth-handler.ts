import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import {
  AppRouterCallbackResult,
  AuthConfig,
  LoginConfig,
  LogoutConfig,
  CallbackResultType,
  LoginState,
  TokenResponse,
  Userinfo,
  CallbackData,
  AppRouterLoginStateCookie,
} from '../../types';
import { WristbandService } from '../../services/wristband-service';
import { decryptLoginState, encryptLoginState } from '../../utils/auth/common-utils';
import {
  createLoginState,
  createLoginStateCookie,
  getLoginStateCookie,
  getAuthorizeUrl,
  resolveTenantCustomDomainParam,
  resolveTenantDomainName,
  clearLoginStateCookie,
} from '../../utils/auth/app-router-utils';
import { LOGIN_REQUIRED_ERROR, NO_CACHE_HEADERS, TENANT_DOMAIN_TOKEN } from '../../utils/constants';
import { WristbandError } from '../../error';

export class AppRouterAuthHandler {
  private wristbandService: WristbandService;
  private clientId: string;
  private customApplicationLoginPageUrl?: string;
  private dangerouslyDisableSecureCookies: boolean;
  private loginStateSecret: string;
  private loginUrl: string;
  private redirectUri: string;
  private rootDomain: string;
  private scopes: string[];
  private useCustomDomains: boolean;
  private useTenantSubdomains: boolean;
  private wristbandApplicationDomain: string;

  constructor(authConfig: AuthConfig, wristbandService: WristbandService) {
    this.wristbandService = wristbandService;
    this.clientId = authConfig.clientId;
    this.customApplicationLoginPageUrl = authConfig.customApplicationLoginPageUrl || '';
    this.dangerouslyDisableSecureCookies =
      typeof authConfig.dangerouslyDisableSecureCookies !== 'undefined'
        ? authConfig.dangerouslyDisableSecureCookies
        : false;
    this.loginStateSecret = authConfig.loginStateSecret;
    this.loginUrl = authConfig.loginUrl;
    this.redirectUri = authConfig.redirectUri;
    this.rootDomain = authConfig.rootDomain || '';
    this.scopes =
      !!authConfig.scopes && !!authConfig.scopes.length ? authConfig.scopes : ['openid', 'offline_access', 'email'];
    this.useCustomDomains = typeof authConfig.useCustomDomains !== 'undefined' ? authConfig.useCustomDomains : false;
    this.useTenantSubdomains =
      typeof authConfig.useTenantSubdomains !== 'undefined' ? authConfig.useTenantSubdomains : false;
    this.wristbandApplicationDomain = authConfig.wristbandApplicationDomain;
  }

  async login(req: NextRequest, loginConfig: LoginConfig = {}): Promise<NextResponse> {
    // Determine if a tenant custom domain is present as it will be needed for the authorize URL, if provided.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.useTenantSubdomains, this.rootDomain);
    const defaultTenantCustomDomain: string = loginConfig.defaultTenantCustomDomain || '';
    const defaultTenantDomainName: string = loginConfig.defaultTenantDomainName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantDomainName && !defaultTenantCustomDomain && !defaultTenantDomainName) {
      const apploginUrl = this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
      return NextResponse.redirect(`${apploginUrl}?client_id=${this.clientId}`, {
        status: 302,
        headers: NO_CACHE_HEADERS,
      });
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { customState });

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = await getAuthorizeUrl(req, {
      wristbandApplicationDomain: this.wristbandApplicationDomain,
      useCustomDomains: this.useCustomDomains,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes: this.scopes,
      tenantCustomDomain,
      tenantDomainName,
      defaultTenantDomainName,
      defaultTenantCustomDomain,
    });

    // Prepare a response object for cookies and redirect
    const res = NextResponse.redirect(authorizeUrl, { status: 302, headers: NO_CACHE_HEADERS });

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(req, res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Perform the redirect to Wristband's Authorize Endpoint.
    return res;
  }

  async callback(req: NextRequest): Promise<AppRouterCallbackResult> {
    const codeArray = req.nextUrl.searchParams.getAll('code');
    const paramStateArray = req.nextUrl.searchParams.getAll('state');
    const errorArray = req.nextUrl.searchParams.getAll('error');
    const errorDescriptionArray = req.nextUrl.searchParams.getAll('error_description');
    const tenantCustomDomainParamArray = req.nextUrl.searchParams.getAll('tenant_custom_domain');

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

    // Resolve and validate the tenant domain name
    const resolvedTenantDomainName: string = resolveTenantDomainName(req, this.useTenantSubdomains, this.rootDomain);
    if (!resolvedTenantDomainName) {
      throw new WristbandError(
        this.useTenantSubdomains ? 'missing_tenant_subdomain' : 'missing_tenant_domain',
        this.useTenantSubdomains
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_domain] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = this.useTenantSubdomains
      ? this.loginUrl.replace(TENANT_DOMAIN_TOKEN, resolvedTenantDomainName)
      : `${this.loginUrl}?tenant_domain=${resolvedTenantDomainName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${this.useTenantSubdomains ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    const redirectResponse = NextResponse.redirect(tenantLoginUrl, { status: 302, headers: NO_CACHE_HEADERS });

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(req);
    if (!loginStateCookie) {
      return { redirectResponse, result: CallbackResultType.REDIRECT_REQUIRED };
    }
    clearLoginStateCookie(redirectResponse, loginStateCookie.name, this.dangerouslyDisableSecureCookies);

    const loginState: LoginState = await decryptLoginState(loginStateCookie.value, this.loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState } = loginState;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { redirectResponse, result: CallbackResultType.REDIRECT_REQUIRED };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { redirectResponse, result: CallbackResultType.REDIRECT_REQUIRED };
      }
      throw new WristbandError(error, errorDescription || '');
    }

    // Exchange the authorization code for tokens
    if (!code) {
      throw new TypeError('Invalid query parameter [code] passed from Wristband during callback');
    }
    const tokenResponse: TokenResponse = await this.wristbandService.getTokens(code, redirectUri, codeVerifier);
    const {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
    } = tokenResponse;

    // Get a minimal set of the user's data to store in their session data.
    // Fetch the userinfo for the user logging in.
    const userinfo: Userinfo = await this.wristbandService.getUserinfo(accessToken);
    const callbackData: CallbackData = {
      accessToken,
      ...(!!customState && { customState }),
      expiresIn,
      idToken,
      ...(!!refreshToken && { refreshToken }),
      ...(!!returnUrl && { returnUrl }),
      ...(!!tenantCustomDomainParam && { tenantCustomDomain: tenantCustomDomainParam }),
      tenantDomainName: resolvedTenantDomainName,
      userinfo,
    };
    return { result: CallbackResultType.COMPLETED, callbackData };
  }

  async logout(req: NextRequest, logoutConfig: LogoutConfig = {}): Promise<NextResponse> {
    const host = req.headers.get('host');

    // Revoke the refresh token only if present.
    if (logoutConfig.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(logoutConfig.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
    if (!logoutConfig.tenantCustomDomain) {
      if (this.useTenantSubdomains && host!.substring(host!.indexOf('.') + 1) !== this.rootDomain) {
        return NextResponse.redirect(logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`, {
          status: 302,
          headers: NO_CACHE_HEADERS,
        });
      }
      if (!this.useTenantSubdomains && !logoutConfig.tenantDomainName) {
        return NextResponse.redirect(logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`, {
          status: 302,
          headers: NO_CACHE_HEADERS,
        });
      }
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = logoutConfig.redirectUrl ? `&redirect_url=${logoutConfig.redirectUrl}` : '';
    const query: string = `client_id=${this.clientId}${logoutRedirectUrl}`;

    // Always perform logout redirect to the Wristband logout endpoint.
    const tenantDomainName = this.useTenantSubdomains
      ? host!.substring(0, host!.indexOf('.'))
      : logoutConfig.tenantDomainName;
    const separator = this.useCustomDomains ? '.' : '-';
    const tenantDomainToUse =
      logoutConfig.tenantCustomDomain || `${tenantDomainName}${separator}${this.wristbandApplicationDomain}`;
    return NextResponse.redirect(`https://${tenantDomainToUse}/api/v1/logout?${query}`, {
      status: 302,
      headers: NO_CACHE_HEADERS,
    });
  }

  // eslint-disable-next-line class-methods-use-this
  async createCallbackResponse(req: NextRequest, redirectUrl: string): Promise<NextResponse> {
    if (!redirectUrl) {
      throw new TypeError('redirectUrl cannot be null or empty');
    }

    const redirectResponse = NextResponse.redirect(redirectUrl, { status: 302, headers: NO_CACHE_HEADERS });

    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(req);
    if (loginStateCookie) {
      clearLoginStateCookie(redirectResponse, loginStateCookie.name, this.dangerouslyDisableSecureCookies);
    }

    return redirectResponse;
  }
}
