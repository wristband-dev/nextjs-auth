import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import {
  AuthConfig,
  CallbackResult,
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
import { LOGIN_REQUIRED_ERROR, REDIRECT_RESPONSE_INIT, TENANT_DOMAIN_TOKEN } from '../../utils/constants';
import { WristbandError } from '../../error';

export class AppRouterAuthHandler {
  private wristbandService: WristbandService;
  private clientId: string;
  private customApplicationLoginPageUrl?: string;
  private dangerouslyDisableSecureCookies: boolean;
  private loginStateSecret: string;
  private loginUrl: string;
  private redirectUri: string;
  private parseTenantFromRootDomain: string;
  private scopes: string[];
  private isApplicationCustomDomainActive: boolean;
  private wristbandApplicationVanityDomain: string;

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
    this.parseTenantFromRootDomain = authConfig.parseTenantFromRootDomain || '';
    this.scopes =
      !!authConfig.scopes && !!authConfig.scopes.length ? authConfig.scopes : ['openid', 'offline_access', 'email'];
    this.isApplicationCustomDomainActive =
      typeof authConfig.isApplicationCustomDomainActive !== 'undefined'
        ? authConfig.isApplicationCustomDomainActive
        : false;
    this.wristbandApplicationVanityDomain = authConfig.wristbandApplicationVanityDomain;
  }

  async login(req: NextRequest, loginConfig: LoginConfig = {}): Promise<NextResponse> {
    // Determine if a tenant custom domain is present as it will be needed for the authorize URL, if provided.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);
    const defaultTenantCustomDomain: string = loginConfig.defaultTenantCustomDomain || '';
    const defaultTenantDomainName: string = loginConfig.defaultTenantDomainName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantDomainName && !defaultTenantCustomDomain && !defaultTenantDomainName) {
      const apploginUrl =
        this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
      return NextResponse.redirect(`${apploginUrl}?client_id=${this.clientId}`, REDIRECT_RESPONSE_INIT);
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { customState });

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = await getAuthorizeUrl(req, {
      wristbandApplicationVanityDomain: this.wristbandApplicationVanityDomain,
      isApplicationCustomDomainActive: this.isApplicationCustomDomainActive,
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
    const res = NextResponse.redirect(authorizeUrl, REDIRECT_RESPONSE_INIT);

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(req, res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Perform the redirect to Wristband's Authorize Endpoint.
    return res;
  }

  async callback(req: NextRequest): Promise<CallbackResult> {
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
    const resolvedTenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);
    if (!resolvedTenantDomainName) {
      throw new WristbandError(
        this.parseTenantFromRootDomain ? 'missing_tenant_subdomain' : 'missing_tenant_domain',
        this.parseTenantFromRootDomain
          ? 'Callback request URL is missing a tenant subdomain'
          : 'Callback request is missing the [tenant_domain] query parameter from Wristband'
      );
    }

    // Construct the tenant login URL in the event we have to redirect to the login endpoint
    let tenantLoginUrl: string = this.parseTenantFromRootDomain
      ? this.loginUrl.replace(TENANT_DOMAIN_TOKEN, resolvedTenantDomainName)
      : `${this.loginUrl}?tenant_domain=${resolvedTenantDomainName}`;
    if (tenantCustomDomainParam) {
      tenantLoginUrl = `${tenantLoginUrl}${this.parseTenantFromRootDomain ? '?' : '&'}tenant_custom_domain=${tenantCustomDomainParam}`;
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(req);
    if (!loginStateCookie) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }

    const loginState: LoginState = await decryptLoginState(loginStateCookie.value, this.loginStateSecret);
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
    return { type: CallbackResultType.COMPLETED, callbackData };
  }

  async logout(req: NextRequest, logoutConfig: LogoutConfig = {}): Promise<NextResponse> {
    // Revoke the refresh token only if present.
    if (logoutConfig.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(logoutConfig.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = logoutConfig.redirectUrl ? `&redirect_url=${logoutConfig.redirectUrl}` : '';
    const logoutPath: string = `/api/v1/logout?client_id=${this.clientId}${logoutRedirectUrl}`;
    const separator = this.isApplicationCustomDomainActive ? '.' : '-';
    const tenantCustomDomainParam: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);

    // Domain priority order resolution:
    // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
    if (logoutConfig.tenantCustomDomain) {
      return NextResponse.redirect(`https://${logoutConfig.tenantCustomDomain}${logoutPath}`, REDIRECT_RESPONSE_INIT);
    }

    // 2) If the LogoutConfig has a tenant domain defined, then use that.
    if (logoutConfig.tenantDomainName) {
      return NextResponse.redirect(
        `https://${logoutConfig.tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}${logoutPath}`,
        REDIRECT_RESPONSE_INIT
      );
    }

    // 3) If the tenant_custom_domain query param exists, then use that.
    if (tenantCustomDomainParam) {
      return NextResponse.redirect(`https://${tenantCustomDomainParam}${logoutPath}`, REDIRECT_RESPONSE_INIT);
    }

    // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
    if (tenantDomainName) {
      return NextResponse.redirect(
        `https://${tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}${logoutPath}`,
        REDIRECT_RESPONSE_INIT
      );
    }

    // Fallback to the appropriate Application-Level Login or Redirect URL if tenant cannot be resolved.
    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
    return NextResponse.redirect(
      logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`,
      REDIRECT_RESPONSE_INIT
    );
  }

  async createCallbackResponse(req: NextRequest, redirectUrl: string): Promise<NextResponse> {
    if (!redirectUrl) {
      throw new TypeError('redirectUrl cannot be null or empty');
    }

    const redirectResponse = NextResponse.redirect(redirectUrl, REDIRECT_RESPONSE_INIT);

    const loginStateCookie: AppRouterLoginStateCookie | null = getLoginStateCookie(req);
    if (loginStateCookie) {
      await clearLoginStateCookie(redirectResponse, loginStateCookie.name, this.dangerouslyDisableSecureCookies);
    }

    return redirectResponse;
  }
}
