import type { NextApiRequest, NextApiResponse } from 'next';

import {
  AuthConfig,
  LoginConfig,
  CallbackData,
  CallbackResultType,
  LogoutConfig,
  LoginState,
  CallbackResult,
  Userinfo,
  TokenResponse,
} from '../../types';
import { WristbandService } from '../../services/wristband-service';
import {
  createLoginState,
  createLoginStateCookie,
  getAndClearLoginStateCookie,
  getAuthorizeUrl,
  resolveTenantCustomDomainParam,
  resolveTenantDomainName,
} from '../../utils/auth/page-router-utils';
import { WristbandError } from '../../error';
import { LOGIN_REQUIRED_ERROR, TENANT_DOMAIN_TOKEN } from '../../utils/constants';
import { decryptLoginState, encryptLoginState } from '../../utils/auth/common-utils';

export class PageRouterAuthHandler {
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
    this.rootDomain = authConfig.rootDomain || '';
    this.scopes =
      !!authConfig.scopes && !!authConfig.scopes.length ? authConfig.scopes : ['openid', 'offline_access', 'email'];
    this.useCustomDomains = typeof authConfig.useCustomDomains !== 'undefined' ? authConfig.useCustomDomains : false;
    this.useTenantSubdomains =
      typeof authConfig.useTenantSubdomains !== 'undefined' ? authConfig.useTenantSubdomains : false;
    this.wristbandApplicationVanityDomain = authConfig.wristbandApplicationVanityDomain;
  }

  async login(req: NextApiRequest, res: NextApiResponse, loginConfig: LoginConfig = {}): Promise<string> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    // Determine if a tenant custom domain is present as it will be needed for the authorize URL, if provided.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.useTenantSubdomains, this.rootDomain);
    const defaultTenantCustomDomain: string = loginConfig.defaultTenantCustomDomain || '';
    const defaultTenantDomainName: string = loginConfig.defaultTenantDomainName || '';

    // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
    if (!tenantCustomDomain && !tenantDomainName && !defaultTenantCustomDomain && !defaultTenantDomainName) {
      const apploginUrl =
        this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
      return `${apploginUrl}?client_id=${this.clientId}`;
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { customState });

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(req, res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = await getAuthorizeUrl(req, {
      wristbandApplicationVanityDomain: this.wristbandApplicationVanityDomain,
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

    return authorizeUrl;
  }

  async callback(req: NextApiRequest, res: NextApiResponse): Promise<CallbackResult> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    // Safety checks -- Wristband backend should never send bad query params
    const {
      code,
      state: paramState,
      error,
      error_description: errorDescription,
      tenant_custom_domain: tenantCustomDomainParam,
    } = req.query;
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
    if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
      throw new TypeError('Invalid query parameter [tenant_custom_domain] passed from Wristband during callback');
    }

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

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res, this.dangerouslyDisableSecureCookies);
    if (!loginStateCookie) {
      return { type: CallbackResultType.REDIRECT_REQUIRED, redirectUrl: tenantLoginUrl };
    }

    const loginState: LoginState = await decryptLoginState(loginStateCookie, this.loginStateSecret);
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

  async logout(
    req: NextApiRequest,
    res: NextApiResponse,
    logoutConfig: LogoutConfig = { tenantCustomDomain: '' }
  ): Promise<string> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    const { host } = req.headers;

    // Revoke the refresh token only if present.
    if (logoutConfig.refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(logoutConfig.refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    // Construct the appropriate Logout Endpoint URL that the user will get redirected to.
    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
    if (!logoutConfig.tenantCustomDomain) {
      if (this.useTenantSubdomains && host!.substring(host!.indexOf('.') + 1) !== this.rootDomain) {
        return logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`;
      }
      if (!this.useTenantSubdomains && !logoutConfig.tenantDomainName) {
        return logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`;
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
      logoutConfig.tenantCustomDomain || `${tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}`;
    return `https://${tenantDomainToUse}/api/v1/logout?${query}`;
  }
}
