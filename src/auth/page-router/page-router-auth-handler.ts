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

  async login(req: NextApiRequest, res: NextApiResponse, loginConfig: LoginConfig = {}): Promise<string> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    // Determine if a tenant custom domain is present as it will be needed for the authorize URL, if provided.
    const tenantCustomDomain: string = resolveTenantCustomDomainParam(req);
    const tenantDomainName: string = resolveTenantDomainName(req, this.parseTenantFromRootDomain);
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
      return `https://${logoutConfig.tenantCustomDomain}${logoutPath}`;
    }

    // 2) If the LogoutConfig has a tenant domain defined, then use that.
    if (logoutConfig.tenantDomainName) {
      return `https://${logoutConfig.tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // 3) If the tenant_custom_domain query param exists, then use that.
    if (tenantCustomDomainParam) {
      return `https://${tenantCustomDomainParam}${logoutPath}`;
    }

    // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
    // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
    if (tenantDomainName) {
      return `https://${tenantDomainName}${separator}${this.wristbandApplicationVanityDomain}${logoutPath}`;
    }

    // Fallback to the appropriate Application-Level Login or Redirect URL if tenant cannot be resolved.
    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationVanityDomain}/login`;
    return logoutConfig.redirectUrl || `${appLoginUrl}?client_id=${this.clientId}`;
  }
}
