import type { NextApiRequest, NextApiResponse } from 'next';

import {
  AuthConfig,
  LoginConfig,
  CallbackConfig,
  CallbackData,
  LogoutConfig,
  LoginState,
  CallbackResult,
  CallbackResultType,
  Userinfo,
  TokenResponse,
} from '../../types';
import { WristbandService } from '../../services/wristband-service';
import {
  createLoginState,
  createLoginStateCookie,
  getAndClearLoginStateCookie,
  getAuthorizeUrl,
  parseTenantSubdomain,
  resolveTenantDomain,
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

  async login(req: NextApiRequest, res: NextApiResponse, loginConfig: LoginConfig = {}): Promise<NextApiResponse> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    // Make sure a valid tenantDomainName exists for multi-tenant apps.
    let tenantDomainName: string = '';
    tenantDomainName = resolveTenantDomain(
      req,
      this.useTenantSubdomains,
      this.rootDomain,
      loginConfig.defaultTenantDomain
    );
    if (!tenantDomainName) {
      const apploginUrl = this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
      return res.redirect(`${apploginUrl}?client_id=${this.clientId}`);
    }

    // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
    const customState =
      !!loginConfig.customState && !!Object.keys(loginConfig.customState).length ? loginConfig.customState : undefined;
    const loginState: LoginState = createLoginState(req, this.redirectUri, { tenantDomainName, customState });

    // Clear any stale login state cookies and add a new one for the current request.
    const encryptedLoginState: string = await encryptLoginState(loginState, this.loginStateSecret);
    createLoginStateCookie(req, res, loginState.state, encryptedLoginState, this.dangerouslyDisableSecureCookies);

    // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
    const authorizeUrl: string = await getAuthorizeUrl(req, {
      wristbandApplicationDomain: this.wristbandApplicationDomain,
      useCustomDomains: this.useCustomDomains,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      state: loginState.state,
      codeVerifier: loginState.codeVerifier,
      scopes: this.scopes,
      tenantDomainName,
    });

    // Perform the redirect to Wristband's Authorize Endpoint.
    return res.redirect(authorizeUrl);
  }

  async callback(
    req: NextApiRequest,
    res: NextApiResponse,
    callbackConfig: CallbackConfig = {}
  ): Promise<CallbackResult> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    // Safety checks -- Wristband backend should never send bad query params
    const { code, state: paramState, error, error_description: errorDescription } = req.query;
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

    const appLoginLocation: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
    const appLoginUrl = `${appLoginLocation}?client_id=${this.clientId}`;
    const tenantSubdomain: string = this.useTenantSubdomains ? parseTenantSubdomain(req, this.rootDomain) : '';
    const defaultTenantDomain: string = callbackConfig.defaultTenantDomain || '';

    let tenantLoginUrl: string = '';
    if (this.useTenantSubdomains) {
      tenantLoginUrl =
        !!tenantSubdomain || !!defaultTenantDomain
          ? this.loginUrl.replace(TENANT_DOMAIN_TOKEN, tenantSubdomain || defaultTenantDomain)
          : '';
    } else {
      tenantLoginUrl = defaultTenantDomain ? `${this.loginUrl}?tenant_domain=${defaultTenantDomain}` : '';
    }

    // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
    const loginStateCookie: string = getAndClearLoginStateCookie(req, res);
    if (!loginStateCookie) {
      console.warn(`Login state cookie not found. Redirecting to login.`);
      return { redirectUrl: tenantLoginUrl || appLoginUrl, result: CallbackResultType.REDIRECT_REQUIRED };
    }

    const loginState: LoginState = await decryptLoginState(loginStateCookie, this.loginStateSecret);
    const { codeVerifier, customState, redirectUri, returnUrl, state: cookieState, tenantDomainName } = loginState;

    // Ensure there is a proper tenantDomain
    if (!this.useTenantSubdomains && !tenantDomainName) {
      return {
        redirectUrl: tenantLoginUrl || appLoginUrl,
        result: CallbackResultType.REDIRECT_REQUIRED,
      };
    }
    if (this.useTenantSubdomains && tenantSubdomain !== tenantDomainName) {
      return { redirectUrl: tenantLoginUrl, result: CallbackResultType.REDIRECT_REQUIRED };
    }

    tenantLoginUrl = this.useTenantSubdomains ? tenantLoginUrl : `${this.loginUrl}?tenant_domain=${tenantDomainName}`;

    // Check for any potential error conditions
    if (paramState !== cookieState) {
      return { redirectUrl: tenantLoginUrl, result: CallbackResultType.REDIRECT_REQUIRED };
    }
    if (error) {
      if (error.toLowerCase() === LOGIN_REQUIRED_ERROR) {
        return { redirectUrl: tenantLoginUrl, result: CallbackResultType.REDIRECT_REQUIRED };
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
      tenantDomainName: tenantDomainName!,
      userinfo,
    };
    return { callbackData, result: CallbackResultType.COMPLETED };
  }

  async logout(req: NextApiRequest, res: NextApiResponse, logoutConfig: LogoutConfig = {}): Promise<NextApiResponse> {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    const { host } = req.headers;
    const { redirectUrl, refreshToken, tenantDomainName: configTenantDomainName } = logoutConfig;

    // Revoke the refresh token only if present.
    if (refreshToken) {
      try {
        await this.wristbandService.revokeRefreshToken(refreshToken);
      } catch (error) {
        // No need to block logout execution if revoking fails
        console.debug(`Revoking the refresh token failed during logout`);
      }
    }

    const appLoginUrl: string =
      this.customApplicationLoginPageUrl || `https://${this.wristbandApplicationDomain}/login`;
    if (this.useTenantSubdomains && host!.substring(host!.indexOf('.') + 1) !== this.rootDomain) {
      return res.redirect(`${appLoginUrl}?client_id=${this.clientId}`);
    }
    if (!this.useTenantSubdomains && !configTenantDomainName) {
      return res.redirect(`${appLoginUrl}?client_id=${this.clientId}`);
    }

    // The client ID is always required by the Wristband Logout Endpoint.
    const logoutRedirectUrl: string = redirectUrl ? `&redirect_url=${redirectUrl}` : '';
    const query: string = `client_id=${this.clientId}${logoutRedirectUrl}`;

    // Always perform logout redirect to the Wristband logout endpoint.
    const tenantDomain = this.useTenantSubdomains ? host!.substring(0, host!.indexOf('.')) : configTenantDomainName;
    const separator = this.useCustomDomains ? '.' : '-';
    const logoutUrl = `https://${tenantDomain}${separator}${this.wristbandApplicationDomain}/api/v1/logout?${query}`;
    return res.redirect(logoutUrl);
  }
}
