import type { NextApiRequest, NextApiResponse } from 'next';
import type { NextRequest, NextResponse } from 'next/server';
import retry from 'async-retry';

import type {
  AuthConfig,
  LoginConfig,
  CallbackConfig,
  LogoutConfig,
  TokenData,
  TokenResponse,
  CallbackResult,
} from '../types';
import { AppRouterAuthHandler } from './app-router/app-router-auth-handler';
import { PageRouterAuthHandler } from './page-router/page-router-auth-handler';
import { WristbandService } from '../services/wristband-service';
import { TENANT_DOMAIN_TOKEN } from '../utils/constants';

/**
 * WristbandAuth is a utility interface providing methods for seamless interaction with Wristband for authenticating
 * application users. It can handle the following:
 * - Initiate a login request by redirecting to Wristband.
 * - Receive callback requests from Wristband to complete a login request.
 * - Retrive all necessary JWT tokens and userinfo to start an application session.
 * - Logout a user from the application by revoking refresh tokens and redirecting to Wristband.
 * - Checking for expired access tokens and refreshing them automatically, if necessary.
 */
export interface WristbandAuth {
  appRouter: {
    /**
     * Initiates a login request by redirecting to Wristband. An authorization request is constructed
     * for the user attempting to login in order to start the Authorization Code flow.
     *
     * Your request can contain Wristband-specific query parameters:
     * - return_url: The location of where to send users after authenticating. (Optional)
     * - login_hint: A hint to Wristband about user's preferred login identifier. (Optional)
     *
     * @param {Request} req - The request object.
     * @param {LoginConfig} [config] - Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<void>} - A Promise as a result of a URL redirect to Wristband.
     * @throws {Error} - If an error occurs during the login process.
     */
    login: (req: NextRequest, loginConfig?: LoginConfig) => Promise<NextResponse>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * @param {Request} req - The request object.
     * @param {CallbackConfig} [config] - Additional configuration for handling auth callbacks from Wristband.
     * @returns {Promise<CallbackResult>} - A Promise with all token data, userinfo, custom state, and return URL,
     * assuming the exchange of an auth code for a token succeeds (response contents depend on what inputs were given
     * to the login endpoint during the auth request). Otherwise, a Promise of type void is returned as a result of a
     * URL redirect in the event of certain error scenarios.
     * @throws {Error} - If an error occurs during the callback handling.
     */
    callback: (req: NextRequest, callbackConfig?: CallbackConfig) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and redirects them to the Wristband logout endpoint to destroy
     * their authenticated session in Wristband.
     *
     * @param {Request} req - The request object.
     * @param {LogoutConfig} [config] - Additional configuration for logging out the user.
     * @returns {Promise<void>} - A Promise of type void as a result of a URL redirect to Wristband.
     * @throws {Error} - If an error occurs during the logout process.
     */
    logout: (req: NextRequest, logoutConfig?: LogoutConfig) => Promise<NextResponse>;
  };

  pageRouter: {
    /**
     * Initiates a login request by redirecting to Wristband. An authorization request is constructed
     * for the user attempting to login in order to start the Authorization Code flow.
     *
     * Your request can contain Wristband-specific query parameters:
     * - return_url: The location of where to send users after authenticating. (Optional)
     * - login_hint: A hint to Wristband about user's preferred login identifier. (Optional)
     *
     * @param {Request} req - The request object.
     * @param {Response} res - The response object.
     * @param {LoginConfig} [config] - Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<void>} - A Promise as a result of a URL redirect to Wristband.
     * @throws {Error} - If an error occurs during the login process.
     */
    login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig) => Promise<NextApiResponse>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * @param {Request} req - The request object.
     * @param {CallbackConfig} [config] - Additional configuration for handling auth callbacks from Wristband.
     * @returns {Promise<CallbackResult>} - A Promise with all token data, userinfo, custom state, and return URL,
     * assuming the exchange of an auth code for a token succeeds (response contents depend on what inputs were given
     * to the login endpoint during the auth request). Otherwise, a Promise of type void is returned as a result of a
     * URL redirect in the event of certain error scenarios.
     * @throws {Error} - If an error occurs during the callback handling.
     */
    callback: (req: NextApiRequest, res: NextApiResponse, callbackConfig?: CallbackConfig) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and redirects them to the Wristband logout endpoint to destroy
     * their authenticated session in Wristband.
     *
     * @param {Request} req - The request object.
     * @param {LogoutConfig} [config] - Additional configuration for logging out the user.
     * @returns {Promise<void>} - A Promise of type void as a result of a URL redirect to Wristband.
     * @throws {Error} - If an error occurs during the logout process.
     */
    logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig) => Promise<NextApiResponse>;
  };

  /**
   * Checks if the user's access token is expired and refreshed the token, if necessary.
   *
   * @param {string} refreshToken - The refresh token.
   * @param {number} expiresAt - Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} - A Promise with the data from the token endpoint if the token was refreshed.
   * Otherwise, a Promise with null value is returned.
   * @throws {Error} - If an error occurs during the token refresh process.
   */
  refreshTokenIfExpired: (refreshToken: string, expiresAt: number) => Promise<TokenData | null>;
}

/**
 * WristbandAuth is a utility class providing methods for seamless interaction with the Wristband authentication service.
 * @implements {WristbandAuth}
 */
export class WristbandAuthImpl implements WristbandAuth {
  private appRouterAuthHandler: AppRouterAuthHandler;
  private pageRouterAuthHandler: PageRouterAuthHandler;
  private wristbandService: WristbandService;

  /**
   * Creates an instance of WristbandAuth.
   *
   * @param {AuthConfig} authConfig - The configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    if (!authConfig.clientId) {
      throw new TypeError('The [clientId] config must have a value.');
    }
    if (!authConfig.clientSecret) {
      throw new TypeError('The [clientSecret] config must have a value.');
    }
    if (!authConfig.loginStateSecret || authConfig.loginStateSecret.length < 32) {
      throw new TypeError('The [loginStateSecret] config must have a value of at least 32 characters.');
    }
    if (!authConfig.loginUrl) {
      throw new TypeError('The [loginUrl] config must have a value.');
    }
    if (!authConfig.redirectUri) {
      throw new TypeError('The [redirectUri] config must have a value.');
    }
    if (!authConfig.wristbandApplicationDomain) {
      throw new TypeError('The [wristbandApplicationDomain] config must have a value.');
    }
    if (authConfig.useTenantSubdomains) {
      if (!authConfig.rootDomain) {
        throw new TypeError('The [rootDomain] config must have a value when using tenant subdomains.');
      }
      if (!authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [loginUrl] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
      if (!authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [redirectUri] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
    } else {
      if (authConfig.loginUrl.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [loginUrl] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
      if (authConfig.redirectUri.includes(TENANT_DOMAIN_TOKEN)) {
        throw new TypeError('The [redirectUri] must contain the "{tenant_domain}" token when using tenant subdomains.');
      }
    }

    const wristbandServiceImpl = new WristbandService(
      authConfig.wristbandApplicationDomain,
      authConfig.clientId,
      authConfig.clientSecret
    );
    this.wristbandService = wristbandServiceImpl;
    this.appRouterAuthHandler = new AppRouterAuthHandler(authConfig, wristbandServiceImpl);
    this.pageRouterAuthHandler = new PageRouterAuthHandler(authConfig, wristbandServiceImpl);
  }

  appRouter = {
    login: (req: NextRequest, loginConfig?: LoginConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.login(req, loginConfig);
    },
    callback: (req: NextRequest, callbackConfig?: CallbackConfig): Promise<CallbackResult> => {
      return this.appRouterAuthHandler.callback(req, callbackConfig);
    },
    logout: (req: NextRequest, logoutConfig?: LogoutConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.logout(req, logoutConfig);
    },
  };

  pageRouter = {
    login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig): Promise<NextApiResponse> => {
      return this.pageRouterAuthHandler.login(req, res, loginConfig);
    },
    callback: (req: NextApiRequest, res: NextApiResponse, callbackConfig?: CallbackConfig): Promise<CallbackResult> => {
      return this.pageRouterAuthHandler.callback(req, res, callbackConfig);
    },
    logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig): Promise<NextApiResponse> => {
      return this.pageRouterAuthHandler.logout(req, res, logoutConfig);
    },
  };

  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    // Safety checks
    if (!refreshToken) {
      throw new TypeError('Refresh token must be a valid string');
    }
    if (!expiresAt || expiresAt < 0) {
      throw new TypeError('The expiresAt field must be an integer greater than 0');
    }

    if (Date.now().valueOf() <= expiresAt) {
      return null;
    }

    // Try up to 3 times to perform a token refresh.
    let tokenResponse: TokenResponse | null = null;
    await retry(
      async () => {
        tokenResponse = await this.wristbandService.refreshToken(refreshToken);
      },
      { retries: 2, minTimeout: 100, maxTimeout: 100 }
    );

    if (tokenResponse) {
      const {
        access_token: accessToken,
        id_token: idToken,
        expires_in: expiresIn,
        refresh_token: responseRefreshToken,
      } = tokenResponse;
      return { accessToken, idToken, refreshToken: responseRefreshToken, expiresIn };
    }

    // [Safety check] Errors during the refresh API call should bubble up, so this should never happen.
    throw new Error('Token response was null');
  }
}
