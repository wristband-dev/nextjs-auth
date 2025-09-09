import type { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';

import type { AuthConfig, CallbackResult, LoginConfig, LogoutConfig, TokenData, TokenResponse } from '../types';
import { AppRouterAuthHandler } from './app-router/app-router-auth-handler';
import { PageRouterAuthHandler } from './page-router/page-router-auth-handler';
import { WristbandService } from '../wristband-service';
import { FetchError, WristbandError } from '../error';
import { ConfigResolver } from '../config-resolver';

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
     * - login_hint: A hint to Wristband about user's preferred login identifier. This can be appended as a query
     * parameter in the redirect request to the Authorize URL.
     * - return_url: The location of where to send users after authenticating.
     * - tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to, if applicable. Should be
     * used as the domain of the authorize URL when present.
     * - tenant_domain: The domain name of the tenant the user belongs to. Should be used in the tenant vanity domain of
     * the authorize URL when not utilizing tenant subdomains nor tenant custom domains.
     *
     * @param {NextRequest} req The request object.
     * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<NextResponse>} A Promise with the NextResponse that is peforming the URL redirect to Wristband.
     */
    login: (req: NextRequest, loginConfig?: LoginConfig) => Promise<NextResponse>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * Your request can contain Wristband-specific query parameters:
     * - code: The authorization code to use for exchanging for an access token.
     * - error: An error code indicating that some an issue occurred during the login process.
     * - error_description: A plaintext description giving more detail around the issue that occurred during the login
     * process.
     * - state: The state value that was originally sent to the Authorize URL.
     * - tenant_custom_domain: If the tenant has a tenant custom domain defined, then this query parameter will be part
     * of the incoming request to the Callback Endpoint. n the event a redirect to the Login Endpoint is required, then
     * this should be appended as a query parameter when redirecting to the Login Endpoint.
     * - tenant_domain: The domain name of the tenant the user belongs to. In the event a redirect to the Login Endpoint
     * is required and neither tenant subdomains nor tenant custom domains are not being utilized, then this should be
     * appended as a query parameter when redirecting to the Login Endpoint.
     *
     * @param {Request} req The request object.
     * @returns {Promise<CallbackResult>} A Promise containing the result of what happened during callback execution
     * as well as any accompanying data.
     * @throws {WristbandError} If an error occurs during the callback handling.
     */
    callback: (req: NextRequest) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and redirects them to the Wristband logout endpoint to destroy
     * their authenticated session in Wristband.
     *
     * @param {NextRequest} req The request object.
     * @param {LogoutConfig} [config] Additional configuration for logging out the user.
     * @returns {Promise<NextResponse>} A Promise with the NextResponse that is peforming the URL redirect to Wristband.
     * @throws {Error} If an error occurs during the logout process.
     */
    logout: (req: NextRequest, logoutConfig?: LogoutConfig) => Promise<NextResponse>;

    /**
     * Constructs the redirect response to your application and cleans up the login state.
     *
     * @param {NextRequest} req The request object.
     * @param {string} redirectUrl The location for your application that you want to send users to.
     * @returns {NextResponse} The NextResponse that is peforming the URL redirect to your desired application URL.
     */
    createCallbackResponse: (req: NextRequest, redirectUrl: string) => Promise<NextResponse>;
  };

  pageRouter: {
    /**
     * Initiates a login request by redirecting to Wristband. An authorization request is constructed
     * for the user attempting to login in order to start the Authorization Code flow.
     *
     * Your request can contain Wristband-specific query parameters:
     * - login_hint: A hint to Wristband about user's preferred login identifier. This can be appended as a query
     * parameter in the redirect request to the Authorize URL.
     * - return_url: The location of where to send users after authenticating.
     * - tenant_custom_domain: The tenant custom domain for the tenant that the user belongs to, if applicable. Should be
     * used as the domain of the authorize URL when present.
     * - tenant_domain: The domain name of the tenant the user belongs to. Should be used in the tenant vanity domain of
     * the authorize URL when not utilizing tenant subdomains nor tenant custom domains.
     *
     * @param {Request} req The request object.
     * @param {Response} res The response object.
     * @param {LoginConfig} [config] Additional configuration for creating an auth request to Wristband.
     * @returns {Promise<string>} A Promise with the Wristband authorize URL that your app should redirect to.
     */
    login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig) => Promise<string>;

    /**
     * Receives incoming requests from Wristband with an authorization code. It will then proceed to exchange the auth
     * code for an access token as well as fetch the userinfo for the user attempting to login.
     *
     * Your request can contain Wristband-specific query parameters:
     * - code: The authorization code to use for exchanging for an access token.
     * - error: An error code indicating that some an issue occurred during the login process.
     * - error_description: A plaintext description giving more detail around the issue that occurred during the login
     * process.
     * - state: The state value that was originally sent to the Authorize URL.
     * - tenant_custom_domain: If the tenant has a tenant custom domain defined, then this query parameter will be part
     * of the incoming request to the Callback Endpoint. n the event a redirect to the Login Endpoint is required, then
     * this should be appended as a query parameter when redirecting to the Login Endpoint.
     * - tenant_domain: The domain name of the tenant the user belongs to. In the event a redirect to the Login Endpoint
     * is required and neither tenant subdomains nor tenant custom domains are not being utilized, then this should be
     * appended as a query parameter when redirecting to the Login Endpoint.
     *
     * @param {Request} req The request object.
     * @param {Response} res The response object.
     * @param {CallbackConfig} [config] Additional configuration for handling auth callbacks from Wristband.
     * @returns {Promise<CallbackResult>} A Promise containing the result of what happened during callback execution
     * as well as any accompanying data.
     * @throws {WristbandError} If an error occurs during the callback handling.
     */
    callback: (req: NextApiRequest, res: NextApiResponse) => Promise<CallbackResult>;

    /**
     * Revokes the user's refresh token and returns a redirect URL to the Wristband logout endpoint, where
     * their authenticated session in Wristband gets destroy.
     *
     * @param {Request} req The request object.
     * @param {Response} res The response object.
     * @param {LogoutConfig} [config] Additional configuration for logging out the user.
     * @returns {Promise<string>} A Promise with the Wristband logout URL that your app should redirect to.
     */
    logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig) => Promise<string>;
  };

  /**
   * Checks if the user's access token is expired and refreshed the token, if necessary.
   *
   * @param {string} refreshToken The refresh token.
   * @param {number} expiresAt Unix timestamp in milliseconds at which the token expires.
   * @returns {Promise<TokenData | null>} A Promise with the data from the token endpoint if the token was refreshed.
   * Otherwise, a Promise with null value is returned.
   * @throws {Error} If an error occurs during the token refresh process.
   */
  refreshTokenIfExpired: (refreshToken: string, expiresAt: number) => Promise<TokenData | null>;
}

/**
 * WristbandAuth is a utility class providing methods for seamless interaction with the Wristband authentication service.
 * @implements {WristbandAuth}
 */
export class WristbandAuthImpl implements WristbandAuth {
  private configResolver: ConfigResolver;
  private appRouterAuthHandler: AppRouterAuthHandler;
  private pageRouterAuthHandler: PageRouterAuthHandler;
  private wristbandService: WristbandService;

  /**
   * Creates an instance of WristbandAuth.
   *
   * @param {AuthConfig} authConfig The configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    this.configResolver = new ConfigResolver(authConfig);
    this.wristbandService = new WristbandService(
      this.configResolver.getWristbandApplicationVanityDomain(),
      this.configResolver.getClientId(),
      this.configResolver.getClientSecret()
    );
    this.appRouterAuthHandler = new AppRouterAuthHandler(this.configResolver, this.wristbandService);
    this.pageRouterAuthHandler = new PageRouterAuthHandler(this.configResolver, this.wristbandService);
  }

  appRouter = {
    login: (req: NextRequest, loginConfig?: LoginConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.login(req, loginConfig);
    },
    callback: (req: NextRequest): Promise<CallbackResult> => {
      return this.appRouterAuthHandler.callback(req);
    },
    logout: (req: NextRequest, logoutConfig?: LogoutConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.logout(req, logoutConfig);
    },
    createCallbackResponse: (req: NextRequest, redirectUrl: string): Promise<NextResponse> => {
      return this.appRouterAuthHandler.createCallbackResponse(req, redirectUrl);
    },
  };

  pageRouter = {
    login: (req: NextApiRequest, res: NextApiResponse, loginConfig?: LoginConfig): Promise<string> => {
      return this.pageRouterAuthHandler.login(req, res, loginConfig);
    },
    callback: (req: NextApiRequest, res: NextApiResponse): Promise<CallbackResult> => {
      return this.pageRouterAuthHandler.callback(req, res);
    },
    logout: (req: NextApiRequest, res: NextApiResponse, logoutConfig?: LogoutConfig): Promise<string> => {
      return this.pageRouterAuthHandler.logout(req, res, logoutConfig);
    },
  };

  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    // Fetch SDK Configs
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();

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
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop
        tokenResponse = await this.wristbandService.refreshToken(refreshToken);
        break;
      } catch (error: any) {
        if (
          error instanceof FetchError &&
          error.response &&
          error.response.status >= 400 &&
          error.response.status < 500
        ) {
          const errorDescription =
            error.body && error.body.error_description ? error.body.error_description : 'Invalid Refresh Token';
          // Only 4xx errors should short-circuit the retry loop early.
          throw new WristbandError('invalid_refresh_token', errorDescription, error);
        }

        // Final attempt failed
        if (attempt === 3) {
          throw new WristbandError('unexpected_error', 'Unexpected Error', error);
        }

        // Wait before retrying (100ms delay)
        // eslint-disable-next-line no-await-in-loop
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 100);
        });
      }
    }

    if (!tokenResponse) {
      // This is merely a safety check, but this should never happen.
      throw new WristbandError('unexpected_error', 'Unexpected Error');
    }

    const {
      access_token: accessToken,
      id_token: idToken,
      expires_in: expiresIn,
      refresh_token: responseRefreshToken,
    } = tokenResponse;

    const resolvedExpiresIn = expiresIn - (tokenExpirationBuffer || 0);
    const resolvedExpiresAt = Date.now() + resolvedExpiresIn * 1000;

    return {
      accessToken,
      expiresAt: resolvedExpiresAt,
      expiresIn: resolvedExpiresIn,
      idToken,
      refreshToken: responseRefreshToken,
    };
  }
}
