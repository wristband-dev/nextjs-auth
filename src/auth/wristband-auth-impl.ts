import type { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionData, SessionOptions } from '@wristband/typescript-session';
import {
  createWristbandJwtValidator,
  WristbandJwtValidatorConfig,
  WristbandJwtValidator,
} from '@wristband/typescript-jwt';
import {
  createWristbandAuth as createCoreAuth,
  type WristbandAuth as CoreWristbandAuth,
} from '@wristband/typescript-auth';

import { getMutableSessionFromCookies, getSessionFromRequest, saveSessionWithCookies } from '../session';
import {
  AuthFailureReason,
  AuthStrategy,
  AuthStrategyResult,
  NextJsCookieStore,
  NormalizedMiddlewareConfig,
  ServerActionAuthResult,
  type AppRouterCallbackResult,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type CallbackData,
  type LoginConfig,
  type LogoutConfig,
  type PagesRouterCallbackResult,
  type TokenData,
} from '../types';
import {
  copyResponseHeaders,
  isProtectedApi,
  isProtectedPage,
  isValidCsrf,
  normalizeMiddlewareConfig,
  resolveOnPageUnauthenticated,
} from '../utils/middleware';
import { WristbandAuth } from './wristband-auth';

/**
 * Converts a Web Standard Response from @wristband/typescript-auth into a NextResponse, keeping the status and every
 * header (including each Set-Cookie).
 */
function toNextResponse(response: Response): NextResponse {
  return new NextResponse(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/**
 * WristbandAuth is a utility class providing methods for seamless interaction with the Wristband authentication service.
 * Login, callback, logout, token refresh, and SDK configuration are handled by @wristband/typescript-auth; this class
 * adapts them to the App Router and Pages Router and adds the Next.js-specific middleware and Server Action helpers.
 * @implements {WristbandAuth}
 */
export class WristbandAuthImpl implements WristbandAuth {
  private core: CoreWristbandAuth;
  private wristbandApplicationVanityDomain: string;
  private jwtValidator?: WristbandJwtValidator;

  /**
   * Creates an instance of WristbandAuth.
   *
   * @param {AuthConfig} authConfig The configuration for Wristband authentication.
   */
  constructor(authConfig: AuthConfig) {
    this.core = createCoreAuth(authConfig);
    this.wristbandApplicationVanityDomain = authConfig.wristbandApplicationVanityDomain;
  }

  /**
   * @see {@link WristbandAuth.appRouter}
   */
  appRouter = {
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    login: async (request: NextRequest, loginConfig?: LoginConfig): Promise<NextResponse> => {
      return toNextResponse(await this.core.login(request, loginConfig));
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    callback: async (
      request: NextRequest,
      resolveRedirectUrl: (request: NextRequest, callbackData: CallbackData) => string | Promise<string>
    ): Promise<AppRouterCallbackResult> => {
      const result = await this.core.callback(request, resolveRedirectUrl);
      // Keep everything the core returns; only the Response becomes a NextResponse.
      return { ...result, response: toNextResponse(result.response) };
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    logout: async (request: NextRequest, logoutConfig?: LogoutConfig): Promise<NextResponse> => {
      return toNextResponse(await this.core.logout(request, logoutConfig));
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    createServerActionAuth: <T extends SessionData = SessionData>(config: {
      sessionOptions: SessionOptions;
    }): ((cookieStore: NextJsCookieStore) => Promise<ServerActionAuthResult<T>>) => {
      if (!config || !config.sessionOptions) {
        throw new TypeError('Session options are a required configuration.');
      }

      return async (cookieStore: NextJsCookieStore): Promise<ServerActionAuthResult<T>> => {
        return this.authenticateServerAction<T>(cookieStore, config.sessionOptions);
      };
    },
  };

  /**
   * @see {@link WristbandAuth.pagesRouter}
   */
  pagesRouter = {
    /**
     * @see {@link WristbandAuth.pagesRouter} for full documentation
     */
    login: (request: NextApiRequest, response: NextApiResponse, loginConfig?: LoginConfig): Promise<string> => {
      return this.core.login(request, response, loginConfig);
    },
    /**
     * @see {@link WristbandAuth.pagesRouter} for full documentation
     */
    callback: (request: NextApiRequest, response: NextApiResponse): Promise<PagesRouterCallbackResult> => {
      return this.core.callback(request, response);
    },
    /**
     * @see {@link WristbandAuth.pagesRouter} for full documentation
     */
    logout: (request: NextApiRequest, response: NextApiResponse, logoutConfig?: LogoutConfig): Promise<string> => {
      return this.core.logout(request, response, logoutConfig);
    },
  };

  /**
   * @see {@link WristbandAuth.refreshTokenIfExpired}
   */
  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    return this.core.refreshTokenIfExpired(refreshToken, expiresAt);
  }

  /**
   * @see {@link WristbandAuth.createMiddlewareAuth}
   */
  createMiddlewareAuth<T extends SessionData = SessionData>(config: AuthMiddlewareConfig) {
    const normalizedConfig = normalizeMiddlewareConfig(config);

    return async (request: NextRequest, previousResponse?: NextResponse): Promise<NextResponse> => {
      // Check if this route needs protection
      const isProtectedApiRoute = isProtectedApi(request.nextUrl.pathname, normalizedConfig);
      const isProtectedPageRoute = isProtectedPage(request, normalizedConfig);

      // If not protected, don't copy anything -- just continue
      if (!(isProtectedApiRoute || isProtectedPageRoute)) {
        return previousResponse || NextResponse.next();
      }

      // Check if this is a session/token endpoint - force SESSION strategy only
      const isSessionEndpoint = request.nextUrl.pathname === normalizedConfig.sessionConfig.sessionEndpoint;
      const isTokenEndpoint = request.nextUrl.pathname === normalizedConfig.sessionConfig.tokenEndpoint;
      const isWristbandAuthEndpoint = isSessionEndpoint || isTokenEndpoint;

      // For session/token endpoints, ONLY use SESSION strategy (prevents JWT from breaking them)
      const strategiesToTry: AuthStrategy[] = isWristbandAuthEndpoint ? ['SESSION'] : normalizedConfig.authStrategies;

      // Try all auth strategies in the sequential order in which they were provided.
      let result: AuthStrategyResult<T> = { authenticated: false, reason: 'not_authenticated' };

      for (let i = 0; i < strategiesToTry.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.tryAuthStrategy<T>(request, strategiesToTry[i], normalizedConfig, isProtectedApiRoute);

        if (result.authenticated) {
          break;
        }
      }

      // If no strategy succeeded, handle the auth faiure accordingly.
      if (!result.authenticated) {
        const failureResponse = await this.getAuthFailureResponse(
          request,
          result.reason,
          isProtectedApiRoute,
          normalizedConfig
        );
        return previousResponse ? copyResponseHeaders(previousResponse, failureResponse) : failureResponse;
      }

      const finalResponse: NextResponse = previousResponse || NextResponse.next();

      // Save session/CSRF cookie headers only if we used SESSION strategy
      if (result.usedStrategy === 'SESSION' && result.session) {
        const sessionResponse = await result.session.saveToResponse(new Response());
        return copyResponseHeaders(sessionResponse, finalResponse);
      }

      return finalResponse;
    };
  }

  /**
   * Lazily initializes and returns the JWT validator instance.
   * Only creates the validator on first use if JWT strategy is configured.
   */
  private getJwtValidator(
    jwtConfig: Pick<WristbandJwtValidatorConfig, 'jwksCacheMaxSize' | 'jwksCacheTtl'>
  ): WristbandJwtValidator {
    if (!this.jwtValidator) {
      this.jwtValidator = createWristbandJwtValidator({
        wristbandApplicationVanityDomain: this.wristbandApplicationVanityDomain,
        jwksCacheMaxSize: jwtConfig?.jwksCacheMaxSize,
        jwksCacheTtl: jwtConfig?.jwksCacheTtl,
      });
    }
    return this.jwtValidator;
  }

  /**
   * Attempts to authenticate a request using a single configured auth strategy.
   *
   * This evaluates the provided strategy in isolation and reports whether it
   * succeeded or failed with a specific reason. Normal authentication failures
   * are returned as structured results rather than thrown, allowing the caller
   * to orchestrate fallback strategies and proper HTTP error responses.
   *
   * @template T - Session data type extending SessionData
   * @param request - The incoming Next.js request to authenticate.
   * @param strategy - The auth strategy to apply for this attempt.
   * @param normalizedConfig - The fully normalized middleware configuration.
   * @param isProtectedApiRoute - Indicates whether the current path is a protected API route.
   * @returns A structured result describing authentication outcome, session (if successful), strategy used, and failure reason (if failed).
   */
  private async tryAuthStrategy<T extends SessionData>(
    request: NextRequest,
    strategy: AuthStrategy,
    normalizedConfig: NormalizedMiddlewareConfig,
    isProtectedApiRoute: boolean
  ): Promise<AuthStrategyResult<T>> {
    if (strategy === 'SESSION') {
      const { csrfTokenHeaderName, sessionOptions } = normalizedConfig.sessionConfig;

      try {
        const session = await getSessionFromRequest<T>(request, sessionOptions!);

        if (!session.isAuthenticated) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        // CSRF validation (only for API routes)
        if (isProtectedApiRoute && sessionOptions?.enableCsrfProtection) {
          const csrfValid = isValidCsrf(request, session.csrfToken, csrfTokenHeaderName);
          if (!csrfValid) {
            return { authenticated: false, reason: 'csrf_failed' };
          }
        }

        if (!(await this.refreshSessionTokens(session))) {
          return { authenticated: false, reason: 'token_refresh_failed' };
        }

        return { authenticated: true, session, usedStrategy: 'SESSION' };
      } catch {
        return { authenticated: false, reason: 'unexpected_error' };
      }
    }

    if (strategy === 'JWT') {
      try {
        const jwtValidator = this.getJwtValidator(normalizedConfig.jwtConfig);

        const authHeader = request.headers.get('authorization');
        if (!authHeader) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        const bearerToken = jwtValidator.extractBearerToken(authHeader);
        if (!bearerToken) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        const validationResult = await jwtValidator.validate(bearerToken);
        if (!validationResult.isValid) {
          return { authenticated: false, reason: 'not_authenticated' };
        }

        return { authenticated: true, usedStrategy: 'JWT' };
      } catch {
        return { authenticated: false, reason: 'unexpected_error' };
      }
    }

    // Should never reach here
    return { authenticated: false, reason: 'unexpected_error' };
  }

  /**
   * Creates the appropriate failure response based on the authentication failure reason
   * and whether the request is for an API route or page route.
   *
   * @param request - The incoming request
   * @param reason - Why authentication failed
   * @param isProtectedApiRoute - Whether this is a protected API route
   * @param normalizedConfig - The normalized middleware configuration
   * @returns NextResponse with appropriate status code or redirect
   */
  private async getAuthFailureResponse(
    request: NextRequest,
    reason: AuthFailureReason,
    isProtectedApiRoute: boolean,
    normalizedConfig: NormalizedMiddlewareConfig
  ): Promise<NextResponse> {
    if (isProtectedApiRoute) {
      // Return appropriate HTTP status based on failure reason
      let status: number;
      let errorMessage: string;

      switch (reason) {
        case 'unexpected_error':
          status = 500;
          errorMessage = 'Internal Server Error';
          break;
        case 'csrf_failed':
          status = 403;
          errorMessage = 'Forbidden';
          break;
        case 'not_authenticated':
        case 'token_refresh_failed':
        default:
          status = 401;
          errorMessage = 'Unauthorized';
      }

      return NextResponse.json({ error: errorMessage }, { status });
    }

    // Protected page route - invoke the unauthenticated handler
    const loginUrl = await this.core.getLoginUrl();
    const onPageUnauthenticatedHandler = resolveOnPageUnauthenticated(normalizedConfig, loginUrl);
    return onPageUnauthenticatedHandler(request, reason);
  }

  /**
   * Validates authentication for Server Actions by checking session validity and refreshing tokens if needed.
   *
   * Note: CSRF validation is not performed as Next.js Server Actions have built-in
   * CSRF protection via Origin/Host header comparison.
   *
   * @template T - Session data type extending SessionData
   * @param cookieStore - Next.js cookie store from await cookies()
   * @param sessionOptions - Session configuration options
   * @returns Promise resolving to authentication result with session data or failure reason
   */
  private async authenticateServerAction<T extends SessionData = SessionData>(
    cookieStore: NextJsCookieStore,
    sessionOptions: SessionOptions
  ): Promise<ServerActionAuthResult<T>> {
    try {
      // Get mutable session from cookies
      const session = await getMutableSessionFromCookies<T>(cookieStore, sessionOptions);
      // Check if user is authenticated
      if (!session.isAuthenticated) {
        return { authenticated: false, reason: 'not_authenticated' };
      }

      if (!(await this.refreshSessionTokens(session))) {
        return { authenticated: false, reason: 'token_refresh_failed' };
      }

      // Always save session with or without token refresh ("touch" for rolling session expiration)
      await saveSessionWithCookies(cookieStore, session);

      // Authentication successful
      return { authenticated: true, session };
    } catch {
      return { authenticated: false, reason: 'unexpected_error' };
    }
  }

  /**
   * Refreshes the session's access token if it has expired, writing the new tokens onto the session. Shared by the
   * middleware SESSION strategy and Server Action auth.
   *
   * @returns `false` if the refresh failed and the user has to log in again, otherwise `true`.
   */
  private async refreshSessionTokens(session: {
    accessToken?: string;
    expiresAt?: number;
    refreshToken?: string;
  }): Promise<boolean> {
    if (!session.refreshToken || session.expiresAt === undefined) {
      return true;
    }
    try {
      const newTokenData = await this.refreshTokenIfExpired(session.refreshToken, session.expiresAt);
      if (newTokenData) {
        session.accessToken = newTokenData.accessToken;
        // The core returns the current refresh token when Wristband doesn't issue a new one.
        session.refreshToken = newTokenData.refreshToken;
        session.expiresAt = newTokenData.expiresAt;
      }
      return true;
    } catch {
      return false;
    }
  }
}
