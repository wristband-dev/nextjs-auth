import type { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionData, SessionOptions } from '@wristband/typescript-session';
import {
  createWristbandJwtValidator,
  WristbandJwtValidatorConfig,
  WristbandJwtValidator,
} from '@wristband/typescript-jwt';

import { ConfigResolver } from '../config-resolver';
import { AppRouterAuthHandler } from './handlers/app-router-auth-handler';
import { PagesRouterAuthHandler } from './handlers/pages-router-auth-handler';
import { getSessionFromRequest } from '../session';
import {
  AuthFailureReason,
  AuthStrategy,
  AuthStrategyResult,
  NextJsCookieStore,
  NormalizedMiddlewareConfig,
  ServerActionAuthResult,
  type AuthConfig,
  type AuthMiddlewareConfig,
  type CallbackResult,
  type LoginConfig,
  type LogoutConfig,
  type TokenData,
} from '../types';
import { refreshExpiredToken } from '../utils/auth/common-utils';
import {
  copyResponseHeaders,
  isProtectedApi,
  isProtectedPage,
  isValidCsrf,
  normalizeMiddlewareConfig,
  resolveOnPageUnauthenticated,
} from '../utils/middleware';
import { WristbandAuth } from './wristband-auth';
import { WristbandService } from '../wristband-service';

/**
 * WristbandAuth is a utility class providing methods for seamless interaction with the Wristband authentication service.
 * @implements {WristbandAuth}
 */
export class WristbandAuthImpl implements WristbandAuth {
  private configResolver: ConfigResolver;
  private appRouterAuthHandler: AppRouterAuthHandler;
  private pagesRouterAuthHandler: PagesRouterAuthHandler;
  private wristbandService: WristbandService;
  private jwtValidator?: WristbandJwtValidator;

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
    this.pagesRouterAuthHandler = new PagesRouterAuthHandler(this.configResolver, this.wristbandService);
  }

  /**
   * @see {@link WristbandAuth.appRouter}
   */
  appRouter = {
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    login: (request: NextRequest, loginConfig?: LoginConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.login(request, loginConfig);
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    callback: (request: NextRequest): Promise<CallbackResult> => {
      return this.appRouterAuthHandler.callback(request);
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    logout: (request: NextRequest, logoutConfig?: LogoutConfig): Promise<NextResponse> => {
      return this.appRouterAuthHandler.logout(request, logoutConfig);
    },
    /**
     * @see {@link WristbandAuth.appRouter} for full documentation
     */
    createCallbackResponse: (request: NextRequest, redirectUrl: string): Promise<NextResponse> => {
      return this.appRouterAuthHandler.createCallbackResponse(request, redirectUrl);
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
        return this.appRouterAuthHandler.createServerActionAuth<T>(cookieStore, config.sessionOptions);
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
      return this.pagesRouterAuthHandler.login(request, response, loginConfig);
    },
    /**
     * @see {@link WristbandAuth.pagesRouter} for full documentation
     */
    callback: (request: NextApiRequest, response: NextApiResponse): Promise<CallbackResult> => {
      return this.pagesRouterAuthHandler.callback(request, response);
    },
    /**
     * @see {@link WristbandAuth.pagesRouter} for full documentation
     */
    logout: (request: NextApiRequest, response: NextApiResponse, logoutConfig?: LogoutConfig): Promise<string> => {
      return this.pagesRouterAuthHandler.logout(request, response, logoutConfig);
    },
  };

  /**
   * @see {@link WristbandAuth.refreshTokenIfExpired}
   */
  async refreshTokenIfExpired(refreshToken: string, expiresAt: number): Promise<TokenData | null> {
    // Fetch SDK Configs
    const tokenExpirationBuffer = this.configResolver.getTokenExpirationBuffer();
    return refreshExpiredToken(refreshToken, expiresAt, this.wristbandService, tokenExpirationBuffer);
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
      const wristbandApplicationVanityDomain = this.configResolver.getWristbandApplicationVanityDomain();
      this.jwtValidator = createWristbandJwtValidator({
        wristbandApplicationVanityDomain,
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

        // Try to refresh token if expired
        if (session.refreshToken && session.expiresAt !== undefined) {
          try {
            const newTokenData = await this.refreshTokenIfExpired(session.refreshToken, session.expiresAt);
            if (newTokenData) {
              session.accessToken = newTokenData.accessToken;
              session.refreshToken = newTokenData.refreshToken;
              session.expiresAt = newTokenData.expiresAt;
            }
          } catch (error) {
            return { authenticated: false, reason: 'token_refresh_failed' };
          }
        }

        return { authenticated: true, session, usedStrategy: 'SESSION' };
      } catch (error) {
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
      } catch (error) {
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
    const loginUrl = await this.configResolver.getLoginUrl();
    const onPageUnauthenticatedHandler = resolveOnPageUnauthenticated(normalizedConfig, loginUrl);
    return onPageUnauthenticatedHandler(request, reason);
  }
}
