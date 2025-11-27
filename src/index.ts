import { createWristbandAuth, WristbandAuth } from './auth';
import { WristbandError } from './error';
import {
  destroySessionWithCookies,
  getMutableSessionFromCookies,
  getPagesRouterSession,
  getReadOnlySessionFromCookies,
  getSessionFromRequest,
  saveSessionWithCookies,
} from './session';
import {
  AuthConfig,
  AuthMiddlewareConfig,
  AuthStrategy,
  CallbackData,
  CallbackResult,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  MutableSession,
  NextJsCookieStore,
  ReadOnlySession,
  ServerActionAuthResult,
  TokenData,
  UserInfo,
  UserInfoRole,
} from './types';

/**
 * Exports
 */
export {
  type AuthConfig,
  type AuthMiddlewareConfig,
  AuthStrategy,
  type CallbackData,
  type CallbackResult,
  CallbackResultType,
  createWristbandAuth,
  destroySessionWithCookies,
  getMutableSessionFromCookies,
  getPagesRouterSession,
  getReadOnlySessionFromCookies,
  getSessionFromRequest,
  type LoginConfig,
  type LogoutConfig,
  type MutableSession,
  type NextJsCookieStore,
  type ReadOnlySession,
  saveSessionWithCookies,
  type ServerActionAuthResult,
  type TokenData,
  type UserInfo,
  type UserInfoRole,
  type WristbandAuth,
  WristbandError,
};

/**
 * Re-export session types from typescript-session
 *
 * These types are needed for session configuration and custom session data definitions.
 */
export {
  type SameSiteOption,
  type Session,
  type SessionData,
  SessionError,
  SessionErrorCode,
  type SessionOptions,
  type SessionResponse,
  type TokenResponse,
} from '@wristband/typescript-session';

/**
 * Re-export from typescript-jwt
 */
export {
  createWristbandJwtValidator,
  type JWTPayload,
  type JwtValidationResult,
  type WristbandJwtValidator,
  type WristbandJwtValidatorConfig,
} from '@wristband/typescript-jwt';
