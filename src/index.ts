import {
  AuthConfig,
  CallbackConfig,
  CallbackData,
  CallbackResult,
  CallbackResultType,
  LoginConfig,
  LogoutConfig,
  TokenData,
} from './types';
import { WristbandAuth, WristbandAuthImpl } from './auth/wristband-auth';
import { WristbandError } from './error';

/**
 * Wristband SDK function to create an instance of WristbandAuth.
 * @param {AuthConfig} - authConfig Configuration for Wristband authentication.
 * @returns {WristbandAuth} - An instance of WristbandAuth.
 */
function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {
  return new WristbandAuthImpl(authConfig);
}

/**
 * Exports
 */
export type {
  AuthConfig,
  CallbackConfig,
  CallbackData,
  CallbackResult,
  LoginConfig,
  LogoutConfig,
  TokenData,
  WristbandAuth,
};
export { createWristbandAuth, CallbackResultType, WristbandError };
