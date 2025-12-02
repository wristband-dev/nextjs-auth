import { WristbandAuth } from './wristband-auth';
import { WristbandAuthImpl } from './wristband-auth-impl';
import { AuthConfig } from '../types';

/**
 * Wristband SDK function to create an instance of WristbandAuth.
 * @param {AuthConfig} - authConfig Configuration for Wristband authentication.
 * @returns {WristbandAuth} - An instance of WristbandAuth.
 */
export function createWristbandAuth(authConfig: AuthConfig): WristbandAuth {
  return new WristbandAuthImpl(authConfig);
}
