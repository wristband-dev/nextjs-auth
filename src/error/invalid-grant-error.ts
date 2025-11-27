import { WristbandError } from './wristband-error';

/**
 * Represents an OAuth2 `invalid_grant` error.
 *
 * Typically occurs when refresh tokens are invalid, expired, or revoked.
 * Extends {@link WristbandError} with a fixed error code of `'invalid_grant'`.
 */
export class InvalidGrantError extends WristbandError {
  /**
   * Creates a new InvalidGrantError instance.
   *
   * @param errorDescription - Optional human-readable description of the error.
   */
  constructor(errorDescription?: string) {
    super('invalid_grant', errorDescription || '');
  }
}
