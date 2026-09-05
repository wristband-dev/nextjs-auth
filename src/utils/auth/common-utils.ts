import { FetchError, InvalidGrantError, WristbandError } from '../../error';
import { TokenData, TokenResponse } from '../../types';
import { WristbandService } from '../../wristband-service';

/**
 * Refreshes an access token if it has expired.
 *
 * @param refreshToken - The refresh token to use
 * @param expiresAt - When the current access token expires (milliseconds since epoch)
 * @param wristbandService - Service instance to make the token refresh request
 * @param tokenExpirationBuffer - Optional buffer time in seconds
 * @returns New token data if refreshed, null if not expired yet
 * @throws {WristbandError} if refresh fails
 */
export async function refreshExpiredToken(
  refreshToken: string,
  expiresAt: number,
  wristbandService: WristbandService,
  tokenExpirationBuffer?: number
): Promise<TokenData | null> {
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

  // Retrying on transient failures (5xx errors, network errors) is already handled one layer
  // down by WristbandService -- see withRetry() in utils/retry.ts. By the time an error surfaces
  // here, retries (if any applied) have already been exhausted.
  let tokenResponse: TokenResponse;
  try {
    tokenResponse = await wristbandService.refreshToken(refreshToken);
  } catch (error: unknown) {
    if (error instanceof InvalidGrantError) {
      // Specifically handle invalid_grant errors
      throw new WristbandError('invalid_refresh_token', error.errorDescription, error);
    }

    // Any remaining 4xx error also indicates an invalid refresh token.
    if (error instanceof FetchError && error.response && error.response.status >= 400 && error.response.status < 500) {
      const errorDescription =
        // @ts-expect-error - body is unknown, error_description access not type-checked
        error.body && error.body.error_description ? error.body.error_description : 'Invalid Refresh Token';
      throw new WristbandError('invalid_refresh_token', errorDescription, error);
    }

    throw new WristbandError('unexpected_error', 'Unexpected Error', error instanceof Error ? error : undefined);
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
