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

  // Try up to 3 times to perform a token refresh
  let tokenResponse: TokenResponse | null = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      tokenResponse = await wristbandService.refreshToken(refreshToken);
      break;
    } catch (error: any) {
      if (error instanceof InvalidGrantError) {
        // Specifically handle invalid_grant errors
        throw new WristbandError('invalid_refresh_token', error.errorDescription, error);
      }

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
