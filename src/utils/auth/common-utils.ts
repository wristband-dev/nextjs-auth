import { FetchError, InvalidGrantError, WristbandError } from '../../error';
import { TokenData, TokenResponse } from '../../types';
import { WristbandService } from '../../wristband-service';

/**
 * Resolves a tenant custom domain to itself when it is verified and belongs to your Wristband
 * application. Resolves to an empty string otherwise, so the caller skips over it and falls through
 * to the next domain in its resolution precedence order.
 *
 * @param tenantCustomDomain - The tenant custom domain to validate.
 * @param wristbandService - Service instance used to perform the validation request.
 * @returns The tenant custom domain when valid, otherwise an empty string.
 */
export async function resolveValidTenantCustomDomain(
  tenantCustomDomain: string,
  wristbandService: WristbandService
): Promise<string> {
  if (!tenantCustomDomain) {
    return '';
  }

  const isValid = await wristbandService.validateTenantCustomDomain(tenantCustomDomain);
  return isValid ? tenantCustomDomain : '';
}

export function getAppLevelLoginUrl(
  wristbandApplicationVanityDomain: string,
  clientId: string,
  customApplicationLoginPageUrl?: string
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!clientId) {
    throw new Error('clientId cannot be null or undefined');
  }

  const apploginUrl = customApplicationLoginPageUrl || `https://${wristbandApplicationVanityDomain}/login`;
  return `${apploginUrl}?client_id=${clientId}`;
}

export function getAppLevelAuthorizationUrl(
  wristbandApplicationVanityDomain: string,
  authorizationParams: URLSearchParams
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!authorizationParams || authorizationParams.size === 0) {
    throw new Error('authorizationParams cannot be null or empty');
  }

  return `https://${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${authorizationParams.toString()}`;
}

export function getTenantLevelAuthorizationUrl(
  wristbandApplicationVanityDomain: string,
  authorizationParams: URLSearchParams,
  config: {
    defaultTenantCustomDomain?: string;
    defaultTenantName?: string;
    tenantCustomDomain?: string;
    tenantName?: string;
    isApplicationCustomDomainActive?: boolean;
  }
): string {
  // Safety check: this should never happen.
  if (!wristbandApplicationVanityDomain) {
    throw new Error('wristbandApplicationVanityDomain cannot be null or undefined');
  }
  if (!authorizationParams || authorizationParams.size === 0) {
    throw new Error('authorizationParams cannot be null or empty');
  }

  // Safety check: this should never happen.
  if (
    !config.defaultTenantCustomDomain &&
    !config.defaultTenantName &&
    !config.tenantCustomDomain &&
    !config.tenantName
  ) {
    throw new Error('No tenant name or tenant custom domain was provided');
  }

  const queryString = authorizationParams.toString();
  const separator = config.isApplicationCustomDomainActive ? '.' : '-';

  // Domain priority order resolution:
  // 1)  tenant_custom_domain query param
  // 2a) tenant subdomain
  // 2b) tenant_name query param
  // 3)  defaultTenantCustomDomain login config
  // 4)  defaultTenantName login config
  if (config.tenantCustomDomain) {
    return `https://${config.tenantCustomDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  if (config.tenantName) {
    return `https://${config.tenantName}${separator}${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  if (config.defaultTenantCustomDomain) {
    return `https://${config.defaultTenantCustomDomain}/api/v1/oauth2/authorize?${queryString}`;
  }
  return `https://${config.defaultTenantName}${separator}${wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryString}`;
}

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
