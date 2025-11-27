import { FetchError, InvalidGrantError } from './error';
import { SdkConfiguration, TokenResponse, UserInfo, WristbandUserinfoResponse } from './types';
import { encodeBase64 } from './utils/crypto';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from './utils/constants';
import { WristbandApiClient } from './wristband-api-client';

/**
 * Service class for making REST API calls to the Wristband platform.
 *
 * Handles OAuth token exchange, user information retrieval, token refresh,
 * and token revocation. Most methods use HTTP Basic Authentication with
 * the configured client credentials.
 *
 * @internal
 */
export class WristbandService {
  private wristbandApiClient: WristbandApiClient;
  private basicAuthHeaders: HeadersInit;
  private clientId: string;

  constructor(wristbandApplicationVanityDomain: string, clientId: string, clientSecret: string) {
    this.wristbandApiClient = new WristbandApiClient(wristbandApplicationVanityDomain);
    this.basicAuthHeaders = {
      'Content-Type': FORM_URLENCODED_MEDIA_TYPE,
      Accept: JSON_MEDIA_TYPE,
      Authorization: `Basic ${encodeBase64(`${clientId}:${clientSecret}`)}`,
    };
    this.clientId = clientId;
  }

  /**
   * Fetches SDK configuration from Wristband's auto-configuration endpoint.
   *
   * Retrieves application-specific configuration values including login URLs,
   * redirect URIs, and custom domain settings.
   *
   * @returns Promise resolving to the SDK configuration object
   * @throws {Error} When the API request fails
   */
  async getSdkConfiguration(): Promise<SdkConfiguration> {
    const jsonHeaders = { 'Content-Type': JSON_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE };
    const sdkConfig = await this.wristbandApiClient.get<SdkConfiguration>(
      `/clients/${this.clientId}/sdk-configuration`,
      jsonHeaders
    );
    return sdkConfig;
  }

  /**
   * Exchanges an authorization code for OAuth tokens.
   *
   * Makes a request to Wristband's token endpoint using the authorization code
   * received from the callback. Uses PKCE (code verifier) for enhanced security.
   *
   * @param code - The authorization code from the OAuth callback
   * @param redirectUri - The redirect URI used in the authorization request
   * @param codeVerifier - The PKCE code verifier for this authorization request
   * @returns Promise resolving to token response with access_token, id_token, and optional refresh_token
   * @throws {Error} When any parameter is missing or empty
   * @throws {InvalidGrantError} When the authorization code is invalid or expired
   */
  async getTokens(code: string, redirectUri: string, codeVerifier: string): Promise<TokenResponse> {
    if (!code || !code.trim()) {
      throw new Error('Authorization code is required');
    }

    if (!redirectUri || !redirectUri.trim()) {
      throw new Error('Redirect URI is required');
    }

    if (!codeVerifier || !codeVerifier.trim()) {
      throw new Error('Code verifier is required');
    }

    const authData: string = [
      'grant_type=authorization_code',
      `code=${code}`,
      `redirect_uri=${encodeURIComponent(redirectUri)}`,
      `code_verifier=${encodeURIComponent(codeVerifier)}`,
    ].join('&');

    try {
      const tokenResponse = await this.wristbandApiClient.post<TokenResponse>(
        '/oauth2/token',
        authData,
        this.basicAuthHeaders
      );
      return tokenResponse;
    } catch (error) {
      if (WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid grant');
      }
      throw error;
    }
  }

  /**
   * Retrieves user information from Wristband's userinfo endpoint.
   *
   * Fetches OIDC-compliant user claims including profile, email, phone, and role data
   * based on the scopes associated with the access token. Transforms snake_case OIDC
   * claims to camelCase field names.
   *
   * @param accessToken - The OAuth access token
   * @returns Promise resolving to structured UserInfo object with user claims
   * @throws {Error} When access token is missing or empty
   * @throws {TypeError} When response is invalid or missing required claims
   */
  async getUserinfo(accessToken: string): Promise<UserInfo> {
    if (!accessToken || !accessToken.trim()) {
      throw new Error('Access token is required');
    }

    const bearerTokenHeaders = {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': JSON_MEDIA_TYPE,
      Accept: JSON_MEDIA_TYPE,
    };
    const userinfo = await this.wristbandApiClient.get('/oauth2/userinfo', bearerTokenHeaders);

    // Validate response data is a valid UserInfo object
    WristbandService.validateUserinfoResponse(userinfo);

    return WristbandService.mapUserinfoClaims(userinfo);
  }

  /**
   * Refreshes an expired access token using a refresh token.
   *
   * Exchanges a valid refresh token for a new set of tokens. The refresh token
   * must have been obtained with the 'offline_access' scope.
   *
   * @param refreshToken - The refresh token
   * @returns Promise resolving to new token response with fresh access_token and id_token
   * @throws {Error} When refresh token is missing or empty
   * @throws {InvalidGrantError} When the refresh token is invalid or expired
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('Refresh token is required');
    }

    const authData: string = `grant_type=refresh_token&refresh_token=${refreshToken}`;

    try {
      const tokenResponse = await this.wristbandApiClient.post<TokenResponse>(
        '/oauth2/token',
        authData,
        this.basicAuthHeaders
      );
      return tokenResponse;
    } catch (error) {
      if (WristbandService.hasInvalidGrantError(error)) {
        throw new InvalidGrantError(WristbandService.getErrorDescription(error) || 'Invalid grant');
      }
      throw error;
    }
  }

  /**
   * Revokes a refresh token to invalidate it.
   *
   * Makes a request to Wristband's revocation endpoint to permanently invalidate
   * the refresh token. After revocation, the token can no longer be used to obtain
   * new access tokens. This is typically called during logout.
   *
   * @param refreshToken - The refresh token to revoke
   * @returns Promise that resolves when revocation is complete
   * @throws {Error} When refresh token is missing or empty
   */
  async revokeRefreshToken(refreshToken: string): Promise<void> {
    if (!refreshToken || !refreshToken.trim()) {
      throw new Error('Refresh token is required');
    }

    await this.wristbandApiClient.post<void>('/oauth2/revoke', `token=${refreshToken}`, this.basicAuthHeaders);
  }

  /// /////////////////////////////////
  //  PRIVATE METHODS
  /// /////////////////////////////////

  /**
   * Checks if a FetchError contains an invalid_grant error.
   *
   * @param error - The FetchError to check
   * @returns True if the response body has error code 'invalid_grant'
   *
   * @internal
   */
  private static hasInvalidGrantError(error: unknown): boolean {
    if (error instanceof FetchError) {
      const data = error.body;
      return data && typeof data === 'object' && 'error' in data && (data as any).error === 'invalid_grant';
    }

    return false;
  }

  /**
   * Extracts the error_description field from a FetchError response.
   *
   * @param error - The FetchError
   * @returns The error description string, or undefined if not present
   *
   * @internal
   */
  private static getErrorDescription(error: unknown): string | undefined {
    if (error instanceof FetchError) {
      const data = error.body;
      if (data && typeof data === 'object' && 'error_description' in data) {
        return (data as any).error_description as string;
      }
    }
    return undefined;
  }

  /**
   * Validates that the userinfo response from Wristband contains all required OIDC claims.
   *
   * Checks for the presence and correct types of mandatory claims that Wristband
   * always returns regardless of scopes: sub (userId), tnt_id (tenantId),
   * app_id (applicationId), and idp_name (identityProviderName).
   *
   * @param data - The raw response data from the userinfo endpoint
   * @throws {Error} When response is not an object or missing required claims
   *
   * @internal
   */
  private static validateUserinfoResponse(data: any): asserts data is WristbandUserinfoResponse {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new TypeError('Invalid userinfo response: expected object');
    }

    // Validate required fields that are always present
    if (!data.sub || typeof data.sub !== 'string') {
      throw new TypeError('Invalid userinfo response: missing sub claim');
    }
    if (!data.tnt_id || typeof data.tnt_id !== 'string') {
      throw new TypeError('Invalid userinfo response: missing tnt_id claim');
    }
    if (!data.app_id || typeof data.app_id !== 'string') {
      throw new TypeError('Invalid userinfo response: missing app_id claim');
    }
    if (!data.idp_name || typeof data.idp_name !== 'string') {
      throw new TypeError('Invalid userinfo response: missing idp_name claim');
    }
  }

  /**
   * Transforms the raw OIDC claims from Wristband's userinfo endpoint
   * to the structured UserInfo type with camelCase field names.
   *
   * @param userinfo - Raw userinfo claims from Wristband auth SDK
   * @returns Structured UserInfo object from Wristband session SDK
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private static mapUserinfoClaims(userinfo: WristbandUserinfoResponse): UserInfo {
    return {
      // Always present
      userId: userinfo.sub,
      tenantId: userinfo.tnt_id,
      applicationId: userinfo.app_id,
      identityProviderName: userinfo.idp_name,

      // Profile scope
      fullName: userinfo.name ?? undefined,
      givenName: userinfo.given_name ?? undefined,
      familyName: userinfo.family_name ?? undefined,
      middleName: userinfo.middle_name ?? undefined,
      nickname: userinfo.nickname ?? undefined,
      displayName: userinfo.preferred_username ?? undefined,
      pictureUrl: userinfo.picture ?? undefined,
      gender: userinfo.gender ?? undefined,
      birthdate: userinfo.birthdate ?? undefined,
      timeZone: userinfo.zoneinfo ?? undefined,
      locale: userinfo.locale ?? undefined,
      updatedAt: userinfo.updated_at ?? undefined,

      // Email scope
      email: userinfo.email ?? undefined,
      emailVerified: userinfo.email_verified ?? undefined,

      // Phone scope
      phoneNumber: userinfo.phone_number ?? undefined,
      phoneNumberVerified: userinfo.phone_number_verified ?? undefined,

      // Roles scope
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      roles: userinfo.roles?.map((role: any) => {
        return {
          id: role.id,
          name: role.name,
          displayName: role.display_name || role.displayName,
        };
      }),

      // Custom claims
      customClaims: userinfo.custom_claims,
    };
  }
}
