// The Wristband Service contains all code for REST API calls to the Wristband platform.
import { WristbandApiClient } from './wristband-api-client';
import { FORM_URLENCODED_MEDIA_TYPE, JSON_MEDIA_TYPE } from './utils/constants';
import { SdkConfiguration, TokenResponse, Userinfo } from './types';
import { encodeBase64 } from './utils/auth/common-utils';

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

  async getSdkConfiguration(): Promise<SdkConfiguration> {
    const jsonHeaders = { 'Content-Type': JSON_MEDIA_TYPE, Accept: JSON_MEDIA_TYPE };

    const sdkConfig = await this.wristbandApiClient.get<SdkConfiguration>(
      `/clients/${this.clientId}/sdk-configuration`,
      jsonHeaders
    );

    return sdkConfig;
  }

  async getTokens(code: string, redirectUri: string, codeVerifier: string): Promise<TokenResponse> {
    const authData: string = [
      'grant_type=authorization_code',
      `code=${code}`,
      `redirect_uri=${encodeURIComponent(redirectUri)}`,
      `code_verifier=${encodeURIComponent(codeVerifier)}`,
    ].join('&');

    const tokenResponse = await this.wristbandApiClient.post<TokenResponse>(
      '/oauth2/token',
      authData,
      this.basicAuthHeaders
    );
    return tokenResponse;
  }

  async getUserinfo(accessToken: string): Promise<Userinfo> {
    const bearerTokenHeaders = {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': JSON_MEDIA_TYPE,
      Accept: JSON_MEDIA_TYPE,
    };
    const userinfo = await this.wristbandApiClient.get<Userinfo>('/oauth2/userinfo', bearerTokenHeaders);
    return userinfo;
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const authData: string = `grant_type=refresh_token&refresh_token=${refreshToken}`;
    const tokenResponse = await this.wristbandApiClient.post<TokenResponse>(
      '/oauth2/token',
      authData,
      this.basicAuthHeaders
    );
    return tokenResponse;
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    await this.wristbandApiClient.post<void>('/oauth2/revoke', `token=${refreshToken}`, this.basicAuthHeaders);
  }
}
