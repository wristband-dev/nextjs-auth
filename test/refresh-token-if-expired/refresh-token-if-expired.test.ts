import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

const wristbandAuth: WristbandAuth = createWristbandAuth({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
  loginUrl: LOGIN_URL,
  redirectUri: REDIRECT_URI,
  wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
});

describe('Refresh Token If Expired', () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    global.fetch = jest.fn();
  });

  test('Token is not expired', async () => {
    // Choose some arbitrary time in the future from the current time (in milliseconds)
    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() + 1000000);
    expect(tokenData).toBeNull();
  });

  test('Token is expired, perform a token refresh', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    // Mock different fetch calls based on the URL
    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        // Mock the token refresh response
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      }

      // Handle other URLs if necessary
      return Promise.reject(new Error('Unexpected URL'));
    });

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1800,
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });
    // Ensure fetch was called with the expected URL and options
    expect(global.fetch).toHaveBeenCalledWith(
      `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`,
      expect.objectContaining({ body: 'grant_type=refresh_token&refresh_token=refreshToken' })
    );
  });
});
