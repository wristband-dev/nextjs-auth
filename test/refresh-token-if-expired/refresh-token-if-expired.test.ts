import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src/index';

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
  autoConfigureEnabled: false, // Disable auto-config to avoid SDK config calls
});

describe('Refresh Token If Expired', () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    global.fetch = jest.fn();
  });

  test('Invalid refreshToken', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('', 1000);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Refresh token must be a valid string');
    }
  });

  test('Invalid expiresAt', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', -1000);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('The expiresAt field must be an integer greater than 0');
    }
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

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    const beforeTime = Date.now();
    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
    const afterTime = Date.now();

    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1740, // 1800 - 60 (default buffer)
      expiresAt: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });

    // Verify expiresAt is calculated correctly with buffer
    const expectedExpiresIn = 1800 - 60; // expires_in minus tokenExpirationBuffer
    const expectedMinExpiresAt = beforeTime + expectedExpiresIn * 1000;
    const expectedMaxExpiresAt = afterTime + expectedExpiresIn * 1000;

    expect(tokenData!.expiresAt).toBeGreaterThanOrEqual(expectedMinExpiresAt);
    expect(tokenData!.expiresAt).toBeLessThanOrEqual(expectedMaxExpiresAt);

    expect(global.fetch).toHaveBeenCalledWith(
      `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`,
      expect.objectContaining({
        body: 'grant_type=refresh_token&refresh_token=refreshToken',
        method: 'POST',
      })
    );
  });

  test('Perform a token refresh with a bad token value (4xx error)', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
    };
    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: true,
          status: 400,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.error).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Invalid refresh token');
    }
  });

  test('Perform a token refresh with a server error (5xx error)', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Internal server error',
    };
    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.error).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    // Should have been called 3 times (all attempts)
    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Token refresh retry logic - succeeds on second attempt', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    (global.fetch as jest.Mock)
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'server_error' })),
        });
      })
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      });

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);

    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1740, // 1800 - 60 (default buffer)
      expiresAt: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });

    // Should have been called twice (first failure, then success)
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  test('Token refresh retry logic - succeeds on third attempt', async () => {
    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    (global.fetch as jest.Mock)
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'server_error' })),
        });
      })
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 503,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'service_unavailable' })),
        });
      })
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      });

    const tokenData = await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);

    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1740, // 1800 - 60 (default buffer)
      expiresAt: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });

    // Should have been called three times (two failures, then success)
    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Token refresh with custom tokenExpirationBuffer', async () => {
    const customBufferAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
      tokenExpirationBuffer: 120, // Custom 2-minute buffer
    });

    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    const tokenData = await customBufferAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);

    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1680, // 1800 - 120 (custom buffer)
      expiresAt: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });
  });

  test('Token refresh with zero tokenExpirationBuffer', async () => {
    const zeroBufferAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
      tokenExpirationBuffer: 0,
    });

    const mockTokens = {
      access_token: 'accessToken',
      expires_in: 1800,
      id_token: 'idToken',
      refresh_token: 'refreshToken',
      token_type: 'bearer',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    const tokenData = await zeroBufferAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);

    expect(tokenData).toEqual({
      accessToken: 'accessToken',
      expiresIn: 1800, // No buffer applied
      expiresAt: expect.any(Number),
      idToken: 'idToken',
      refreshToken: 'refreshToken',
    });
  });

  test('Token refresh timing - should wait 100ms between retries', async () => {
    const startTime = Date.now();

    (global.fetch as jest.Mock)
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'server_error' })),
        });
      })
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'server_error' })),
        });
      })
      .mockImplementationOnce(() => {
        return Promise.resolve({
          ok: true,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify({ error: 'server_error' })),
        });
      });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
    } catch (error) {
      // Expected to fail after all retries
    }

    const endTime = Date.now();
    const elapsed = endTime - startTime;

    // Should have taken at least 200ms for 2 delays between 3 attempts
    expect(elapsed).toBeGreaterThanOrEqual(180);
    expect(global.fetch).toHaveBeenCalledTimes(3);
  });
});
