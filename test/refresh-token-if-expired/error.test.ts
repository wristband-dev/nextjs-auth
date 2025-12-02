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

describe('Refresh Token Errors', () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    global.fetch = jest.fn();
  });

  test('Invalid refreshToken', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('', 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(TypeError);
      expect(error.message).toBe('Refresh token must be a valid string');
    }
  });

  test('Invalid expiresAt', async () => {
    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', -1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(TypeError);
      expect(error.message).toBe('The expiresAt field must be an integer greater than 0');
    }
  });

  test('Perform a token refresh with a bad token value', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 400,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Invalid refresh token');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Perform a token refresh with InvalidGrantError', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'The refresh token is invalid or expired',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 400,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('The refresh token is invalid or expired');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Perform a token refresh with a server error', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Internal server error',
    };

    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Perform a token refresh with 401 error', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Unauthorized',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 401,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 401');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Unauthorized');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Perform a token refresh with 403 error', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Forbidden',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 403,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 403');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Forbidden');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Perform a token refresh with 422 error', async () => {
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Unprocessable Entity',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 422,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 422');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Unprocessable Entity');
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Perform a token refresh with 500 error', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Internal Server Error',
    };

    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 500');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Perform a token refresh with 502 error', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Bad Gateway',
    };

    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 502,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 502');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Perform a token refresh with 503 error', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Service Unavailable',
    };

    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 503,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 503');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Perform a token refresh with 504 error', async () => {
    const mockError = {
      error: 'server_error',
      error_description: 'Gateway Timeout',
    };

    (global.fetch as jest.Mock).mockImplementation((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 504,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown for status 504');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });

  test('Perform a token refresh with error without error_description', async () => {
    const mockError = {
      error: 'invalid_grant',
      // No error_description field
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 400,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('invalid_refresh_token');
      expect(error.errorDescription).toBe('Invalid grant'); // Default fallback
    }
  });

  test('Perform a token refresh with network error', async () => {
    (global.fetch as jest.Mock).mockImplementation(() => {
      throw new Error('Network connection failed');
    });

    try {
      await wristbandAuth.refreshTokenIfExpired('refreshToken', Date.now().valueOf() - 1000);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.code).toBe('unexpected_error');
      expect(error.errorDescription).toBe('Unexpected Error');
    }

    expect(global.fetch).toHaveBeenCalledTimes(3);
  });
});
