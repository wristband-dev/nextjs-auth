import { FetchError, InvalidGrantError, WristbandError } from '../../../src/error';
import { WristbandService } from '../../../src/wristband-service';
import { refreshExpiredToken } from '../../../src/utils/auth/common-utils';

// Mock WristbandService
jest.mock('../../../src/wristband-service');

describe('refreshExpiredToken()', () => {
  let mockWristbandService: jest.Mocked<WristbandService>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockWristbandService = {
      refreshToken: jest.fn(),
    } as any;
  });

  describe('Input Validation', () => {
    test('should throw TypeError when refreshToken is empty string', async () => {
      await expect(refreshExpiredToken('', Date.now() + 1000, mockWristbandService)).rejects.toThrow(TypeError);
      await expect(refreshExpiredToken('', Date.now() + 1000, mockWristbandService)).rejects.toThrow(
        'Refresh token must be a valid string'
      );
    });

    test('should throw TypeError when refreshToken is undefined', async () => {
      await expect(refreshExpiredToken(undefined as any, Date.now() + 1000, mockWristbandService)).rejects.toThrow(
        TypeError
      );
    });

    test('should throw TypeError when expiresAt is 0', async () => {
      await expect(refreshExpiredToken('valid-token', 0, mockWristbandService)).rejects.toThrow(TypeError);
      await expect(refreshExpiredToken('valid-token', 0, mockWristbandService)).rejects.toThrow(
        'The expiresAt field must be an integer greater than 0'
      );
    });

    test('should throw TypeError when expiresAt is negative', async () => {
      await expect(refreshExpiredToken('valid-token', -1000, mockWristbandService)).rejects.toThrow(TypeError);
      await expect(refreshExpiredToken('valid-token', -1000, mockWristbandService)).rejects.toThrow(
        'The expiresAt field must be an integer greater than 0'
      );
    });

    test('should throw TypeError when expiresAt is undefined', async () => {
      await expect(refreshExpiredToken('valid-token', undefined as any, mockWristbandService)).rejects.toThrow(
        TypeError
      );
    });
  });

  describe('Token Not Expired', () => {
    test('should return null when token has not expired yet', async () => {
      const futureExpiry = Date.now() + 3600000; // 1 hour from now

      const result = await refreshExpiredToken('valid-token', futureExpiry, mockWristbandService);

      expect(result).toBeNull();
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });

    test('should return null when token expires far in the future', async () => {
      const farFutureExpiry = Date.now() + 86400000; // 24 hours from now

      const result = await refreshExpiredToken('valid-token', farFutureExpiry, mockWristbandService);

      expect(result).toBeNull();
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });

    test('should return null when token expires exactly at current time + 1ms', async () => {
      const justFutureExpiry = Date.now() + 1;

      const result = await refreshExpiredToken('valid-token', justFutureExpiry, mockWristbandService);

      expect(result).toBeNull();
      expect(mockWristbandService.refreshToken).not.toHaveBeenCalled();
    });
  });

  describe('Successful Token Refresh', () => {
    test('should refresh token when expired and return new token data', async () => {
      const expiredTime = Date.now() - 1000; // Expired 1 second ago
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('expired-token', expiredTime, mockWristbandService);

      expect(result).not.toBeNull();
      expect(result!.accessToken).toBe('new-access-token');
      expect(result!.idToken).toBe('new-id-token');
      expect(result!.refreshToken).toBe('new-refresh-token');
      expect(result!.expiresIn).toBe(3600);
      expect(result!.expiresAt).toBeGreaterThan(Date.now());
      expect(result!.expiresAt).toBeLessThanOrEqual(Date.now() + 3600 * 1000);

      expect(mockWristbandService.refreshToken).toHaveBeenCalledWith('expired-token');
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('should apply token expiration buffer when provided', async () => {
      const expiredTime = Date.now() - 1000;
      const buffer = 300; // 5 minutes buffer
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('expired-token', expiredTime, mockWristbandService, buffer);

      expect(result).not.toBeNull();
      expect(result!.expiresIn).toBe(3600 - 300); // 3600 - buffer
      expect(result!.expiresAt).toBeLessThanOrEqual(Date.now() + (3600 - 300) * 1000);

      expect(mockWristbandService.refreshToken).toHaveBeenCalledWith('expired-token');
    });

    test('should handle token response without refresh_token', async () => {
      const expiredTime = Date.now() - 1000;
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        // No refresh_token in response
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('expired-token', expiredTime, mockWristbandService);

      expect(result).not.toBeNull();
      expect(result!.accessToken).toBe('new-access-token');
      expect(result!.refreshToken).toBeUndefined();
    });

    test('should handle zero token expiration buffer', async () => {
      const expiredTime = Date.now() - 1000;
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('expired-token', expiredTime, mockWristbandService, 0);

      expect(result).not.toBeNull();
      expect(result!.expiresIn).toBe(3600); // No buffer applied
    });
  });

  describe('Error Handling - InvalidGrantError', () => {
    test('should throw WristbandError with invalid_refresh_token when InvalidGrantError occurs', async () => {
      const expiredTime = Date.now() - 1000;
      const invalidGrantError = new InvalidGrantError('Token is invalid');

      mockWristbandService.refreshToken.mockRejectedValue(invalidGrantError);

      try {
        await refreshExpiredToken('invalid-token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Token is invalid'); // message is the errorDescription
        expect(error.errorDescription).toBe('Token is invalid');
      }

      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('should not retry when InvalidGrantError occurs', async () => {
      const expiredTime = Date.now() - 1000;
      const invalidGrantError = new InvalidGrantError('Refresh token expired');

      mockWristbandService.refreshToken.mockRejectedValue(invalidGrantError);

      await expect(refreshExpiredToken('invalid-token', expiredTime, mockWristbandService)).rejects.toThrow();

      // Should only call once, no retries for InvalidGrantError
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling - FetchError (4xx)', () => {
    test('should throw WristbandError for 400 FetchError', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Bad Request', {
        status: 400,
      } as any);
      // Set the properties that the implementation checks
      (fetchError as any).response = { status: 400 };
      (fetchError as any).body = { error_description: 'Invalid token format' };

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      try {
        await refreshExpiredToken('bad-token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Invalid token format'); // message is errorDescription
        expect(error.errorDescription).toBe('Invalid token format');
      }

      // Should not retry for 4xx errors
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('should throw WristbandError for 401 FetchError', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Unauthorized', {
        status: 401,
      } as any);
      (fetchError as any).response = { status: 401 };
      (fetchError as any).body = { error_description: 'Unauthorized' };

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      await expect(refreshExpiredToken('unauthorized-token', expiredTime, mockWristbandService)).rejects.toThrow(
        WristbandError
      );

      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('should use default error message when error_description is missing', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Bad Request', {
        status: 400,
      } as any);
      (fetchError as any).response = { status: 400 };
      (fetchError as any).body = {}; // No error_description

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      try {
        await refreshExpiredToken('bad-token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Invalid Refresh Token'); // message is errorDescription
        expect(error.errorDescription).toBe('Invalid Refresh Token');
      }
    });

    test('should use default error message when body is missing', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Bad Request', {
        status: 400,
      } as any);
      (fetchError as any).response = { status: 400 };
      // No body property

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      try {
        await refreshExpiredToken('bad-token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Invalid Refresh Token'); // message is errorDescription
        expect(error.errorDescription).toBe('Invalid Refresh Token');
      }
    });

    test('should not retry for 403 FetchError', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Forbidden', {
        status: 403,
      } as any);
      (fetchError as any).response = { status: 403 };
      (fetchError as any).body = { error_description: 'Forbidden' };

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      await expect(refreshExpiredToken('forbidden-token', expiredTime, mockWristbandService)).rejects.toThrow(
        WristbandError
      );

      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });

    test('should not retry for 499 FetchError (last 4xx)', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Client Error', {
        status: 499,
      } as any);
      (fetchError as any).response = { status: 499 };
      (fetchError as any).body = { error_description: 'Client closed request' };

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      await expect(refreshExpiredToken('token', expiredTime, mockWristbandService)).rejects.toThrow(WristbandError);

      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling - Retries (5xx)', () => {
    test('should retry up to 3 times for 500 errors before throwing', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Internal Server Error', {
        status: 500,
      } as any);

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      try {
        await refreshExpiredToken('token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Unexpected Error'); // message is errorDescription
        expect(error.errorDescription).toBe('Unexpected Error');
      }

      // Should have tried 3 times
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });

    test('should succeed on second retry attempt', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Service Unavailable', {
        status: 503,
      } as any);
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken
        .mockRejectedValueOnce(fetchError) // First attempt fails
        .mockResolvedValueOnce(mockTokenResponse); // Second attempt succeeds

      const result = await refreshExpiredToken('token', expiredTime, mockWristbandService);

      expect(result).not.toBeNull();
      expect(result!.accessToken).toBe('new-access-token');
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(2);
    });

    test('should succeed on third retry attempt', async () => {
      const expiredTime = Date.now() - 1000;
      const networkError = new Error('Network timeout');
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken
        .mockRejectedValueOnce(networkError) // First attempt fails
        .mockRejectedValueOnce(networkError) // Second attempt fails
        .mockResolvedValueOnce(mockTokenResponse); // Third attempt succeeds

      const result = await refreshExpiredToken('token', expiredTime, mockWristbandService);

      expect(result).not.toBeNull();
      expect(result!.accessToken).toBe('new-access-token');
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });

    test('should throw unexpected_error after 3 failed attempts', async () => {
      const expiredTime = Date.now() - 1000;
      const networkError = new Error('Connection refused');

      mockWristbandService.refreshToken.mockRejectedValue(networkError);

      try {
        await refreshExpiredToken('token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Unexpected Error'); // message is errorDescription
        expect(error.errorDescription).toBe('Unexpected Error');
      }

      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });

    test('should wait 100ms between retry attempts', async () => {
      const expiredTime = Date.now() - 1000;
      const error = new Error('Temporary failure');

      mockWristbandService.refreshToken.mockRejectedValue(error);

      const startTime = Date.now();

      await expect(refreshExpiredToken('token', expiredTime, mockWristbandService)).rejects.toThrow();

      const endTime = Date.now();
      const elapsed = endTime - startTime;

      // Should have waited ~200ms total (2 delays of 100ms each)
      // Allow some flexibility for test execution time
      expect(elapsed).toBeGreaterThanOrEqual(180);
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });
  });

  describe('Error Handling - FetchError without response', () => {
    test('should retry when FetchError has no response object', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Network error', null as any);

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      await expect(refreshExpiredToken('token', expiredTime, mockWristbandService)).rejects.toThrow(WristbandError);

      // Should retry since there's no response status
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });

    test('should retry when FetchError has response without status', async () => {
      const expiredTime = Date.now() - 1000;
      const fetchError = new FetchError('Network error', {} as any);

      mockWristbandService.refreshToken.mockRejectedValue(fetchError);

      await expect(refreshExpiredToken('token', expiredTime, mockWristbandService)).rejects.toThrow(WristbandError);

      // Should retry since status is undefined
      expect(mockWristbandService.refreshToken).toHaveBeenCalledTimes(3);
    });
  });

  describe('Edge Cases', () => {
    test('should handle token expired by 1 millisecond', async () => {
      const justExpired = Date.now() - 1;
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('token', justExpired, mockWristbandService);

      expect(result).not.toBeNull();
      expect(mockWristbandService.refreshToken).toHaveBeenCalled();
    });

    test('should handle very large expiration buffer', async () => {
      const expiredTime = Date.now() - 1000;
      const largeBuffer = 7200; // 2 hours
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('token', expiredTime, mockWristbandService, largeBuffer);

      expect(result).not.toBeNull();
      // expiresIn would be negative: 3600 - 7200 = -3600
      expect(result!.expiresIn).toBe(3600 - 7200);
    });

    test('should handle extremely long expiry times', async () => {
      const veryOldExpiry = Date.now() - 365 * 24 * 60 * 60 * 1000; // 1 year ago
      const mockTokenResponse = {
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        expires_in: 3600,
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
      };

      mockWristbandService.refreshToken.mockResolvedValue(mockTokenResponse);

      const result = await refreshExpiredToken('token', veryOldExpiry, mockWristbandService);

      expect(result).not.toBeNull();
      expect(result!.accessToken).toBe('new-access-token');
    });

    test('should throw WristbandError if tokenResponse is null after retries', async () => {
      const expiredTime = Date.now() - 1000;

      // Mock a scenario where refreshToken somehow returns null
      mockWristbandService.refreshToken.mockResolvedValue(null as any);

      try {
        await refreshExpiredToken('token', expiredTime, mockWristbandService);
        fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error).toBeInstanceOf(WristbandError);
        expect(error.message).toBe('Unexpected Error'); // message is errorDescription
        expect(error.errorDescription).toBe('Unexpected Error');
      }
    });
  });
});
