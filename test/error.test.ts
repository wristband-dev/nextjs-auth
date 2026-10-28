import { WristbandError, InvalidGrantError, FetchError } from '../src/error';
import { CryptoError } from '../src/error/crypto-error';

describe('Error Classes', () => {
  describe('WristbandError', () => {
    test('Creates error with error code and description', () => {
      const error = new WristbandError('test_error', 'Test error description');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('Test error description');
      expect(error.code).toBe('test_error');
      expect(error.errorDescription).toBe('Test error description');
    });

    test('Creates error with only error code', () => {
      const error = new WristbandError('another_error');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('another_error');
      expect(error.code).toBe('another_error');
      expect(error.errorDescription).toBeUndefined();
    });

    test('Creates error with original error cause', () => {
      const originalError = new Error('Network timeout');
      const error = new WristbandError('network_error', 'Failed to connect', originalError);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error.name).toBe('WristbandError');
      expect(error.message).toBe('Failed to connect');
      expect(error.code).toBe('network_error');
      expect(error.errorDescription).toBe('Failed to connect');
      expect(error.originalError).toBe(originalError);
      expect(error.originalError?.message).toBe('Network timeout');
    });

    test('Creates error with empty string description', () => {
      const error = new WristbandError('empty_desc_error', '');

      expect(error).toBeInstanceOf(WristbandError);
      expect(error.message).toBe('empty_desc_error'); // Falls back to code when description is empty
      expect(error.code).toBe('empty_desc_error');
      expect(error.errorDescription).toBe('');
      expect(error.originalError).toBeUndefined();
    });

    test('Creates error with only code and originalError', () => {
      const originalError = new TypeError('Invalid type');
      const error = new WristbandError('type_error', undefined, originalError);

      expect(error).toBeInstanceOf(WristbandError);
      expect(error.message).toBe('type_error');
      expect(error.code).toBe('type_error');
      expect(error.errorDescription).toBeUndefined();
      expect(error.originalError).toBe(originalError);
    });

    test('Error can be thrown and caught', () => {
      expect(() => {
        throw new WristbandError('thrown_error', 'This error was thrown');
      }).toThrow(WristbandError);
    });

    test('Error has correct prototype chain', () => {
      const error = new WristbandError('proto_test');

      expect(error instanceof WristbandError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });

  describe('InvalidGrantError', () => {
    test('Creates error with description', () => {
      const error = new InvalidGrantError('The grant is invalid');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('The grant is invalid');
      expect(error.message).toBe('The grant is invalid');
    });

    test('Creates error without description', () => {
      const error = new InvalidGrantError();

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('');
      expect(error.message).toBe('invalid_grant'); // Falls back to code
    });

    test('Creates error with empty string description', () => {
      const error = new InvalidGrantError('');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(WristbandError);
      expect(error).toBeInstanceOf(InvalidGrantError);
      expect(error.code).toBe('invalid_grant');
      expect(error.errorDescription).toBe('');
      expect(error.message).toBe('invalid_grant');
    });

    test('Error can be thrown and caught', () => {
      expect(() => {
        throw new InvalidGrantError('Invalid authorization code');
      }).toThrow(InvalidGrantError);
    });

    test('Error has correct prototype chain', () => {
      const error = new InvalidGrantError('test');

      expect(error instanceof InvalidGrantError).toBe(true);
      expect(error instanceof WristbandError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    test('Error always has invalid_grant as error code', () => {
      const error1 = new InvalidGrantError('First error');
      const error2 = new InvalidGrantError('Second error');
      const error3 = new InvalidGrantError();

      expect(error1.code).toBe('invalid_grant');
      expect(error2.code).toBe('invalid_grant');
      expect(error3.code).toBe('invalid_grant');
    });

    test('InvalidGrantError does not support originalError', () => {
      const error = new InvalidGrantError('Test');
      expect(error.originalError).toBeUndefined();
    });

    test('Error has correct name property', () => {
      const error = new InvalidGrantError('Test');
      expect(error.name).toBe('WristbandError'); // Inherits from WristbandError
    });
  });

  describe('FetchError', () => {
    test('Creates error with response and body', () => {
      const mockResponse = new Response(null, { status: 400 });
      const body = { error: 'invalid_grant', error_description: 'Invalid grant' };
      const error = new FetchError(mockResponse, body);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(FetchError);
      expect(error.name).toBe('FetchError');
      expect(error.message).toBe('Fetch Error');
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBe(body);
    });

    test('Creates error with undefined body', () => {
      const mockResponse = new Response(null, { status: 204 });
      const error = new FetchError(mockResponse, undefined);

      expect(error).toBeInstanceOf(FetchError);
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBeUndefined();
    });

    test('Creates error with null body', () => {
      const mockResponse = new Response(null, { status: 500 });
      const error = new FetchError(mockResponse, null);

      expect(error).toBeInstanceOf(FetchError);
      expect(error.response).toBe(mockResponse);
      expect(error.body).toBeNull();
    });

    test('Creates error with string body', () => {
      const mockResponse = new Response(null, { status: 503 });
      const error = new FetchError(mockResponse, 'Service Unavailable');

      expect(error).toBeInstanceOf(FetchError);
      expect(error.body).toBe('Service Unavailable');
    });

    test('Response and body properties are readonly', () => {
      const mockResponse = new Response(null, { status: 400 });
      const error = new FetchError(mockResponse, { error: 'bad_request' });

      // TypeScript readonly enforced at compile time; verify values are stable at runtime
      expect(error.response).toBe(mockResponse);
      expect(error.body).toEqual({ error: 'bad_request' });
    });

    test('Works with generic response type', () => {
      interface MockResponse {
        status: number;
        ok: boolean;
      }
      const mockResponse: MockResponse = { status: 401, ok: false };
      const error = new FetchError<MockResponse>(mockResponse, { error: 'unauthorized' });

      expect(error.response?.status).toBe(401);
      expect(error.response?.ok).toBe(false);
    });

    test('Error can be thrown and caught', () => {
      const mockResponse = new Response(null, { status: 400 });
      expect(() => {
        throw new FetchError(mockResponse, { error: 'bad_request' });
      }).toThrow(FetchError);
    });

    test('Error has correct prototype chain', () => {
      const mockResponse = new Response(null, { status: 400 });
      const error = new FetchError(mockResponse, null);

      expect(error instanceof FetchError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    test('instanceof check works for downstream error handling', () => {
      const mockResponse = new Response(null, { status: 400 });
      const fetchError = new FetchError(mockResponse, { error: 'invalid_grant' });
      const regularError = new Error('regular error');

      expect(fetchError instanceof FetchError).toBe(true);
      expect(regularError instanceof FetchError).toBe(false);
    });

    test('Body with invalid_grant error is accessible', () => {
      const mockResponse = new Response(null, { status: 400 });
      const body = { error: 'invalid_grant', error_description: 'The authorization code has expired' };
      const error = new FetchError(mockResponse, body);
      const errorBody = error.body as { error: string; error_description: string };

      expect(error.body).toBeDefined();
      expect(errorBody.error).toBe('invalid_grant');
      expect(errorBody.error_description).toBe('The authorization code has expired');
    });

    test('Response status is accessible via response property', () => {
      const mockResponse = new Response(null, { status: 401 });
      const error = new FetchError(mockResponse, { error: 'unauthorized' });

      expect(error.response?.status).toBe(401);
    });
  });

  describe('CryptoError', () => {
    test('Creates error with code and message', () => {
      const error = new CryptoError('DECRYPTION_FAILED', 'Decryption failed');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(CryptoError);
      expect(error.name).toBe('CryptoError');
      expect(error.code).toBe('DECRYPTION_FAILED');
      expect(error.message).toBe('Decryption failed');
    });

    test('Uses code as message when message not provided', () => {
      const error = new CryptoError('INVALID_SECRET');

      expect(error.message).toBe('INVALID_SECRET');
    });

    test('Creates error without cause', () => {
      const error = new CryptoError('ENCRYPTION_FAILED', 'Encryption failed');

      expect(error.cause).toBeUndefined();
    });

    test('Creates error with Error cause', () => {
      const cause = new Error('Underlying error');
      const error = new CryptoError('DECRYPTION_FAILED', 'Decryption failed', cause);

      expect(error.cause).toBe(cause);
      expect(error.cause?.message).toBe('Underlying error');
    });

    test('Preserves stack trace', () => {
      const error = new CryptoError('EXPIRED', 'Cookie has expired');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('CryptoError');
    });

    test('Supports every error code', () => {
      const codes = [
        'INVALID_SECRET',
        'INVALID_SECRETS_LIST',
        'INVALID_MAX_AGE',
        'DATA_TOO_LARGE',
        'MALFORMED_DATA',
        'UNSUPPORTED_VERSION',
        'EXPIRED',
        'AUTH_FAILED',
        'DECRYPTION_FAILED',
        'ENCRYPTION_FAILED',
        'NODE_CRYPTO_UNAVAILABLE',
      ] as const;

      codes.forEach((code) => {
        const error = new CryptoError(code, 'Test message');
        expect(error.code).toBe(code);
      });
    });

    test('Preserves Error subclass cause as-is', () => {
      const cause = new TypeError('Type error');
      const error = new CryptoError('DECRYPTION_FAILED', 'Failed', cause);

      expect(error.cause).toBe(cause);
      expect(error.cause).toBeInstanceOf(TypeError);
    });

    test('Wraps string cause in Error', () => {
      const error = new CryptoError('AUTH_FAILED', 'Auth failed', 'Invalid signature');

      expect(error.cause).toBeInstanceOf(Error);
      expect(error.cause?.message).toBe('Invalid signature');
    });

    test('Wraps number cause in Error', () => {
      const error = new CryptoError('DECRYPTION_FAILED', 'Failed', 404);

      expect(error.cause).toBeInstanceOf(Error);
      expect(error.cause?.message).toBe('404');
    });

    test('Wraps object cause in Error', () => {
      const error = new CryptoError('ENCRYPTION_FAILED', 'Failed', { detail: 'Some detail' });

      expect(error.cause).toBeInstanceOf(Error);
      expect(error.cause?.message).toContain('object');
    });

    test('Ignores null cause', () => {
      const error = new CryptoError('EXPIRED', 'Expired', null);

      expect(error.cause).toBeUndefined();
    });

    test('Ignores undefined cause', () => {
      const error = new CryptoError('EXPIRED', 'Expired', undefined);

      expect(error.cause).toBeUndefined();
    });

    test('Error can be thrown and caught', () => {
      expect(() => {
        throw new CryptoError('AUTH_FAILED', 'Failed to decrypt data');
      }).toThrow(CryptoError);
    });

    test('Error has correct prototype chain', () => {
      const error = new CryptoError('DECRYPTION_FAILED', 'Failed');

      expect(error instanceof CryptoError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    test('Error is not a WristbandError', () => {
      const error = new CryptoError('DECRYPTION_FAILED', 'Failed');

      expect(error instanceof WristbandError).toBe(false);
    });

    test('Creates error when Error.captureStackTrace is unavailable (non-V8 engines)', () => {
      const originalCaptureStackTrace = Error.captureStackTrace;
      // Simulate a non-V8 engine where Error.captureStackTrace does not exist
      (Error as any).captureStackTrace = undefined;

      try {
        const error = new CryptoError('EXPIRED', 'Cookie has expired');

        expect(error).toBeInstanceOf(CryptoError);
        expect(error.code).toBe('EXPIRED');
        expect(error.message).toBe('Cookie has expired');
      } finally {
        Error.captureStackTrace = originalCaptureStackTrace;
      }
    });
  });
});
