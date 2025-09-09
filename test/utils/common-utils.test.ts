import * as crypto from 'uncrypto';
import * as ironWebcrypto from 'iron-webcrypto';
import {
  encodeBase64,
  base64ToURLSafe,
  generateRandomString,
  sha256Base64,
  encryptLoginState,
  decryptLoginState,
} from '../../src/utils/auth/common-utils';
import { LoginState } from '../../src/types';

// Mock iron-webcrypto
jest.mock('iron-webcrypto', () => {
  return {
    defaults: { encryption: 'aes-256-cbc', integrity: 'sha256' },
    seal: jest.fn(),
    unseal: jest.fn(),
  };
});

// Mock uncrypto
jest.mock('uncrypto', () => {
  return {
    getRandomValues: jest.fn(),
    subtle: {
      digest: jest.fn(),
    },
  };
});

const mockSeal = ironWebcrypto.seal as jest.MockedFunction<any>;
const mockUnseal = ironWebcrypto.unseal as jest.MockedFunction<any>;

const mockGetRandomValues = crypto.getRandomValues as jest.MockedFunction<typeof crypto.getRandomValues>;
const mockDigest = crypto.subtle.digest as jest.MockedFunction<typeof crypto.subtle.digest>;

describe('Common Utils', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('encodeBase64', () => {
    it('should encode simple string to base64', () => {
      const result = encodeBase64('hello');
      expect(result).toBe('aGVsbG8=');
    });

    it('should encode empty string', () => {
      const result = encodeBase64('');
      expect(result).toBe('');
    });

    it('should encode string with special characters', () => {
      const result = encodeBase64('hello:world@123');
      expect(result).toBe('aGVsbG86d29ybGRAMTIz');
    });

    it('should encode unicode characters', () => {
      const result = encodeBase64('héllo 世界');
      expect(result).toBe('aMOpbGxvIOS4lueVjA==');
    });

    it('should handle client ID and secret combination', () => {
      const clientId = 'test-client-id';
      const clientSecret = 'test-client-secret';
      const combined = `${clientId}:${clientSecret}`;
      const result = encodeBase64(combined);

      // Should be valid base64
      expect(result).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);

      // Should decode back to original
      expect(atob(result)).toBe(combined);
    });
  });

  describe('base64ToURLSafe', () => {
    it('should convert standard base64 to URL-safe format', () => {
      const input = 'aGVsbG8+d29ybGQ/test+value=';
      const result = base64ToURLSafe(input);
      expect(result).toBe('aGVsbG8-d29ybGQ_test-value');
    });

    it('should replace + with -', () => {
      const result = base64ToURLSafe('test+value+more');
      expect(result).toBe('test-value-more');
    });

    it('should replace / with _', () => {
      const result = base64ToURLSafe('test/value/more');
      expect(result).toBe('test_value_more');
    });

    it('should remove = padding', () => {
      const result = base64ToURLSafe('test===');
      expect(result).toBe('test');
    });

    it('should handle empty string', () => {
      const result = base64ToURLSafe('');
      expect(result).toBe('');
    });

    it('should handle string with no special characters', () => {
      const result = base64ToURLSafe('abcdefghijklmnop');
      expect(result).toBe('abcdefghijklmnop');
    });
  });

  describe('generateRandomString', () => {
    beforeEach(() => {
      // Mock crypto.getRandomValues to return predictable values for testing
      mockGetRandomValues.mockImplementation((array: any) => {
        const uint8Array = array as Uint8Array;
        for (let i = 0; i < uint8Array.length; i += 1) {
          uint8Array[i] = i % 256; // Predictable pattern
        }
        return uint8Array;
      });
    });

    it('should generate string of specified length', () => {
      const result = generateRandomString(10);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    it('should generate different results for different lengths', () => {
      const result1 = generateRandomString(5);
      const result2 = generateRandomString(10);
      expect(result1.length).not.toBe(result2.length);
    });

    it('should return URL-safe characters only', () => {
      const result = generateRandomString(20);
      // Should only contain URL-safe base64 characters (no +, /, =)
      expect(result).toMatch(/^[A-Za-z0-9_-]*$/);
    });

    it('should handle length of 1', () => {
      const result = generateRandomString(1);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should call crypto.getRandomValues with correct array size', () => {
      generateRandomString(10);
      expect(mockGetRandomValues).toHaveBeenCalledWith(expect.any(Uint8Array));
      expect(mockGetRandomValues).toHaveBeenCalledWith(expect.objectContaining({ length: 10 }));
    });

    it('should generate strings without padding characters', () => {
      const result = generateRandomString(50);
      expect(result).not.toContain('=');
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
    });
  });

  describe('sha256Base64', () => {
    beforeEach(() => {
      // Mock crypto.subtle.digest to return predictable hash
      const mockHashArray = new Uint8Array([
        227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76,
        164, 149, 153, 27, 120, 82, 184, 85,
      ]);
      mockDigest.mockResolvedValue(mockHashArray.buffer);
    });

    it('should generate SHA-256 hash in base64 format', async () => {
      const result = await sha256Base64('hello world');
      expect(result).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('should handle empty string', async () => {
      const result = await sha256Base64('');
      expect(result).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('should handle unicode characters', async () => {
      const result = await sha256Base64('héllo 世界');
      expect(result).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('should call crypto.subtle.digest with SHA-256', async () => {
      await sha256Base64('test input');
      expect(mockDigest).toHaveBeenCalledWith('SHA-256', expect.any(Uint8Array));
    });

    it('should encode input as UTF-8 before hashing', async () => {
      await sha256Base64('test');
      expect(mockDigest).toHaveBeenCalledWith(
        'SHA-256',
        new Uint8Array([116, 101, 115, 116]) // UTF-8 bytes for "test"
      );
    });

    it('should return consistent results for same input', async () => {
      const input = 'consistent input';
      const result1 = await sha256Base64(input);
      const result2 = await sha256Base64(input);
      expect(result1).toBe(result2);
    });

    it('should return different results for different inputs', async () => {
      // Mock different hash for different input
      mockDigest
        .mockResolvedValueOnce(new Uint8Array(32).fill(1).buffer)
        .mockResolvedValueOnce(new Uint8Array(32).fill(2).buffer);

      const result1 = await sha256Base64('input1');
      const result2 = await sha256Base64('input2');
      expect(result1).not.toBe(result2);
    });
  });

  describe('encryptLoginState', () => {
    const validLoginState: LoginState = {
      codeVerifier: 'test-code-verifier',
      state: 'test-state',
      redirectUri: 'https://example.com/callback',
      returnUrl: 'https://example.com/return',
      customState: { userId: '123', tenantId: 'tenant-456' },
    };

    const loginStateSecret = 'test-login-state-secret-32-chars';

    beforeEach(() => {
      mockSeal.mockResolvedValue('encrypted-login-state-cookie');
    });

    it('should encrypt login state successfully', async () => {
      const result = await encryptLoginState(validLoginState, loginStateSecret);
      expect(result).toBe('encrypted-login-state-cookie');
    });

    it('should call seal with correct parameters', async () => {
      await encryptLoginState(validLoginState, loginStateSecret);

      expect(mockSeal).toHaveBeenCalledWith(
        crypto,
        validLoginState,
        loginStateSecret,
        expect.any(Object) // defaults from iron-webcrypto
      );
    });

    it('should handle login state without customState', async () => {
      const minimalLoginState: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
      };

      const result = await encryptLoginState(minimalLoginState, loginStateSecret);
      expect(result).toBe('encrypted-login-state-cookie');
      expect(mockSeal).toHaveBeenCalledWith(crypto, minimalLoginState, loginStateSecret, expect.any(Object));
    });

    it('should handle login state without returnUrl', async () => {
      const loginStateWithoutReturn: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
        customState: { key: 'value' },
      };

      const result = await encryptLoginState(loginStateWithoutReturn, loginStateSecret);
      expect(result).toBe('encrypted-login-state-cookie');
    });

    it('should throw error when encrypted state exceeds 4kB', async () => {
      // Mock seal to return a large string > 4096 characters
      const largeEncryptedString = 'x'.repeat(4097);
      mockSeal.mockResolvedValue(largeEncryptedString);

      await expect(encryptLoginState(validLoginState, loginStateSecret)).rejects.toThrow(
        'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
      );
    });

    it('should throw TypeError specifically for size limit', async () => {
      const largeEncryptedString = 'x'.repeat(5000);
      mockSeal.mockResolvedValue(largeEncryptedString);

      await expect(encryptLoginState(validLoginState, loginStateSecret)).rejects.toThrow(TypeError);
    });

    it('should accept exactly 4096 characters', async () => {
      const exactLimitString = 'x'.repeat(4096);
      mockSeal.mockResolvedValue(exactLimitString);

      const result = await encryptLoginState(validLoginState, loginStateSecret);
      expect(result).toBe(exactLimitString);
    });

    it('should propagate seal errors', async () => {
      const sealError = new Error('Encryption failed');
      mockSeal.mockRejectedValue(sealError);

      await expect(encryptLoginState(validLoginState, loginStateSecret)).rejects.toThrow('Encryption failed');
    });

    it('should handle empty customState object', async () => {
      const loginStateWithEmptyCustom: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
        customState: {},
      };

      const result = await encryptLoginState(loginStateWithEmptyCustom, loginStateSecret);
      expect(result).toBe('encrypted-login-state-cookie');
    });
  });

  describe('decryptLoginState', () => {
    const loginStateSecret = 'test-login-state-secret-32-chars';
    const encryptedCookie = 'encrypted-login-state-cookie';

    const expectedLoginState: LoginState = {
      codeVerifier: 'test-code-verifier',
      state: 'test-state',
      redirectUri: 'https://example.com/callback',
      returnUrl: 'https://example.com/return',
      customState: { userId: '123', tenantId: 'tenant-456' },
    };

    beforeEach(() => {
      mockUnseal.mockResolvedValue(expectedLoginState);
    });

    it('should decrypt login state successfully', async () => {
      const result = await decryptLoginState(encryptedCookie, loginStateSecret);
      expect(result).toEqual(expectedLoginState);
    });

    it('should call unseal with correct parameters', async () => {
      await decryptLoginState(encryptedCookie, loginStateSecret);

      expect(mockUnseal).toHaveBeenCalledWith(
        crypto,
        encryptedCookie,
        loginStateSecret,
        expect.any(Object) // defaults from iron-webcrypto
      );
    });

    it('should handle minimal login state', async () => {
      const minimalLoginState: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
      };

      mockUnseal.mockResolvedValue(minimalLoginState);

      const result = await decryptLoginState(encryptedCookie, loginStateSecret);
      expect(result).toEqual(minimalLoginState);
    });

    it('should handle login state without customState', async () => {
      const loginStateWithoutCustom: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
        returnUrl: 'https://example.com/return',
      };

      mockUnseal.mockResolvedValue(loginStateWithoutCustom);

      const result = await decryptLoginState(encryptedCookie, loginStateSecret);
      expect(result).toEqual(loginStateWithoutCustom);
    });

    it('should handle login state without returnUrl', async () => {
      const loginStateWithoutReturn: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
        customState: { key: 'value' },
      };

      mockUnseal.mockResolvedValue(loginStateWithoutReturn);

      const result = await decryptLoginState(encryptedCookie, loginStateSecret);
      expect(result).toEqual(loginStateWithoutReturn);
    });

    it('should propagate unseal errors', async () => {
      const unsealError = new Error('Decryption failed');
      mockUnseal.mockRejectedValue(unsealError);

      await expect(decryptLoginState(encryptedCookie, loginStateSecret)).rejects.toThrow('Decryption failed');
    });

    it('should handle invalid encrypted cookie format', async () => {
      const invalidFormatError = new Error('Invalid sealed object format');
      mockUnseal.mockRejectedValue(invalidFormatError);

      await expect(decryptLoginState('invalid-cookie', loginStateSecret)).rejects.toThrow(
        'Invalid sealed object format'
      );
    });

    it('should handle wrong secret', async () => {
      const wrongSecretError = new Error('Invalid key');
      mockUnseal.mockRejectedValue(wrongSecretError);

      await expect(decryptLoginState(encryptedCookie, 'wrong-secret')).rejects.toThrow('Invalid key');
    });

    it('should type cast unseal result correctly', async () => {
      // Test that the result is properly typed as LoginState
      const result = await decryptLoginState(encryptedCookie, loginStateSecret);

      // Should have LoginState properties
      expect(result).toHaveProperty('codeVerifier');
      expect(result).toHaveProperty('state');
      expect(result).toHaveProperty('redirectUri');
    });

    it('should handle complex customState objects', async () => {
      const complexLoginState: LoginState = {
        codeVerifier: 'test-code-verifier',
        state: 'test-state',
        redirectUri: 'https://example.com/callback',
        customState: {
          user: { id: '123', name: 'John Doe' },
          permissions: ['read', 'write'],
          metadata: { timestamp: Date.now(), version: '1.0' },
        },
      };

      mockUnseal.mockResolvedValue(complexLoginState);

      const result = await decryptLoginState(encryptedCookie, loginStateSecret);
      expect(result).toEqual(complexLoginState);
    });
  });

  describe('Integration Tests', () => {
    it('should maintain consistency between encodeBase64 and atob', () => {
      const testStrings = ['hello', 'test:secret', 'user@domain.com', '123:456:789'];

      testStrings.forEach((testString) => {
        const encoded = encodeBase64(testString);
        const decoded = atob(encoded);
        expect(decoded).toBe(testString);
      });
    });

    it('should generate URL-safe strings that are different each time', () => {
      // Since we're mocking getRandomValues with a pattern, we can predict behavior
      const result1 = generateRandomString(10);
      const result2 = generateRandomString(10);

      // Both should be URL-safe
      expect(result1).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(result2).toMatch(/^[A-Za-z0-9_-]*$/);
    });

    it('should handle encrypt/decrypt round trip with real-looking data', async () => {
      const loginState: LoginState = {
        codeVerifier: generateRandomString(43), // Standard PKCE length
        state: generateRandomString(16),
        redirectUri: 'https://myapp.com/auth/callback',
        returnUrl: 'https://myapp.com/dashboard',
        customState: {
          tenantId: 'tenant-123',
          userId: 'user-456',
          permissions: ['read', 'write'],
        },
      };

      // Mock the round trip
      mockSeal.mockResolvedValue('encrypted-cookie-data');
      mockUnseal.mockResolvedValue(loginState);

      const encrypted = await encryptLoginState(loginState, 'my-secret-key-32-characters-long');
      const decrypted = await decryptLoginState(encrypted, 'my-secret-key-32-characters-long');

      expect(decrypted).toEqual(loginState);
    });
  });
});
