import { CookieCrypto } from '../../../src/utils/crypto';
import { CryptoError } from '../../../src/error/crypto-error';
import { LoginState } from '../../../src/types';

describe('CookieCrypto - Async Methods', () => {
  const validSecret = 'a'.repeat(32);
  const alternateSecret = 'b'.repeat(32);

  const baseLoginState: LoginState = {
    codeVerifier: 'code-verifier-123',
    redirectUri: 'https://app.example.com/auth/callback',
    state: 'state-123',
  };

  describe('encrypt()', () => {
    it('should encrypt empty data', async () => {
      const encrypted = await CookieCrypto.encrypt({} as LoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('should encrypt login state with required properties', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should encrypt login state with all properties', async () => {
      const loginState: LoginState = {
        ...baseLoginState,
        returnUrl: 'https://app.example.com/settings',
        customState: { flow: 'signup' },
      };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should produce different outputs for same data (random IV)', async () => {
      const encrypted1 = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const encrypted2 = await CookieCrypto.encrypt(baseLoginState, validSecret);
      // Different IVs mean different ciphertexts
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should produce different outputs for different secrets', async () => {
      const encrypted1 = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const encrypted2 = await CookieCrypto.encrypt(baseLoginState, alternateSecret);
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should handle string values', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { name: 'Test User' } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle number values', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { expiresAt: 1234567890 } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle boolean values', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { isNewUser: true } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle nested objects', async () => {
      const loginState: LoginState = {
        ...baseLoginState,
        customState: { metadata: { theme: 'dark', language: 'en' } },
      };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle arrays', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { roles: ['admin', 'editor', 'viewer'] } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle null values', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { optionalField: null } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle special characters in strings', async () => {
      const loginState: LoginState = {
        ...baseLoginState,
        customState: { name: 'Test with special chars: !@#$%^&*()_+-={}[]|\\:";\'<>?,./' },
      };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle unicode characters', async () => {
      const loginState: LoginState = { ...baseLoginState, customState: { name: '日本語 中文 한글 العربية 🎉' } };
      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should produce base64url-encoded output', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      // Base64url only contains A-Z, a-z, 0-9, -, _ (no padding)
      expect(encrypted).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should throw DATA_TOO_LARGE for very large data', async () => {
      // Create data that will exceed 4KB when encrypted
      const largeData: LoginState = { ...baseLoginState, customState: { largeField: 'x'.repeat(5000) } };

      await expect(CookieCrypto.encrypt(largeData, validSecret)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.encrypt(largeData, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DATA_TOO_LARGE');
      }
    });

    it('should throw DATA_TOO_LARGE when data is under 4KB but the encrypted value exceeds 4KB', async () => {
      // About 3.2KB of JSON passes the 4KB raw data check, but encrypting and base64url-encoding it
      // adds roughly a third in size, pushing the encrypted value past the 4KB cookie limit.
      const data: LoginState = { ...baseLoginState, customState: { largeField: 'x'.repeat(3100) } };

      await expect(CookieCrypto.encrypt(data, validSecret)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.encrypt(data, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DATA_TOO_LARGE');
        expect((error as CryptoError).message).toContain('Encrypted data exceeds 4KB cookie limit');
      }
    });

    it('should accept moderately large data under 4KB', async () => {
      // Create data that's large but under the limit
      const moderateData: LoginState = { ...baseLoginState, customState: { data: 'x'.repeat(2000) } };
      const encrypted = await CookieCrypto.encrypt(moderateData, validSecret);
      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeLessThan(4096);
    });

    it('should throw ENCRYPTION_FAILED for non-JSON-serializable data (BigInt)', async () => {
      const dataWithBigInt: any = {
        ...baseLoginState,
        bigNumber: BigInt(12345), // BigInt is not JSON-serializable
      };

      await expect(CookieCrypto.encrypt(dataWithBigInt, validSecret)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.encrypt(dataWithBigInt, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toContain('JSON-serializable');
      }
    });
  });

  describe('decrypt()', () => {
    it('should decrypt valid encrypted data', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt login state with all properties', async () => {
      const original: LoginState = {
        ...baseLoginState,
        returnUrl: 'https://app.example.com/settings',
        customState: { flow: 'signup' },
      };
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should throw AUTH_FAILED for wrong secret', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

      await expect(CookieCrypto.decrypt(encrypted, alternateSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(encrypted, alternateSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw AUTH_FAILED for tampered data', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

      // Tamper with the end of the data (likely the auth tag or encrypted payload)
      const tampered = `${encrypted.slice(0, -5)}XXXXX`;

      await expect(CookieCrypto.decrypt(tampered, validSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(tampered, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw AUTH_FAILED for invalid base64url', async () => {
      const invalidBase64 = '!!!invalid!!!';

      await expect(CookieCrypto.decrypt(invalidBase64, validSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(invalidBase64, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw MALFORMED_DATA for truncated data', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      // Truncate the encrypted data
      const truncated = encrypted.substring(0, 30);

      await expect(CookieCrypto.decrypt(truncated, validSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(truncated, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('MALFORMED_DATA');
      }
    });

    it('should throw DATA_TOO_LARGE for cookie exceeding 4KB', async () => {
      // Create a fake encrypted value that's too large
      const tooLarge = 'A'.repeat(50000);

      await expect(CookieCrypto.decrypt(tooLarge, validSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(tooLarge, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DATA_TOO_LARGE');
      }
    });

    it('should throw EXPIRED for expired data', async () => {
      // Save original skew value
      const CookieCryptoClass = CookieCrypto as any;
      const originalSkew = CookieCryptoClass.TIMESTAMP_SKEW_MS;
      // Temporarily reduce skew tolerance to 0 for testing
      CookieCryptoClass.TIMESTAMP_SKEW_MS = 0;

      try {
        const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

        // Wait 100ms with maxAge of 50ms (0.05 seconds)
        await new Promise((resolve) => {
          setTimeout(resolve, 100);
        });

        await expect(CookieCrypto.decrypt(encrypted, validSecret, 0.05)).rejects.toThrow(CryptoError);

        try {
          await CookieCrypto.decrypt(encrypted, validSecret, 0.05);
        } catch (error) {
          expect((error as CryptoError).code).toBe('EXPIRED');
        }
      } finally {
        // Restore original skew value
        CookieCryptoClass.TIMESTAMP_SKEW_MS = originalSkew;
      }
    });

    it('should accept data within maxAge', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

      // Decrypt immediately with generous maxAge
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should include 60-second clock skew tolerance', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

      // Wait 1 second with maxAge of 1 second
      // Should still work due to 60-second skew tolerance
      await new Promise((resolve) => {
        setTimeout(resolve, 1100);
      });
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 1);
      expect(decrypted).toEqual(baseLoginState);
    });
  });

  describe('roundtrip integrity', () => {
    it('should roundtrip empty object', async () => {
      const original = {} as LoginState;
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should roundtrip complex nested data', async () => {
      const original: LoginState = {
        ...baseLoginState,
        customState: {
          metadata: {
            preferences: {
              theme: 'dark',
              notifications: true,
            },
            tags: ['admin', 'premium'],
          },
          loginHistory: [
            { timestamp: 1234567890, ip: '192.168.1.1' },
            { timestamp: 1234567900, ip: '192.168.1.2' },
          ],
        },
      };
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should preserve data types', async () => {
      const original: LoginState = {
        ...baseLoginState,
        customState: {
          stringField: 'test',
          numberField: 42,
          booleanField: true,
          nullField: null,
          arrayField: [1, 2, 3],
          objectField: { nested: 'value' },
        },
      };

      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted: any = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
      expect(typeof decrypted.customState.stringField).toBe('string');
      expect(typeof decrypted.customState.numberField).toBe('number');
      expect(typeof decrypted.customState.booleanField).toBe('boolean');
      expect(decrypted.customState.nullField).toBeNull();
      expect(Array.isArray(decrypted.customState.arrayField)).toBe(true);
      expect(typeof decrypted.customState.objectField).toBe('object');
    });

    it('should preserve unicode characters', async () => {
      const original: LoginState = { ...baseLoginState, customState: { name: '日本語 中文 한글 العربية 🎉🚀' } };
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
      expect(decrypted.customState?.name).toBe('日本語 中文 한글 العربية 🎉🚀');
    });

    it('should preserve special characters', async () => {
      const original: LoginState = { ...baseLoginState, customState: { name: '!@#$%^&*()_+-={}[]|\\:";\'<>?,./' } };
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });
  });

  describe('decryptWithSecrets()', () => {
    it('should decrypt with first secret', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const decrypted = await CookieCrypto.decryptWithSecrets(encrypted, [validSecret, alternateSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt with second secret when first fails', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const decrypted = await CookieCrypto.decryptWithSecrets(
        encrypted,
        [alternateSecret, validSecret], // validSecret is second
        3600
      );
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt with third secret when first two fail', async () => {
      const thirdSecret = 'c'.repeat(32);
      const encrypted = await CookieCrypto.encrypt(baseLoginState, thirdSecret);
      const decrypted = await CookieCrypto.decryptWithSecrets(
        encrypted,
        [validSecret, alternateSecret, thirdSecret], // thirdSecret is last
        3600
      );
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should throw DECRYPTION_FAILED when all secrets fail', async () => {
      const wrongSecret = 'z'.repeat(32);
      const encrypted = await CookieCrypto.encrypt(baseLoginState, wrongSecret);

      await expect(CookieCrypto.decryptWithSecrets(encrypted, [validSecret, alternateSecret], 3600)).rejects.toThrow(
        CryptoError
      );

      try {
        await CookieCrypto.decryptWithSecrets(encrypted, [validSecret, alternateSecret], 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DECRYPTION_FAILED');
      }
    });

    it('should work with single secret in array', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const decrypted = await CookieCrypto.decryptWithSecrets(encrypted, [validSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should try secrets in order (performance)', async () => {
      // This is more of a documentation test - order matters for performance
      const encrypted = await CookieCrypto.encrypt(baseLoginState, alternateSecret);

      // Should succeed faster if correct secret is first
      const decrypted = await CookieCrypto.decryptWithSecrets(
        encrypted,
        [alternateSecret, validSecret], // Correct secret first
        3600
      );
      expect(decrypted).toEqual(baseLoginState);
    });
  });

  describe('binary format validation', () => {
    it('should have minimum size of 39 bytes', async () => {
      // Even empty data should have: version(1) + timestamp(8) + iv(12) + tag(16) + data(2 for "{}")
      const encrypted = await CookieCrypto.encrypt({} as LoginState, validSecret);
      // Base64url encoding increases size, but binary should be at least 39
      expect(encrypted.length).toBeGreaterThanOrEqual(39);
    });

    it('should throw UNSUPPORTED_VERSION for wrong version', async () => {
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);

      // Decode, change version byte, re-encode
      const bytes = Buffer.from(encrypted, 'base64url');
      bytes[0] = 99; // Invalid version
      const modifiedEncrypted = bytes.toString('base64url');

      await expect(CookieCrypto.decrypt(modifiedEncrypted, validSecret, 3600)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.decrypt(modifiedEncrypted, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('UNSUPPORTED_VERSION');
        expect((error as CryptoError).message).toContain('99');
      }
    });
  });

  describe('Web Crypto error handling', () => {
    it('should throw ENCRYPTION_FAILED when key derivation fails', async () => {
      expect.assertions(3);
      const originalSubtle = globalThis.crypto.subtle;
      const mockSubtle = {
        ...originalSubtle,
        deriveKey: jest.fn().mockRejectedValue(new Error('Algorithm not supported')),
      };

      Object.defineProperty(globalThis.crypto, 'subtle', {
        value: mockSubtle,
        writable: true,
        configurable: true,
      });

      try {
        await CookieCrypto.encrypt(baseLoginState, validSecret);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toContain('derive encryption key');
      } finally {
        Object.defineProperty(globalThis.crypto, 'subtle', {
          value: originalSubtle,
          writable: true,
          configurable: true,
        });
      }
    });

    it('should throw ENCRYPTION_FAILED when Web Crypto encrypt fails', async () => {
      expect.assertions(3);
      const originalSubtle = globalThis.crypto.subtle;
      const mockSubtle = {
        ...originalSubtle,
        importKey: originalSubtle.importKey.bind(originalSubtle),
        deriveKey: originalSubtle.deriveKey.bind(originalSubtle),
        encrypt: jest.fn().mockRejectedValue(new Error('Encryption operation failed')),
      };

      Object.defineProperty(globalThis.crypto, 'subtle', {
        value: mockSubtle,
        writable: true,
        configurable: true,
      });

      try {
        await CookieCrypto.encrypt(baseLoginState, validSecret);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toBe('Failed to encrypt data');
      } finally {
        Object.defineProperty(globalThis.crypto, 'subtle', {
          value: originalSubtle,
          writable: true,
          configurable: true,
        });
      }
    });
  });
});
