import { CookieCrypto } from '../../../src/utils/crypto';
import { CryptoError } from '../../../src/error/crypto-error';
import { LoginState } from '../../../src/types';

describe('CookieCrypto - Sync Methods', () => {
  const validSecret = 'a'.repeat(32);
  const alternateSecret = 'b'.repeat(32);

  const baseLoginState: LoginState = {
    codeVerifier: 'code-verifier-123',
    redirectUri: 'https://app.example.com/auth/callback',
    state: 'state-123',
  };

  describe('encryptSync()', () => {
    it('should encrypt empty data', () => {
      const encrypted = CookieCrypto.encryptSync({} as LoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('should encrypt login state with required properties', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should encrypt login state with all properties', () => {
      const loginState: LoginState = {
        ...baseLoginState,
        returnUrl: 'https://app.example.com/settings',
        customState: { flow: 'signup' },
      };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should produce different outputs for same data (random IV)', () => {
      const encrypted1 = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const encrypted2 = CookieCrypto.encryptSync(baseLoginState, validSecret);
      // Different IVs mean different ciphertexts
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should produce different outputs for different secrets', () => {
      const encrypted1 = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const encrypted2 = CookieCrypto.encryptSync(baseLoginState, alternateSecret);
      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should handle string values', () => {
      const loginState: LoginState = { ...baseLoginState, customState: { name: 'Test User' } };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle number values', () => {
      const loginState: LoginState = { ...baseLoginState, customState: { expiresAt: 1234567890 } };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle boolean values', () => {
      const loginState: LoginState = { ...baseLoginState, customState: { isNewUser: true } };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle nested objects', () => {
      const loginState: LoginState = {
        ...baseLoginState,
        customState: { metadata: { theme: 'dark', language: 'en' } },
      };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle arrays', () => {
      const loginState: LoginState = { ...baseLoginState, customState: { roles: ['admin', 'editor', 'viewer'] } };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle special characters', () => {
      const loginState: LoginState = {
        ...baseLoginState,
        customState: { name: 'Test with special chars: !@#$%^&*()_+-={}[]|\\:";\'<>?,./' },
      };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should handle unicode characters', () => {
      const loginState: LoginState = { ...baseLoginState, customState: { name: '日本語 中文 한글 العربية 🎉' } };
      const encrypted = CookieCrypto.encryptSync(loginState, validSecret);
      expect(encrypted).toBeDefined();
    });

    it('should produce base64url-encoded output', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      // Base64url only contains A-Z, a-z, 0-9, -, _ (no padding)
      expect(encrypted).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should throw DATA_TOO_LARGE for very large data', () => {
      const largeData: LoginState = { ...baseLoginState, customState: { largeField: 'x'.repeat(5000) } };
      expect(() => {
        return CookieCrypto.encryptSync(largeData, validSecret);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.encryptSync(largeData, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DATA_TOO_LARGE');
      }
    });

    it('should accept moderately large data under 4KB', () => {
      const moderateData: LoginState = { ...baseLoginState, customState: { data: 'x'.repeat(2000) } };
      const encrypted = CookieCrypto.encryptSync(moderateData, validSecret);
      expect(encrypted).toBeDefined();
      expect(encrypted.length).toBeLessThan(4096);
    });

    it('should throw ENCRYPTION_FAILED for non-JSON-serializable data (BigInt)', () => {
      const dataWithBigInt: any = {
        ...baseLoginState,
        bigNumber: BigInt(12345),
      };

      expect(() => {
        CookieCrypto.encryptSync(dataWithBigInt, validSecret);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.encryptSync(dataWithBigInt, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toContain('Failed to encrypt data');
      }
    });
  });

  describe('decryptSync()', () => {
    it('should decrypt valid encrypted data', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt login state with all properties', () => {
      const original: LoginState = {
        ...baseLoginState,
        returnUrl: 'https://app.example.com/settings',
        customState: { flow: 'signup' },
      };
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should throw AUTH_FAILED for wrong secret', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      expect(() => {
        return CookieCrypto.decryptSync(encrypted, alternateSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(encrypted, alternateSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw AUTH_FAILED for tampered data', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      // Tamper with the encrypted data (pick a character that always differs from the original)
      const replacement = encrypted[20] === 'X' ? 'Y' : 'X';
      const tampered = `${encrypted.substring(0, 20)}${replacement}${encrypted.substring(21)}`;
      expect(() => {
        return CookieCrypto.decryptSync(tampered, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(tampered, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw AUTH_FAILED for invalid base64url', () => {
      const invalidBase64 = '!!!invalid!!!';
      expect(() => {
        return CookieCrypto.decryptSync(invalidBase64, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(invalidBase64, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
      }
    });

    it('should throw MALFORMED_DATA for truncated data', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const truncated = encrypted.substring(0, 30);
      expect(() => {
        return CookieCrypto.decryptSync(truncated, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(truncated, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('MALFORMED_DATA');
      }
    });

    it('should throw DATA_TOO_LARGE for cookie exceeding 4KB', () => {
      const tooLarge = 'A'.repeat(50000);
      expect(() => {
        return CookieCrypto.decryptSync(tooLarge, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(tooLarge, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DATA_TOO_LARGE');
      }
    });

    it('should throw EXPIRED for expired data', () => {
      // Save original skew value
      const CookieCryptoClass = CookieCrypto as any;
      const originalSkew = CookieCryptoClass.TIMESTAMP_SKEW_MS;
      // Temporarily reduce skew tolerance to 0 for testing
      CookieCryptoClass.TIMESTAMP_SKEW_MS = 0;

      try {
        const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);

        // Wait 100ms with maxAge of 50ms (0.05 seconds)
        const start = Date.now();
        while (Date.now() - start < 100) {
          // Busy wait for sync context
        }

        expect(() => {
          return CookieCrypto.decryptSync(encrypted, validSecret, 0.05);
        }).toThrow(CryptoError);

        try {
          CookieCrypto.decryptSync(encrypted, validSecret, 0.05);
        } catch (error) {
          expect((error as CryptoError).code).toBe('EXPIRED');
        }
      } finally {
        // Restore original skew value
        CookieCryptoClass.TIMESTAMP_SKEW_MS = originalSkew;
      }
    });

    it('should accept data within maxAge', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should include 60-second clock skew tolerance', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);

      // Wait 1+ second with maxAge of 1 second
      const start = Date.now();
      while (Date.now() - start < 1100) {
        // Busy wait
      }

      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 1);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should throw AUTH_FAILED when decipher operations fail', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);

      // Decode, corrupt the encrypted data portion, re-encode
      const bytes = Buffer.from(encrypted, 'base64url');
      bytes[25] ^= 0xff; // Corrupt encrypted data
      const corrupted = bytes.toString('base64url');

      expect(() => {
        CookieCrypto.decryptSync(corrupted, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(corrupted, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('AUTH_FAILED');
        expect((error as CryptoError).message).toBe('Failed to decrypt data');
      }
    });
  });

  describe('roundtrip integrity (sync)', () => {
    it('should roundtrip empty object', () => {
      const original = {} as LoginState;
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should roundtrip complex nested data', () => {
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
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should preserve data types', () => {
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
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted: any = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
      expect(typeof decrypted.customState.stringField).toBe('string');
      expect(typeof decrypted.customState.numberField).toBe('number');
      expect(typeof decrypted.customState.booleanField).toBe('boolean');
      expect(decrypted.customState.nullField).toBeNull();
      expect(Array.isArray(decrypted.customState.arrayField)).toBe(true);
      expect(typeof decrypted.customState.objectField).toBe('object');
    });

    it('should preserve unicode characters', () => {
      const original: LoginState = { ...baseLoginState, customState: { name: '日本語 中文 한글 العربية 🎉🚀' } };
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
      expect(decrypted.customState?.name).toBe('日本語 中文 한글 العربية 🎉🚀');
    });

    it('should preserve special characters', () => {
      const original: LoginState = { ...baseLoginState, customState: { name: '!@#$%^&*()_+-={}[]|\\:";\'<>?,./' } };
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });
  });

  describe('decryptWithSecretsSync()', () => {
    it('should decrypt with first secret', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const decrypted = CookieCrypto.decryptWithSecretsSync(encrypted, [validSecret, alternateSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt with second secret when first fails', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const decrypted = CookieCrypto.decryptWithSecretsSync(encrypted, [alternateSecret, validSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should decrypt with third secret when first two fail', () => {
      const thirdSecret = 'c'.repeat(32);
      const encrypted = CookieCrypto.encryptSync(baseLoginState, thirdSecret);
      const decrypted = CookieCrypto.decryptWithSecretsSync(
        encrypted,
        [validSecret, alternateSecret, thirdSecret],
        3600
      );
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should throw DECRYPTION_FAILED when all secrets fail', () => {
      const wrongSecret = 'z'.repeat(32);
      const encrypted = CookieCrypto.encryptSync(baseLoginState, wrongSecret);

      expect(() => {
        return CookieCrypto.decryptWithSecretsSync(encrypted, [validSecret, alternateSecret], 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptWithSecretsSync(encrypted, [validSecret, alternateSecret], 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('DECRYPTION_FAILED');
      }
    });

    it('should work with single secret in array', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);
      const decrypted = CookieCrypto.decryptWithSecretsSync(encrypted, [validSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });

    it('should try secrets in order (performance)', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, alternateSecret);
      const decrypted = CookieCrypto.decryptWithSecretsSync(encrypted, [alternateSecret, validSecret], 3600);
      expect(decrypted).toEqual(baseLoginState);
    });
  });

  describe('cross-compatibility (sync ↔ async)', () => {
    it('should decrypt async-encrypted data with sync', async () => {
      const original: LoginState = { ...baseLoginState, returnUrl: 'https://app.example.com/settings' };
      const encrypted = await CookieCrypto.encrypt(original, validSecret);
      const decrypted = CookieCrypto.decryptSync(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should decrypt sync-encrypted data with async', async () => {
      const original: LoginState = { ...baseLoginState, returnUrl: 'https://app.example.com/settings' };
      const encrypted = CookieCrypto.encryptSync(original, validSecret);
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted).toEqual(original);
    });

    it('should handle complex data cross-platform', async () => {
      const original: LoginState = {
        ...baseLoginState,
        customState: {
          metadata: {
            roles: ['admin', 'user'],
            settings: { theme: 'dark' },
          },
        },
      };

      // Encrypt with async, decrypt with sync
      const encryptedAsync = await CookieCrypto.encrypt(original, validSecret);
      const decryptedFromAsync = CookieCrypto.decryptSync(encryptedAsync, validSecret, 3600);
      expect(decryptedFromAsync).toEqual(original);

      // Encrypt with sync, decrypt with async
      const encryptedSync = CookieCrypto.encryptSync(original, validSecret);
      const decryptedFromSync = await CookieCrypto.decrypt(encryptedSync, validSecret, 3600);
      expect(decryptedFromSync).toEqual(original);
    });

    it('should handle unicode data cross-platform', async () => {
      const original: LoginState = { ...baseLoginState, customState: { name: '日本語 🎉' } };
      const encryptedAsync = await CookieCrypto.encrypt(original, validSecret);
      const decryptedSync = CookieCrypto.decryptSync(encryptedAsync, validSecret, 3600);
      expect(decryptedSync).toEqual(original);
      const encryptedSync = CookieCrypto.encryptSync(original, validSecret);
      const decryptedAsync = await CookieCrypto.decrypt(encryptedSync, validSecret, 3600);
      expect(decryptedAsync).toEqual(original);
    });

    it('should support key rotation cross-platform', async () => {
      // Encrypt with async, decrypt with sync using multiple secrets
      const encryptedAsync = await CookieCrypto.encrypt(baseLoginState, validSecret);
      const decryptedSync = CookieCrypto.decryptWithSecretsSync(encryptedAsync, [alternateSecret, validSecret], 3600);
      expect(decryptedSync).toEqual(baseLoginState);

      // Encrypt with sync, decrypt with async using multiple secrets
      const encryptedSync = CookieCrypto.encryptSync(baseLoginState, alternateSecret);
      const decryptedAsync = await CookieCrypto.decryptWithSecrets(encryptedSync, [validSecret, alternateSecret], 3600);
      expect(decryptedAsync).toEqual(baseLoginState);
    });
  });

  describe('binary format validation (sync)', () => {
    it('should have minimum size of 39 bytes', () => {
      const encrypted = CookieCrypto.encryptSync({} as LoginState, validSecret);
      expect(encrypted.length).toBeGreaterThanOrEqual(39);
    });

    it('should throw UNSUPPORTED_VERSION for wrong version', () => {
      const encrypted = CookieCrypto.encryptSync(baseLoginState, validSecret);

      // Decode, change version byte, re-encode
      const bytes = Buffer.from(encrypted, 'base64url');
      bytes[0] = 99;
      const modifiedEncrypted = bytes.toString('base64url');
      expect(() => {
        return CookieCrypto.decryptSync(modifiedEncrypted, validSecret, 3600);
      }).toThrow(CryptoError);

      try {
        CookieCrypto.decryptSync(modifiedEncrypted, validSecret, 3600);
      } catch (error) {
        expect((error as CryptoError).code).toBe('UNSUPPORTED_VERSION');
        expect((error as CryptoError).message).toContain('99');
      }
    });
  });

  describe('Node crypto error handling', () => {
    it('should throw ENCRYPTION_FAILED when cipher operations fail', () => {
      expect.assertions(3);
      // Mock Node crypto to make cipher fail
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const crypto = require('node:crypto');
      const originalCreateCipheriv = crypto.createCipheriv;
      crypto.createCipheriv = jest.fn().mockImplementation(() => {
        throw new Error('Cipher creation failed');
      });

      try {
        CookieCrypto.encryptSync(baseLoginState, validSecret);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toBe('Failed to encrypt data');
      } finally {
        // Restore
        crypto.createCipheriv = originalCreateCipheriv;
      }
    });
  });
});
