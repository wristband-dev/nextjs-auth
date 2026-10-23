import { CookieCrypto } from '../../../src/utils/crypto';
import { CryptoError } from '../../../src/error/crypto-error';
import { LoginState } from '../../../src/types';

describe('CookieCrypto - Validation', () => {
  const baseLoginState: LoginState = {
    codeVerifier: 'code-verifier-123',
    redirectUri: 'https://app.example.com/auth/callback',
    state: 'state-123',
  };

  describe('secret validation', () => {
    it('should reject empty string secret', async () => {
      await expect(CookieCrypto.encrypt(baseLoginState, '')).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.encrypt(baseLoginState, '')).rejects.toThrow('non-empty string');
    });

    it('should reject secret shorter than 32 characters', async () => {
      const shortSecret = 'a'.repeat(31);

      await expect(CookieCrypto.encrypt(baseLoginState, shortSecret)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.encrypt(baseLoginState, shortSecret)).rejects.toThrow('at least 32 characters');
    });

    it('should accept secret exactly 32 characters', async () => {
      const validSecret = 'a'.repeat(32);
      const encrypted = await CookieCrypto.encrypt(baseLoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should accept secret longer than 32 characters', async () => {
      const longSecret = 'a'.repeat(64);
      const encrypted = await CookieCrypto.encrypt(baseLoginState, longSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should reject non-string secret', async () => {
      await expect(CookieCrypto.encrypt(baseLoginState, 12345 as any)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.encrypt(baseLoginState, null as any)).rejects.toThrow(CryptoError);
    });

    it('should include actual length in error message', async () => {
      expect.assertions(2);
      const secret = 'short';

      try {
        await CookieCrypto.encrypt(baseLoginState, secret);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).message).toContain('5'); // actual length
      }
    });
  });

  describe('secrets list validation', () => {
    const validSecret = 'a'.repeat(32);
    let encryptedValue: string;

    beforeAll(async () => {
      // Create a real encrypted value to use in tests
      encryptedValue = await CookieCrypto.encrypt(baseLoginState, validSecret);
    });

    it('should reject non-array secrets', async () => {
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, null as any, 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, 'not-array' as any, 3600)).rejects.toThrow(
        'must be an array'
      );
    });

    it('should reject empty secrets array', async () => {
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, [], 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, [], 3600)).rejects.toThrow(
        'At least one secret is required'
      );
    });

    it('should reject more than 3 secrets', async () => {
      const tooManySecrets = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32), 'd'.repeat(32)];

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, tooManySecrets, 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, tooManySecrets, 3600)).rejects.toThrow(
        'Maximum 3 secrets allowed'
      );
    });

    it('should accept exactly 3 secrets', async () => {
      // All different secrets (none match validSecret), so decryption will fail
      const threeSecrets = ['b'.repeat(32), 'c'.repeat(32), 'd'.repeat(32)];

      // Passes validation, fails decryption (wrong secrets)
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, threeSecrets, 3600)).rejects.toThrow(CryptoError);
    });

    it('should accept single secret in array', async () => {
      // Different secret, so decryption will fail
      const oneSecret = ['b'.repeat(32)];

      // Passes validation, fails decryption (wrong secret)
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, oneSecret, 3600)).rejects.toThrow(CryptoError);
    });

    it('should accept two secrets', async () => {
      // Both different secrets, so decryption will fail
      const twoSecrets = ['b'.repeat(32), 'c'.repeat(32)];

      // Passes validation, fails decryption (wrong secrets)
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, twoSecrets, 3600)).rejects.toThrow(CryptoError);
    });

    it('should reject undefined secrets', async () => {
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, undefined as any, 3600)).rejects.toThrow(
        CryptoError
      );

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, undefined as any, 3600)).rejects.toThrow(
        'must be an array'
      );
    });

    it('should reject object as secrets', async () => {
      await expect(
        CookieCrypto.decryptWithSecrets(encryptedValue, { secret: validSecret } as any, 3600)
      ).rejects.toThrow(CryptoError);
    });

    it('should reject falsy non-null/undefined secrets', async () => {
      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, 0 as any, 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decryptWithSecrets(encryptedValue, '' as any, 3600)).rejects.toThrow(
        'must be an array'
      );
    });
  });

  describe('maxAge validation', () => {
    const validSecret = 'a'.repeat(32);
    const encryptedValue = 'AQABkx7f2g...'; // Mock encrypted value

    it('should reject zero maxAge', async () => {
      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, 0)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, 0)).rejects.toThrow(
        'maxAge must be greater than 0'
      );
    });

    it('should reject negative maxAge', async () => {
      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, -100)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, -100)).rejects.toThrow(
        'maxAge must be greater than 0'
      );
    });

    it('should accept maxAge of 1', async () => {
      // Will fail decryption but pass validation
      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, 1)).rejects.toThrow(); // Fails at decryption, not validation
    });

    it('should accept large maxAge values', async () => {
      const oneYear = 365 * 24 * 60 * 60;

      // Will fail decryption but pass validation
      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, oneYear)).rejects.toThrow(); // Fails at decryption, not validation
    });

    it('should reject non-number maxAge', async () => {
      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, '3600' as any)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decrypt(encryptedValue, validSecret, null as any)).rejects.toThrow(CryptoError);
    });
  });

  describe('data validation', () => {
    const validSecret = 'a'.repeat(32);

    it('should reject null data', async () => {
      await expect(CookieCrypto.encrypt(null as any, validSecret)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.encrypt(null as any, validSecret)).rejects.toThrow('plain object');
    });

    it('should reject undefined data', async () => {
      await expect(CookieCrypto.encrypt(undefined as any, validSecret)).rejects.toThrow(CryptoError);
    });

    it('should reject array as data', async () => {
      await expect(CookieCrypto.encrypt([] as any, validSecret)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.encrypt([1, 2, 3] as any, validSecret)).rejects.toThrow('plain object');
    });

    it('should accept empty object', async () => {
      const encrypted = await CookieCrypto.encrypt({} as LoginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should accept object with properties', async () => {
      const loginState: LoginState = {
        ...baseLoginState,
        returnUrl: 'https://app.example.com/settings',
        customState: { loginTime: Date.now() },
      };

      const encrypted = await CookieCrypto.encrypt(loginState, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should handle data with functions by omitting them', async () => {
      const dataWithFunction = {
        ...baseLoginState,
        callback: (): any => {
          return console.log('test');
        },
      };

      // Should succeed - functions are silently omitted by JSON.stringify
      const encrypted = await CookieCrypto.encrypt(dataWithFunction as any, validSecret);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');

      // Decrypt and verify function was omitted
      const decrypted = await CookieCrypto.decrypt(encrypted, validSecret, 3600);
      expect(decrypted.state).toBe('state-123');
      expect(decrypted).not.toHaveProperty('callback');
    });

    it('should reject circular references', async () => {
      const circular: any = { ...baseLoginState };
      circular.self = circular;

      await expect(CookieCrypto.encrypt(circular, validSecret)).rejects.toThrow(CryptoError);
    });

    it('should reject string as data', async () => {
      await expect(CookieCrypto.encrypt('not an object' as any, validSecret)).rejects.toThrow(CryptoError);

      try {
        await CookieCrypto.encrypt('not an object' as any, validSecret);
      } catch (error) {
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
        expect((error as CryptoError).message).toContain('plain object');
      }
    });

    it('should reject number as data', async () => {
      await expect(CookieCrypto.encrypt(123 as any, validSecret)).rejects.toThrow(CryptoError);
    });

    it('should reject boolean as data', async () => {
      await expect(CookieCrypto.encrypt(true as any, validSecret)).rejects.toThrow(CryptoError);
    });

    it('should reject string as data (sync)', () => {
      expect(() => {
        CookieCrypto.encryptSync('not an object' as any, validSecret);
      }).toThrow(CryptoError);
    });

    it('should reject number as data (sync)', () => {
      expect(() => {
        CookieCrypto.encryptSync(123 as any, validSecret);
      }).toThrow(CryptoError);
    });
  });

  describe('encrypted value validation', () => {
    const validSecret = 'a'.repeat(32);

    it('should reject empty string', async () => {
      await expect(CookieCrypto.decrypt('', validSecret, 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decrypt('', validSecret, 3600)).rejects.toThrow('non-empty string');
    });

    it('should reject null encrypted value', async () => {
      await expect(CookieCrypto.decrypt(null as any, validSecret, 3600)).rejects.toThrow(CryptoError);
    });

    it('should reject undefined encrypted value', async () => {
      await expect(CookieCrypto.decrypt(undefined as any, validSecret, 3600)).rejects.toThrow(CryptoError);
    });

    it('should reject non-string encrypted value', async () => {
      await expect(CookieCrypto.decrypt(12345 as any, validSecret, 3600)).rejects.toThrow(CryptoError);

      await expect(CookieCrypto.decrypt({} as any, validSecret, 3600)).rejects.toThrow(CryptoError);
    });
  });

  describe('error codes', () => {
    const validSecret = 'a'.repeat(32);

    it('should throw INVALID_SECRET for bad secret', async () => {
      expect.assertions(2);
      try {
        await CookieCrypto.encrypt(baseLoginState, 'short');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('INVALID_SECRET');
      }
    });

    it('should throw INVALID_SECRETS_LIST for bad secrets array', async () => {
      expect.assertions(2);
      try {
        await CookieCrypto.decryptWithSecrets('test', [], 3600);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('INVALID_SECRETS_LIST');
      }
    });

    it('should throw INVALID_MAX_AGE for bad maxAge', async () => {
      expect.assertions(2);
      try {
        await CookieCrypto.decrypt('test', validSecret, 0);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('INVALID_MAX_AGE');
      }
    });

    it('should throw ENCRYPTION_FAILED for bad data', async () => {
      expect.assertions(2);
      try {
        await CookieCrypto.encrypt(null as any, validSecret);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
      }
    });

    it('should throw MALFORMED_DATA for bad encrypted value', async () => {
      expect.assertions(2);
      try {
        await CookieCrypto.decrypt('', validSecret, 3600);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MALFORMED_DATA');
      }
    });
  });
});
