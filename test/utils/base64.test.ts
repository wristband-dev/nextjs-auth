import { Base64 } from '../../src/utils/base64';

describe('Base64', () => {
  describe('encode', () => {
    it('should encode empty Uint8Array to empty string', () => {
      const input = new Uint8Array(0);
      const result = Base64.encode(input);
      expect(result).toBe('');
    });

    it('should encode simple ASCII text with padding', () => {
      // "Hello"
      const input = new Uint8Array([72, 101, 108, 108, 111]);
      const result = Base64.encode(input);
      expect(result).toBe('SGVsbG8=');
    });

    it('should encode single byte with padding', () => {
      const input = new Uint8Array([65]); // 'A'
      const result = Base64.encode(input);
      expect(result).toBe('QQ==');
    });

    it('should keep "+" and "/" characters', () => {
      const input = new Uint8Array([251, 255]);
      const result = Base64.encode(input);
      expect(result).toBe('+/8=');
    });

    it('should encode binary data with all byte values', () => {
      // Include all possible byte values 0-255
      const input = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        input[i] = i;
      }
      const result = Base64.encode(input);
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);

      // Verify it's valid base64
      expect(result).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);
    });

    it('should encode UTF-8 byte sequences', () => {
      // UTF-8 encoding of "Hello 世界" manually represented
      const input = new Uint8Array([
        72,
        101,
        108,
        108,
        111,
        32, // "Hello "
        228,
        184,
        150,
        231,
        149,
        140, // "世界"
      ]);
      const result = Base64.encode(input);
      expect(result).toBeTruthy();
      expect(result).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);
    });

    it('should match Node.js base64 encoding', () => {
      const input = new Uint8Array(1000);
      for (let i = 0; i < input.length; i++) {
        input[i] = (i * 31) % 256;
      }
      const result = Base64.encode(input);
      expect(result).toBe(Buffer.from(input).toString('base64'));
    });

    it('should handle data exactly at chunk boundary (32KB)', () => {
      const chunkSize = 0x8000; // 32KB
      const input = new Uint8Array(chunkSize);
      input.fill(65); // Fill with 'A'

      const result = Base64.encode(input);
      expect(result).toBe(Buffer.from(input).toString('base64'));
    });

    it('should handle data larger than chunk size', () => {
      const size = 0x8000 + 1000; // 32KB + 1000 bytes
      const input = new Uint8Array(size);

      // Fill with pattern to ensure chunks are processed correctly
      for (let i = 0; i < size; i++) {
        input[i] = i % 256;
      }

      const result = Base64.encode(input);
      expect(result).toBe(Buffer.from(input).toString('base64'));
    });

    it('should produce consistent output for same input', () => {
      const input = new Uint8Array([1, 2, 3, 4, 5]);
      const result1 = Base64.encode(input);
      const result2 = Base64.encode(input);
      expect(result1).toBe(result2);
    });
  });

  describe('encodeStr', () => {
    it('should encode empty string to empty string', () => {
      expect(Base64.encodeStr('')).toBe('');
    });

    it('should encode a simple ASCII string', () => {
      expect(Base64.encodeStr('Hello')).toBe('SGVsbG8=');
    });

    it('should encode clientId:clientSecret format correctly', () => {
      const input = 'myClientId:myClientSecret';
      expect(Base64.encodeStr(input)).toBe(btoa(input));
    });

    it('should encode non-ASCII characters as UTF-8', () => {
      const input = 'Hello 世界';
      expect(Base64.encodeStr(input)).toBe(Buffer.from(input, 'utf8').toString('base64'));
    });

    it('should match encode() of the UTF-8 bytes', () => {
      const input = 'test-input:é';
      expect(Base64.encodeStr(input)).toBe(Base64.encode(new TextEncoder().encode(input)));
    });

    it('should produce valid base64 output', () => {
      const result = Base64.encodeStr('test-input');
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
  });

  describe('urlEncode', () => {
    it('should encode empty Uint8Array to empty string', () => {
      const input = new Uint8Array(0);
      const result = Base64.urlEncode(input);
      expect(result).toBe('');
    });

    it('should encode simple ASCII text without padding', () => {
      // "Hello"
      const input = new Uint8Array([72, 101, 108, 108, 111]);
      const result = Base64.urlEncode(input);
      expect(result).toBe('SGVsbG8');
    });

    it('should encode single byte without padding', () => {
      const input = new Uint8Array([65]); // 'A'
      const result = Base64.urlEncode(input);
      expect(result).toBe('QQ');
    });

    it('should encode two bytes without padding', () => {
      const input = new Uint8Array([65, 66]); // 'AB'
      const result = Base64.urlEncode(input);
      expect(result).toBe('QUI');
    });

    it('should encode three bytes with no padding needed', () => {
      const input = new Uint8Array([65, 66, 67]); // 'ABC'
      const result = Base64.urlEncode(input);
      expect(result).toBe('QUJD');
    });

    it('should use "-" and "_" instead of "+" and "/"', () => {
      // Standard base64 for these bytes is "+/8=" (contains both "+" and "/")
      const input = new Uint8Array([251, 255]);
      const result = Base64.urlEncode(input);
      expect(result).toBe('-_8');
    });

    it('should encode binary data with all byte values', () => {
      // Include all possible byte values 0-255
      const input = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        input[i] = i;
      }
      const result = Base64.urlEncode(input);
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);

      // Verify it's valid base64url (no "+", "/", or "=")
      expect(result).toMatch(/^[A-Za-z0-9_-]*$/);
    });

    it('should encode UTF-8 byte sequences', () => {
      // UTF-8 encoding of "Hello 世界" manually represented
      const input = new Uint8Array([
        72,
        101,
        108,
        108,
        111,
        32, // "Hello "
        228,
        184,
        150,
        231,
        149,
        140, // "世界"
      ]);
      const result = Base64.urlEncode(input);
      expect(result).toBeTruthy();
      expect(result).toMatch(/^[A-Za-z0-9_-]*$/);
    });

    it('should produce output that is unchanged by encodeURIComponent', () => {
      const input = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        input[i] = i;
      }
      const result = Base64.urlEncode(input);
      expect(encodeURIComponent(result)).toBe(result);
    });

    it('should match Node.js base64url encoding', () => {
      const input = new Uint8Array(1000);
      for (let i = 0; i < input.length; i++) {
        input[i] = (i * 31) % 256;
      }
      const result = Base64.urlEncode(input);
      expect(result).toBe(Buffer.from(input).toString('base64url'));
    });

    it('should handle data exactly at chunk boundary (32KB)', () => {
      const chunkSize = 0x8000; // 32KB
      const input = new Uint8Array(chunkSize);
      input.fill(65); // Fill with 'A'

      const result = Base64.urlEncode(input);
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle data larger than chunk size', () => {
      const size = 0x8000 + 1000; // 32KB + 1000 bytes
      const input = new Uint8Array(size);

      // Fill with pattern to ensure chunks are processed correctly
      for (let i = 0; i < size; i++) {
        input[i] = i % 256;
      }

      const result = Base64.urlEncode(input);
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle very large data (multiple chunks)', () => {
      const size = 0x8000 * 3 + 500; // ~96KB
      const input = new Uint8Array(size);
      input.fill(88); // Fill with 'X'

      const result = Base64.urlEncode(input);
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);
    });

    it('should produce consistent output for same input', () => {
      const input = new Uint8Array([1, 2, 3, 4, 5]);
      const result1 = Base64.urlEncode(input);
      const result2 = Base64.urlEncode(input);
      expect(result1).toBe(result2);
    });
  });

  describe('urlDecode', () => {
    it('should decode empty string to empty Uint8Array', () => {
      const result = Base64.urlDecode('');
      expect(result).toEqual(new Uint8Array(0));
      expect(result.length).toBe(0);
    });

    it('should decode base64url without padding', () => {
      const result = Base64.urlDecode('SGVsbG8');
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should decode base64url with two missing padding characters', () => {
      const result = Base64.urlDecode('QQ');
      expect(result).toEqual(new Uint8Array([65]));
    });

    it('should decode base64url with no padding needed', () => {
      const result = Base64.urlDecode('QUJD');
      expect(result).toEqual(new Uint8Array([65, 66, 67]));
    });

    it('should decode "-" and "_" characters', () => {
      const result = Base64.urlDecode('-_8');
      expect(result).toEqual(new Uint8Array([251, 255]));
    });

    it('should decode standard base64 with padding', () => {
      const result = Base64.urlDecode('SGVsbG8=');
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should decode standard base64 single character with padding', () => {
      const result = Base64.urlDecode('QQ==');
      expect(result).toEqual(new Uint8Array([65]));
    });

    it('should decode standard base64 with plus and slash characters', () => {
      const result = Base64.urlDecode('+/8=');
      expect(result).toEqual(new Uint8Array([251, 255]));
    });

    it('should decode base64 with all byte values', () => {
      const original = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        original[i] = i;
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should throw on invalid base64 characters', () => {
      expect(() => {
        return Base64.urlDecode('!!!invalid!!!');
      }).toThrow();
      expect(() => {
        return Base64.urlDecode('SGVs^G8');
      }).toThrow();
      expect(() => {
        return Base64.urlDecode('Hello@World');
      }).toThrow(); // @ is invalid in base64
    });

    it('should throw on malformed base64 (impossible length)', () => {
      // A length with a remainder of 1 when divided by 4 can never be produced by encoding
      expect(() => {
        return Base64.urlDecode('A');
      }).toThrow();
      expect(() => {
        return Base64.urlDecode('SGVsb');
      }).toThrow();
    });

    it('should decode large base64url strings', () => {
      const size = 0x8000 * 2; // 64KB
      const original = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        original[i] = i % 256;
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });
  });

  describe('urlEncode/urlDecode roundtrip', () => {
    it('should successfully roundtrip empty data', () => {
      const original = new Uint8Array(0);
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip single byte', () => {
      const original = new Uint8Array([42]);
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip every padding length', () => {
      // Lengths 1, 2, and 3 cover the 2, 1, and 0 stripped padding characters cases
      [1, 2, 3, 4, 5, 6].forEach((length) => {
        const original = new Uint8Array(length).fill(200);
        const encoded = Base64.urlEncode(original);
        expect(Base64.urlDecode(encoded)).toEqual(original);
      });
    });

    it('should successfully roundtrip random data', () => {
      const original = new Uint8Array(100);
      for (let i = 0; i < original.length; i++) {
        original[i] = Math.floor(Math.random() * 256);
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip data at chunk boundary', () => {
      const original = new Uint8Array(0x8000);
      original.fill(123);
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip data larger than chunk size', () => {
      const original = new Uint8Array(0x8000 + 5000);
      for (let i = 0; i < original.length; i++) {
        original[i] = i % 256;
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip very large data', () => {
      const original = new Uint8Array(0x8000 * 5); // 160KB
      for (let i = 0; i < original.length; i++) {
        original[i] = (i * 7) % 256;
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it('should successfully roundtrip all possible byte values', () => {
      const original = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        original[i] = i;
      }
      const encoded = Base64.urlEncode(original);
      const decoded = Base64.urlDecode(encoded);
      expect(decoded).toEqual(original);
    });
  });
});
