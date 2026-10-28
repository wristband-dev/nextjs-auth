import { CryptoErrorCode } from '../types';

/**
 * Error class for cryptographic operations.
 *
 * Internal error type used by CookieCrypto for encryption/decryption failures.
 * Callers may wrap these errors in their own error types before exposing them to users,
 * but can be inspected via the error cause chain for debugging.
 *
 * @internal
 *
 * @example
 * ```typescript
 * try {
 *   await CookieCrypto.decrypt(data, secret, maxAge);
 * } catch (error) {
 *   if (error instanceof CryptoError) {
 *     console.error('Crypto error:', error.code);
 *     if (error.cause) {
 *       console.error('Caused by:', error.cause);
 *     }
 *   }
 * }
 * ```
 */
export class CryptoError extends Error {
  public readonly code: CryptoErrorCode;
  public readonly cause?: Error;

  /**
   * Create a new CryptoError.
   *
   * @param code - The error code identifying the failure type
   * @param message - Human-readable error message (defaults to code if not provided)
   * @param cause - Optional underlying error for debugging
   */
  constructor(code: CryptoErrorCode, message?: string, cause?: unknown) {
    super(message ?? code);

    this.name = 'CryptoError';
    this.code = code;

    if (cause) {
      this.cause = cause instanceof Error ? cause : new Error(String(cause));
    }

    // Maintain proper stack trace (V8 engines only)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, CryptoError);
    }
  }
}
