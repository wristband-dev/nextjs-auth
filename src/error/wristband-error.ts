/**
 * Represents a structured error from the Wristband SDK.
 *
 * Wraps an error code, an optional description, and optionally the original underlying Error.
 */
export class WristbandError extends Error {
  /**
   * A short error code or identifier.
   */
  readonly code: string;
  /**
   * An optional human-readable description of the error.
   */
  readonly errorDescription?: string;
  /**
   * The original Error instance that triggered this WristbandError, if any.
   */
  readonly originalError?: Error;

  /**
   * Creates a new WristbandError instance.
   *
   * @param code - A short error code or identifier.
   * @param errorDescription - Optional human-readable description of the error.
   * @param originalError - Optional original Error instance that caused this error.
   */
  constructor(code: string, errorDescription?: string, originalError?: Error) {
    super(errorDescription || code);
    this.name = 'WristbandError';
    this.code = code;
    this.errorDescription = errorDescription;
    this.originalError = originalError;
  }
}
