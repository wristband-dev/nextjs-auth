export class WristbandError extends Error {
  private error: string;
  private errorDescription?: string;
  private originalError?: Error;

  constructor(error: string, errorDescription?: string, originalError?: Error) {
    super(error);
    this.name = 'WristbandError';
    this.error = error;
    this.errorDescription = errorDescription;
    this.originalError = originalError;
  }

  getError(): string {
    return this.error;
  }

  getErrorDescription(): string | undefined {
    return this.errorDescription;
  }

  getOriginalError(): Error | undefined {
    return this.originalError;
  }
}
