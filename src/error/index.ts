export class WristbandError extends Error {
  private error: string;
  private errorDescription?: string;

  constructor(error: string, errorDescription?: string) {
    super(error);
    this.name = 'WristbandError';
    this.error = error;
    this.errorDescription = errorDescription;
  }

  getError(): string {
    return this.error;
  }

  getErrorDescription(): string | undefined {
    return this.errorDescription;
  }
}
