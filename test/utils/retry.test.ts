import { withRetry } from '../../src/utils/retry';
import { FetchError } from '../../src/error';
import { API_RETRY_DELAY_MS, API_RETRY_DELAY_MULTIPLIER, MAX_API_RETRY_ATTEMPTS } from '../../src/utils/constants';

function createFetchError(status: number, body: unknown = {}): FetchError<{ status: number }> {
  return new FetchError({ status } as any, body);
}

describe('withRetry', () => {
  test('Resolves on first attempt without retrying', async () => {
    const fn = jest.fn().mockResolvedValue('result');

    const result = await withRetry(fn);

    expect(result).toBe('result');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('Retries on a 5xx FetchError and eventually succeeds', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(createFetchError(500))
      .mockRejectedValueOnce(createFetchError(503))
      .mockResolvedValue('result');

    const result = await withRetry(fn);

    expect(result).toBe('result');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  test('Retries on a network error (non-FetchError) and eventually succeeds', async () => {
    const fn = jest.fn().mockRejectedValueOnce(new Error('Network failure')).mockResolvedValue('result');

    const result = await withRetry(fn);

    expect(result).toBe('result');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  test('Retries on a FetchError with no response', async () => {
    const errorWithNoResponse = new FetchError(undefined as any, {});
    const fn = jest.fn().mockRejectedValueOnce(errorWithNoResponse).mockResolvedValue('result');

    const result = await withRetry(fn);

    expect(result).toBe('result');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  test('Does not retry on a 4xx FetchError', async () => {
    const error = createFetchError(400);
    const fn = jest.fn().mockRejectedValue(error);

    await expect(withRetry(fn)).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('Does not retry on a 404 FetchError', async () => {
    const error = createFetchError(404);
    const fn = jest.fn().mockRejectedValue(error);

    await expect(withRetry(fn)).rejects.toThrow(error);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test('Exhausts retries and throws the last error on persistent 5xx failures', async () => {
    const finalError = createFetchError(500, { error: 'server_error' });
    const fn = jest.fn().mockRejectedValue(finalError);

    await expect(withRetry(fn)).rejects.toThrow(finalError);
    expect(fn).toHaveBeenCalledTimes(MAX_API_RETRY_ATTEMPTS);
  });

  test('Exhausts retries and throws the last error on persistent network failures', async () => {
    const finalError = new Error('Persistent network failure');
    const fn = jest.fn().mockRejectedValue(finalError);

    await expect(withRetry(fn)).rejects.toThrow(finalError);
    expect(fn).toHaveBeenCalledTimes(MAX_API_RETRY_ATTEMPTS);
  });

  test('Waits between retry attempts', async () => {
    const fn = jest.fn().mockRejectedValueOnce(createFetchError(500)).mockResolvedValue('result');

    const startTime = Date.now();
    await withRetry(fn);
    const elapsed = Date.now() - startTime;

    expect(elapsed).toBeGreaterThanOrEqual(API_RETRY_DELAY_MS - 1);
  });

  test('Does not wait after a non-retryable error', async () => {
    const fn = jest.fn().mockRejectedValue(createFetchError(400));

    const startTime = Date.now();
    await expect(withRetry(fn)).rejects.toThrow();
    const elapsed = Date.now() - startTime;

    expect(elapsed).toBeLessThan(API_RETRY_DELAY_MS);
  });

  test('Applies exponential backoff, multiplying the delay after each retry', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(createFetchError(500))
      .mockRejectedValueOnce(createFetchError(500))
      .mockResolvedValue('result');

    const expectedMinElapsed = API_RETRY_DELAY_MS + API_RETRY_DELAY_MS * API_RETRY_DELAY_MULTIPLIER;

    const startTime = Date.now();
    await withRetry(fn);
    const elapsed = Date.now() - startTime;

    expect(elapsed).toBeGreaterThanOrEqual(expectedMinElapsed - 1);
  });
});
