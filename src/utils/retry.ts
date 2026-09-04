import { FetchError } from '../error';
import { MAX_API_RETRY_ATTEMPTS, API_RETRY_DELAY_MS, API_RETRY_DELAY_MULTIPLIER } from './constants';

/**
 * Determines whether an error from a Wristband API call is safe to retry.
 *
 * 4xx client errors are never retried since the request itself is the problem and retrying
 * won't change the outcome. 5xx server errors, FetchErrors without a response, and any other
 * error (e.g. network failures) are treated as transient and are retried.
 *
 * @param error - The error thrown by the API call.
 * @returns True if the error is retryable.
 *
 * @internal
 */
function isRetryableError(error: unknown): boolean {
  if (error instanceof FetchError && error.response) {
    const { status } = error.response;
    return status >= 500;
  }
  return true;
}

/**
 * Wraps an async Wristband API call with common retry logic. The call is retried up to
 * {@link MAX_API_RETRY_ATTEMPTS} times, but only for retryable errors (5xx responses, missing
 * responses, or non-FetchErrors such as network failures). Non-retryable errors (4xx responses)
 * are re-thrown immediately without retrying.
 *
 * The delay between attempts starts at {@link API_RETRY_DELAY_MS} and grows exponentially,
 * multiplying by {@link API_RETRY_DELAY_MULTIPLIER} after each failed attempt.
 *
 * This does not transform or wrap errors in any way -- the original error (FetchError or
 * otherwise) is always what gets thrown, whether on an immediate non-retryable failure or
 * after all retry attempts are exhausted. Callers remain responsible for any error mapping.
 *
 * @param fn - The async function to invoke, retrying on transient failure.
 * @returns The resolved value of fn.
 * @throws The error from the last attempt once retries are exhausted, or immediately for a
 *   non-retryable error.
 *
 * @internal
 */
export async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let delayMs = API_RETRY_DELAY_MS;

  for (let attempt = 1; attempt <= MAX_API_RETRY_ATTEMPTS; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      return await fn();
    } catch (error: unknown) {
      if (attempt === MAX_API_RETRY_ATTEMPTS || !isRetryableError(error)) {
        throw error;
      }

      // eslint-disable-next-line no-await-in-loop
      await new Promise<void>((resolve) => {
        setTimeout(resolve, delayMs);
      });
      delayMs *= API_RETRY_DELAY_MULTIPLIER;
    }
  }

  // This is merely a safety check, but this should never happen.
  throw new Error('Unreachable: withRetry loop exited without returning or throwing');
}
