/**
 * Represents an error that occurs during a fetch request.
 *
 * Wraps both the raw {@link Response} object and its parsed body,
 * providing structured access to error details returned by the server.
 *
 * @template Response - The type of the underlying fetch response object.
 */
export class FetchError<Response> extends Error {
  /**
   * The raw Response object returned from the fetch request.
   */
  readonly response?: Response;
  /**
   * The parsed response body, typically JSON or text, if available.
   */
  readonly body?: any;

  /**
   * Creates a new FetchError instance.
   *
   * @param response - The raw fetch Response associated with the error.
   * @param body - The parsed body of the response, if available.
   */
  constructor(response: Response, body: any) {
    super('Fetch Error');
    this.name = 'FetchError';
    this.response = response;
    this.body = body;
  }
}
