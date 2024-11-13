export class FetchError<Response> extends Error {
  response?: Response;
  body?: any;

  constructor(response: Response, body: any) {
    super('Fetch Error');
    this.name = 'FetchError';
    this.response = response;
    this.body = body;
  }
}
