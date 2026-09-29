export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export class DuplicateMerchantError extends Error {
  constructor() {
    super('merchant already connected');
    this.name = 'DuplicateMerchantError';
  }
}

export class DuplicateTenantError extends Error {
  constructor() {
    super('tenant already exists');
    this.name = 'DuplicateTenantError';
  }
}
