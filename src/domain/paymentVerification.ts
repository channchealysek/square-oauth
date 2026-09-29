export interface SquarePaymentFacts {
  id: string;
  status: string | null;
  amount: number | null;
  currency: string | null;
  locationId: string | null;
  referenceId: string | null;
}

export type PaymentVerificationReason =
  | 'verified'
  | 'payment_not_found'
  | 'status_not_completed'
  | 'amount_mismatch'
  | 'currency_mismatch'
  | 'location_mismatch'
  | 'reference_mismatch';

export interface PaymentVerification {
  verified: boolean;
  reason: PaymentVerificationReason;
  paymentId: string;
  status?: string | null;
  amount?: number | null;
  currency?: string | null;
  locationId?: string | null;
  referenceId?: string | null;
}

export function evaluatePayment(input: {
  requestedPaymentId: string;
  payment: SquarePaymentFacts | null;
  expectedAmount: number;
  expectedCurrency: string;
  expectedLocationId: string;
  referenceId?: string;
}): PaymentVerification {
  const payment = input.payment;
  if (!payment) {
    return {
      verified: false,
      reason: 'payment_not_found',
      paymentId: input.requestedPaymentId,
    };
  }
  const base = {
    paymentId: payment.id,
    status: payment.status,
    amount: payment.amount,
    currency: payment.currency,
    locationId: payment.locationId,
    referenceId: payment.referenceId,
  };
  if (payment.status !== 'COMPLETED') {
    return { verified: false, reason: 'status_not_completed', ...base };
  }
  if (payment.amount !== input.expectedAmount) {
    return { verified: false, reason: 'amount_mismatch', ...base };
  }
  if (payment.currency !== input.expectedCurrency) {
    return { verified: false, reason: 'currency_mismatch', ...base };
  }
  if (!payment.locationId || payment.locationId !== input.expectedLocationId) {
    return { verified: false, reason: 'location_mismatch', ...base };
  }
  if (input.referenceId !== undefined && payment.referenceId !== input.referenceId) {
    return { verified: false, reason: 'reference_mismatch', ...base };
  }
  return { verified: true, reason: 'verified', ...base };
}
