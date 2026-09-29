const FORBIDDEN_KEYS = new Set([
  'pan',
  'cvv',
  'cvc',
  'cid',
  'cardnumber',
  'primaryaccountnumber',
  'track1',
  'track2',
  'trackdata',
  'magstripe',
]);

export function containsCardData(value: unknown): boolean {
  return walk(value);
}

function walk(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) => walk(entry));
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([key, child]) => {
      const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      return FORBIDDEN_KEYS.has(normalized) || walk(child);
    });
  }
  return typeof value === 'string' && (looksLikePan(value) || looksLikeTrack(value));
}

function looksLikePan(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) {
    return false;
  }
  return luhn(digits);
}

function looksLikeTrack(value: string): boolean {
  return value.startsWith('%B') || /;\d{12,19}=\d{4}/.test(value);
}

function luhn(digits: string): boolean {
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (alternate) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}
