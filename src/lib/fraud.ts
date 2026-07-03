import {
  FAKE_UK_ADDRESS_PATTERNS,
  MISSING_COMPANY_NUMBER_REQUIRED_TERMS,
  UK_POSTCODE_REGEX,
  VAT_REGEX,
  US_STATES,
} from "./constants";

export function detectFakeUkAddresses(text: string): string[] {
  const lower = text.toLowerCase();
  const found = FAKE_UK_ADDRESS_PATTERNS.filter((pattern) => lower.includes(pattern));

  const mentionsUk = lower.includes("united kingdom") || lower.includes("uk");
  if (mentionsUk && !UK_POSTCODE_REGEX.test(lower)) {
    found.push("missing_valid_uk_postcode");
  }
  return found;
}

export function detectMissingCompanyNumber(text: string): boolean {
  const lower = text.toLowerCase();
  const claimsUk = lower.includes("united kingdom") || lower.includes("uk") || lower.includes("england");
  if (!claimsUk) return false;
  return !MISSING_COMPANY_NUMBER_REQUIRED_TERMS.some((term) => lower.includes(term));
}

export function detectVatFraud(text: string): string | null {
  const lower = text.toLowerCase();
  if (!lower.includes("vat")) return null;
  if (!VAT_REGEX.test(lower)) return "vat_claimed_but_no_valid_number";
  if (lower.includes("000000000")) return "fake_vat_number";
  return null;
}

export function detectUsLlcPatterns(text: string): string[] {
  const lower = text.toLowerCase();
  if (!lower.includes("llc")) return [];
  return US_STATES.filter((state) => lower.includes(state));
}
