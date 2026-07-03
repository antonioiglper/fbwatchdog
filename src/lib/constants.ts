export const US_STATES = [
  "alabama", "alaska", "arizona", "arkansas", "california", "colorado",
  "connecticut", "delaware", "florida", "georgia", "hawaii", "idaho",
  "illinois", "indiana", "iowa", "kansas", "kentucky", "louisiana",
  "maine", "maryland", "massachusetts", "michigan", "minnesota", "mississippi",
  "missouri", "montana", "nebraska", "nevada", "new hampshire", "new jersey",
  "new mexico", "new york", "north carolina", "north dakota", "ohio",
  "oklahoma", "oregon", "pennsylvania", "rhode island", "south carolina",
  "south dakota", "tennessee", "texas", "utah", "vermont", "virginia",
  "washington", "west virginia", "wisconsin", "wyoming",
];

export const POLICY_KEYWORDS = [
  "refund", "return", "returns", "reembolso", "devolución",
  "terms", "terminos", "devoluciones", "service", "servicio",
];

export const RETURN_RED_FLAGS = [
  "return to asia", "return to china", "return to hong kong",
  "return to singapore", "return to warehouse in",
  "customer pays return shipping", "return shipping is not free",
  "return shipping fee", "international return", "restocking fee",
  "non-refundable", "buyer is responsible for return shipping",
  "los gastos de devolución corren por cuenta del cliente",
  "devolución no gratuita", "envío de devolución no incluido", "en asia", "in asia",
];

export const FAKE_UK_ADDRESS_PATTERNS = [
  "london ec1v", "27 old gloucester", "71-75 shelton street",
  "kemp house", "virtual office", "mailbox", "po box", "unit", "suite", "warehouse",
];

export const MISSING_COMPANY_NUMBER_REQUIRED_TERMS = [
  "company number", "registered in england", "registered in scotland",
  "companies house", "crn",
];

export const SHOPIFY_SIGNALS = [
  "cdn.shopify.com", "shopifyassets", "x-shopify",
  "shopify-checkout-api", "shopify.theme", "shopify",
];

export const UK_POSTCODE_REGEX = /\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b/i;
export const VAT_REGEX = /\b(gb)?\d{9}\b/;
export const PHONE_REGEX = /(\+\d{1,3}\s?)?((\(\d{3}\)\s?)|(\d{3}[-.\s]?))?\d{3}[-.\s]?\d{4}/g;
export const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
