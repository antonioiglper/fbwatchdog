import * as cheerio from "cheerio";
import { fetchWithTimeout } from "./http";
import { extractText } from "./extractText";
import { getDomainAgeReport, type DomainAgeResult } from "./domainAge";
import { scanTrustpilot, type TrustpilotResult } from "./trustpilot";
import { extractShopifyPoliciesFallback, detectReturnRedFlags, type RedFlagHit } from "./policies";
import {
  detectFakeUkAddresses,
  detectMissingCompanyNumber,
  detectVatFraud,
  detectUsLlcPatterns,
} from "./fraud";
import { SHOPIFY_SIGNALS, PHONE_REGEX, EMAIL_REGEX } from "./constants";

export interface AnalysisResult {
  domain: string;
  domainAge: DomainAgeResult;
  emails: string[];
  phones: string[];
  isShopify: boolean;
  policyLinks: string[];
  redFlags: RedFlagHit[];
  trustpilot: TrustpilotResult;
  fraud: {
    hasTosText: boolean;
    fakeUkAddresses: string[];
    missingCompanyNumber: boolean;
    vatIssue: string | null;
    usLlcStates: string[];
  };
  errors?: string[];
}

function normalizeDomainInput(input: string): { domain: string; url: string } {
  let domain = input.trim().toLowerCase().replace(/^www\./, "");
  let url: string;
  if (!domain.startsWith("http")) {
    url = `https://${domain}`;
  } else {
    url = domain;
    domain = new URL(url).hostname.replace(/^www\./, "");
  }
  return { domain, url };
}

async function detectShopify(url: string, html: string): Promise<boolean> {
  const lowerHtml = html.toLowerCase();
  if (SHOPIFY_SIGNALS.some((sig) => lowerHtml.includes(sig))) return true;

  try {
    const cartRes = await fetchWithTimeout(`${url.replace(/\/$/, "")}/cart.js`, { timeoutMs: 5_000 });
    if (cartRes.ok) {
      const text = await cartRes.text();
      if (text.includes("items")) return true;
    }
  } catch {
    // ignore
  }
  return false;
}

async function getShopifyPolicyLinks(url: string, $: cheerio.CheerioAPI): Promise<string[]> {
  try {
    const res = await fetchWithTimeout(`${url.replace(/\/$/, "")}/policies.json`);
    if (!res.ok) throw new Error(`policies.json returned ${res.status}`);
    const data = await res.json();
    const policies: Array<{ url: string }> = data?.policies ?? [];
    if (!policies.length) throw new Error("Empty policies.json");
    return policies.map((p) => p.url);
  } catch {
    return extractShopifyPoliciesFallback(url, $);
  }
}

function buildFraudReport(tosText: string) {
  return tosText
    ? {
        hasTosText: true,
        fakeUkAddresses: detectFakeUkAddresses(tosText),
        missingCompanyNumber: detectMissingCompanyNumber(tosText),
        vatIssue: detectVatFraud(tosText),
        usLlcStates: detectUsLlcPatterns(tosText),
      }
    : {
        hasTosText: false,
        fakeUkAddresses: [],
        missingCompanyNumber: false,
        vatIssue: null,
        usLlcStates: [],
      };
}

export async function analyzeDomain(rawInput: string): Promise<AnalysisResult> {
  const { domain, url } = normalizeDomainInput(rawInput);
  const errors: string[] = [];

  let html = "";
  let $: cheerio.CheerioAPI | null = null;
  let text = "";

  try {
    const response = await fetchWithTimeout(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch domain: HTTP ${response.status}`);
    }
    html = await response.text();
    $ = cheerio.load(html);
    text = extractText($);
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
  }

  const [domainAge, isShopify, trustpilot] = await Promise.allSettled([
    getDomainAgeReport(domain),
    html ? detectShopify(url, html) : Promise.resolve(false),
    scanTrustpilot(domain),
  ]);

  const resolvedDomainAge =
    domainAge.status === "fulfilled"
      ? domainAge.value
      : { error: `Domain age lookup failed: ${domainAge.reason instanceof Error ? domainAge.reason.message : String(domainAge.reason)}` };
  const resolvedIsShopify = isShopify.status === "fulfilled" ? isShopify.value : false;
  const resolvedTrustpilot: TrustpilotResult =
    trustpilot.status === "fulfilled"
      ? trustpilot.value
      : { exists: false, reason: `Trustpilot lookup failed: ${trustpilot.reason instanceof Error ? trustpilot.reason.message : String(trustpilot.reason)}` };

  if (domainAge.status === "rejected") {
    errors.push(`Domain age lookup failed: ${domainAge.reason instanceof Error ? domainAge.reason.message : String(domainAge.reason)}`);
  }
  if (isShopify.status === "rejected") {
    errors.push(`Shopify detection failed: ${isShopify.reason instanceof Error ? isShopify.reason.message : String(isShopify.reason)}`);
  }
  if (trustpilot.status === "rejected") {
    errors.push(`Trustpilot lookup failed: ${trustpilot.reason instanceof Error ? trustpilot.reason.message : String(trustpilot.reason)}`);
  }

  const emails = Array.from(new Set(text.match(EMAIL_REGEX) ?? []));
  const phones = Array.from(new Set(text.match(PHONE_REGEX) ?? [])).filter((p) => p.trim().length > 0);

  let policyLinks: string[] = [];
  let redFlags: RedFlagHit[] = [];
  let tosText = "";

  if ($ && resolvedIsShopify) {
    policyLinks = await getShopifyPolicyLinks(url, $);
    redFlags = policyLinks.length ? await detectReturnRedFlags(policyLinks) : [];

    const tosLinks = policyLinks.filter(
      (link) => link.toLowerCase().includes("terms") || link.toLowerCase().includes("terminos")
    );

    if (tosLinks.length) {
      try {
        const res = await fetchWithTimeout(tosLinks[0]);
        if (res.ok) {
          tosText = extractText(cheerio.load(await res.text())).toLowerCase();
        }
      } catch {
        // ignore, leave tosText empty
      }
    }
  }

  const fraud = buildFraudReport(tosText);

  return {
    domain,
    domainAge: resolvedDomainAge,
    emails,
    phones,
    isShopify: resolvedIsShopify,
    policyLinks,
    redFlags,
    trustpilot: resolvedTrustpilot,
    fraud,
    ...(errors.length ? { errors } : {}),
  };
}
