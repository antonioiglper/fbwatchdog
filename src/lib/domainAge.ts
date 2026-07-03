import { domain as whoisDomain, type WhoisSearchResult } from "whoiser";

export interface DomainAgeReport {
  created: string;
  ageDays: number;
  ageMonths: number;
  ageYears: number;
  risk: string;
}

export type DomainAgeResult = DomainAgeReport | { error: string };

function classifyRisk(ageMonths: number): string {
  if (ageMonths < 1) return "⚠️ Extremely new domain — very high risk";
  if (ageMonths < 3) return "⚠️ New domain — suspicious for Shopify stores";
  if (ageMonths < 12) return "🟡 Moderately new — check other signals";
  return "🟢 Established domain — low age‑related risk";
}

export async function getDomainAgeReport(domain: string): Promise<DomainAgeResult> {
  try {
    const results = await whoisDomain(domain, { follow: 1, timeout: 15_000 });
    const record = Object.values(results)[0] as WhoisSearchResult | undefined;
    if (!record || typeof record.error === "string") {
      throw new Error("No WHOIS record found");
    }

    const createdRaw = record["Created Date"];
    const createdValue = Array.isArray(createdRaw) ? createdRaw[0] : createdRaw;
    if (!createdValue || typeof createdValue !== "string") {
      throw new Error("WHOIS record missing creation date");
    }

    const created = new Date(createdValue);
    if (Number.isNaN(created.getTime())) {
      throw new Error(`Could not parse creation date: ${createdValue}`);
    }

    const ageDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
    const ageMonths = ageDays / 30.44;
    const ageYears = ageDays / 365.25;

    return {
      created: created.toISOString(),
      ageDays,
      ageMonths: Math.round(ageMonths * 10) / 10,
      ageYears: Math.round(ageYears * 100) / 100,
      risk: classifyRisk(ageMonths),
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}
