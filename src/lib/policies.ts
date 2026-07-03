import * as cheerio from "cheerio";
import type { CheerioAPI } from "cheerio";
import { fetchWithTimeout } from "./http";
import { extractText } from "./extractText";
import { POLICY_KEYWORDS, RETURN_RED_FLAGS } from "./constants";

export function extractShopifyPoliciesFallback(baseUrl: string, $: CheerioAPI): string[] {
  const links = new Set<string>();
  $("a[href]").each((_, el) => {
    const href = ($(el).attr("href") ?? "").toLowerCase();
    const text = $(el).text().trim().toLowerCase();
    if (POLICY_KEYWORDS.some((k) => href.includes(k) || text.includes(k))) {
      try {
        links.add(new URL($(el).attr("href")!, baseUrl).toString());
      } catch {
        // ignore unparsable hrefs (mailto:, javascript:, etc.)
      }
    }
  });
  return Array.from(links);
}

export interface RedFlagHit {
  flag: string;
  link: string;
}

export async function detectReturnRedFlags(policyLinks: string[]): Promise<RedFlagHit[]> {
  const results = await Promise.all(
    policyLinks.map(async (link) => {
      try {
        const res = await fetchWithTimeout(link);
        if (!res.ok) return [];
        const html = await res.text();
        const text = extractText(cheerio.load(html)).toLowerCase();
        return RETURN_RED_FLAGS.filter((flag) => text.includes(flag)).map((flag) => ({
          flag,
          link,
        }));
      } catch {
        return [];
      }
    })
  );
  return results.flat();
}
