import type { CheerioAPI } from "cheerio";

// Equivalent of BeautifulSoup's soup.get_text(separator=" "): concatenates
// all text nodes with a space so unrelated words don't get smashed together.
export function extractText($: CheerioAPI): string {
  const parts: string[] = [];
  $("*")
    .contents()
    .each((_, node) => {
      if (node.type === "text") {
        const value = (node as unknown as { data: string }).data.trim();
        if (value) parts.push(value);
      }
    });
  return parts.join(" ");
}
