import { fetchWithTimeout } from "./http";

export type TrustpilotResult =
  | {
      exists: true;
      name?: string;
      trustscore?: number;
      reviews?: number;
      url: string;
    }
  | { exists: false; reason: string };

export async function scanTrustpilot(domain: string): Promise<TrustpilotResult> {
  const apiUrl = `https://www.trustpilot.com/api/business-units/find?domain=${encodeURIComponent(domain)}`;
  try {
    const res = await fetchWithTimeout(apiUrl);
    if (!res.ok) {
      return { exists: false, reason: "No Trustpilot profile found" };
    }
    const data = await res.json();
    if (!data || !data.id) {
      return { exists: false, reason: "No Trustpilot profile found" };
    }
    return {
      exists: true,
      name: data.displayName,
      trustscore: data.trustScore,
      reviews: data.numberOfReviews,
      url: `https://www.trustpilot.com/review/${domain}`,
    };
  } catch (err) {
    return { exists: false, reason: err instanceof Error ? err.message : String(err) };
  }
}
