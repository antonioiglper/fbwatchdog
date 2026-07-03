import { NextResponse } from "next/server";
import { analyzeDomain } from "@/lib/analyze";

export async function POST(request: Request) {
  let domain: unknown;
  try {
    const body = await request.json();
    domain = body?.domain;
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  if (typeof domain !== "string" || !domain.trim()) {
    return NextResponse.json({ error: "Domain is required" }, { status: 400 });
  }

  try {
    const result = await analyzeDomain(domain);
    return NextResponse.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error during analysis";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
