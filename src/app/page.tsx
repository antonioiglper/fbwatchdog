"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import type { AnalysisResult } from "@/lib/analyze";
import { Section } from "@/components/Section";

export default function Home() {
  const [domainInput, setDomainInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domainInput.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainInput }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Error during analysis");
      } else {
        setResult(data);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch domain");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-10 sm:px-8 sm:py-14">
      {/* Hero */}
      <section className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1 text-xs font-medium text-slate-600 shadow-sm dark:border-white/10 dark:bg-white/5 dark:text-slate-300">
          <span className="h-1.5 w-1.5 rounded-full bg-indigo-500" />
          E-commerce due diligence
        </span>
        <h1 className="mt-5 text-4xl font-bold tracking-tight text-slate-900 sm:text-5xl dark:text-white">
          Spot fraudulent stores{" "}
          <span className="bg-gradient-to-r from-indigo-500 to-sky-500 bg-clip-text text-transparent">
            before you buy
          </span>
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-base text-slate-600 sm:text-lg dark:text-slate-400">
          Enter any e-commerce domain to scan it for fraud indicators, suspicious
          patterns, and compliance red flags — in seconds.
        </p>
      </section>

      {/* Search */}
      <form
        onSubmit={handleSubmit}
        className="mx-auto mt-8 flex w-full max-w-2xl flex-col gap-3 rounded-2xl border border-slate-200/80 bg-white/80 p-2 shadow-lg shadow-slate-900/5 backdrop-blur sm:flex-row sm:items-center dark:border-white/10 dark:bg-white/5"
      >
        <div className="flex flex-1 items-center gap-2 pl-3">
          <svg className="h-5 w-5 shrink-0 text-slate-400" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="9" cy="9" r="6.25" />
            <path d="m14 14 3.5 3.5" />
          </svg>
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="example.com"
            className="w-full bg-transparent py-2.5 text-slate-900 placeholder:text-slate-400 focus:outline-none dark:text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-sky-500 px-6 py-2.5 font-semibold text-white shadow-md shadow-indigo-500/25 transition hover:shadow-lg hover:shadow-indigo-500/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? (
            <>
              <Spinner />
              Analyzing…
            </>
          ) : (
            "Analyze"
          )}
        </button>
      </form>

      {error && (
        <div className="mx-auto mt-6 flex max-w-2xl items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200">
          <span className="text-base leading-none">❌</span>
          <span>{error}</span>
        </div>
      )}

      {loading && !result && <LoadingSkeleton />}

      {result && (
        <div className="mt-10 space-y-4">
          <Verdict result={result} />

          {result.errors?.length ? (
            <Alert tone="warning">
              <p className="font-semibold">Partial analysis completed</p>
              <ul className="mt-1.5 list-inside list-disc space-y-0.5 text-sm">
                {result.errors.map((message) => (
                  <li key={message}>{message}</li>
                ))}
              </ul>
            </Alert>
          ) : null}

          <Section
            icon="📅"
            title="Domain Age Analysis"
            hint="How long the domain has existed"
            defaultOpen
          >
            {"error" in result.domainAge ? (
              <Alert tone="warning">
                Could not fetch domain info: {result.domainAge.error}
              </Alert>
            ) : (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <Metric label="Created" value={result.domainAge.created.slice(0, 10)} />
                <Metric label="Age" value={`${result.domainAge.ageMonths} months`} />
                <Metric label="Risk Level" value={result.domainAge.risk} />
              </div>
            )}
          </Section>

          <Section icon="📧" title="Contact Information" hint="Emails & phone numbers on the site">
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
              <div>
                <p className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                  Emails found
                </p>
                {result.emails.length ? (
                  <ChipList items={result.emails.slice(0, 10)} />
                ) : (
                  <Alert tone="info">No emails found</Alert>
                )}
              </div>
              <div>
                <p className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                  Phone numbers found
                </p>
                {result.phones.length ? (
                  <ChipList items={result.phones.slice(0, 10)} />
                ) : (
                  <Alert tone="info">No phone numbers found</Alert>
                )}
              </div>
            </div>
          </Section>

          <Section icon="🛍️" title="Platform Detection" hint="Underlying store technology">
            {result.isShopify ? (
              <Alert tone="success">Shopify store detected</Alert>
            ) : (
              <Alert tone="info">Not a Shopify store (or not detectable)</Alert>
            )}
          </Section>

          <Section icon="📋" title="Terms & Policies" hint="Published legal & store policies">
            {result.policyLinks.length ? (
              <>
                <p className="mb-2 text-sm text-slate-600 dark:text-slate-400">
                  Found {result.policyLinks.length} policy link
                  {result.policyLinks.length === 1 ? "" : "s"}:
                </p>
                <ul className="space-y-1.5">
                  {result.policyLinks.map((link) => (
                    <li key={link}>
                      <LinkRow href={link} />
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <Alert tone="warning">No policy links found</Alert>
            )}
          </Section>

          <Section icon="⚠️" title="Return Policy Red Flags" hint="Risky phrases in return policies">
            {result.policyLinks.length ? (
              result.redFlags.length ? (
                <ul className="space-y-2">
                  {result.redFlags.map(({ flag, link }, i) => (
                    <li key={`${flag}-${link}-${i}`}>
                      <Alert tone="warning">
                        Found <em className="font-semibold">&lsquo;{flag}&rsquo;</em> in{" "}
                        <a href={link} target="_blank" rel="noopener noreferrer" className="font-medium underline underline-offset-2">
                          {link}
                        </a>
                      </Alert>
                    </li>
                  ))}
                </ul>
              ) : (
                <Alert tone="success">No risky return policy phrases detected</Alert>
              )
            ) : (
              <Alert tone="info">No policies to analyze</Alert>
            )}
          </Section>

          <Section icon="⭐" title="Trustpilot Profile" hint="External reputation signal">
            {result.trustpilot.exists ? (
              <div className="space-y-3">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <Metric label="Trust Score" value={String(result.trustpilot.trustscore ?? "N/A")} />
                  <Metric label="Reviews" value={String(result.trustpilot.reviews ?? "N/A")} />
                  <a
                    href={result.trustpilot.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-3 py-3 text-center text-sm font-semibold text-slate-800 transition hover:bg-slate-100 dark:border-white/10 dark:bg-white/5 dark:text-slate-200 dark:hover:bg-white/10"
                  >
                    View on Trustpilot
                    <svg className="h-4 w-4" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M7 5h8v8M15 5 5 15" />
                    </svg>
                  </a>
                </div>
                {typeof result.trustpilot.trustscore === "number" && result.trustpilot.trustscore < 3 && (
                  <Alert tone="danger">Low TrustScore detected — possible scam indicator</Alert>
                )}
              </div>
            ) : (
              <Alert tone="warning">{result.trustpilot.reason}</Alert>
            )}
          </Section>

          <Section icon="🚨" title="Advanced Fraud Indicators" hint="Deep checks on Terms of Service">
            {result.fraud.hasTosText ? (
              <div className="space-y-2">
                {result.fraud.fakeUkAddresses.length > 0 && (
                  <Alert tone="danger">
                    <p className="font-semibold">Fake UK address indicators found</p>
                    <ul className="mt-1 list-inside list-disc text-sm">
                      {result.fraud.fakeUkAddresses.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </Alert>
                )}
                {result.fraud.missingCompanyNumber && (
                  <Alert tone="danger">Company claims UK presence but no registration number found</Alert>
                )}
                {result.fraud.vatIssue && <Alert tone="danger">VAT issue detected: {result.fraud.vatIssue}</Alert>}
                {result.fraud.usLlcStates.length > 0 && (
                  <Alert tone="danger">U.S. LLC jurisdiction detected: {result.fraud.usLlcStates.join(", ")}</Alert>
                )}
                {!result.fraud.fakeUkAddresses.length &&
                  !result.fraud.missingCompanyNumber &&
                  !result.fraud.vatIssue &&
                  !result.fraud.usLlcStates.length && (
                    <Alert tone="success">No major fraud indicators detected</Alert>
                  )}
              </div>
            ) : (
              <Alert tone="info">No Terms of Service found for analysis</Alert>
            )}
          </Section>
        </div>
      )}

      {!result && !loading && (
        <p className="mx-auto mt-10 max-w-2xl text-center text-sm text-slate-500 dark:text-slate-500">
          💡 <strong className="font-semibold">Tip:</strong> Enter an e-commerce domain to
          scan it for fraud indicators, compliance issues, and red flags.
        </p>
      )}
    </main>
  );
}

/* ---------- Verdict summary ---------- */

function Verdict({ result }: { result: AnalysisResult }) {
  let dangers = 0;
  let warnings = 0;

  if (result.fraud.hasTosText) {
    if (result.fraud.fakeUkAddresses.length) dangers++;
    if (result.fraud.missingCompanyNumber) dangers++;
    if (result.fraud.vatIssue) dangers++;
    if (result.fraud.usLlcStates.length) dangers++;
  }
  if (result.trustpilot.exists && typeof result.trustpilot.trustscore === "number" && result.trustpilot.trustscore < 3) dangers++;
  if (result.redFlags.length) warnings += result.redFlags.length;
  if (!result.policyLinks.length) warnings++;
  if (!("error" in result.domainAge) && result.domainAge.ageMonths < 3) warnings++;

  const level = dangers > 0 ? "danger" : warnings > 0 ? "warning" : "clear";

  const config = {
    danger: {
      label: "High risk",
      emoji: "🚨",
      blurb: "Multiple fraud indicators detected — proceed with extreme caution.",
      ring: "from-red-500/15 to-red-500/5 border-red-300 dark:border-red-500/30",
      badge: "bg-red-500 text-white",
    },
    warning: {
      label: "Caution advised",
      emoji: "⚠️",
      blurb: "Some warning signs found — review the details below before trusting this store.",
      ring: "from-amber-400/15 to-amber-400/5 border-amber-300 dark:border-amber-500/30",
      badge: "bg-amber-500 text-white",
    },
    clear: {
      label: "No major flags",
      emoji: "✅",
      blurb: "No major fraud indicators detected. Always combine with your own judgement.",
      ring: "from-emerald-400/15 to-emerald-400/5 border-emerald-300 dark:border-emerald-500/30",
      badge: "bg-emerald-500 text-white",
    },
  }[level];

  return (
    <div className={`rounded-2xl border bg-gradient-to-br ${config.ring} p-5 shadow-sm`}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/70 text-2xl shadow-sm dark:bg-white/10">
            {config.emoji}
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${config.badge}`}>
                {config.label}
              </span>
              <span className="font-mono text-sm text-slate-500 dark:text-slate-400">
                {result.domain}
              </span>
            </div>
            <p className="mt-1.5 max-w-xl text-sm text-slate-700 dark:text-slate-300">
              {config.blurb}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Stat count={dangers} label="Critical" tone="danger" />
          <Stat count={warnings} label="Warnings" tone="warning" />
        </div>
      </div>
    </div>
  );
}

function Stat({ count, label, tone }: { count: number; label: string; tone: "danger" | "warning" }) {
  const color =
    tone === "danger"
      ? "text-red-600 dark:text-red-400"
      : "text-amber-600 dark:text-amber-400";
  return (
    <div className="min-w-[76px] rounded-xl border border-slate-200/70 bg-white/70 px-3 py-2 text-center dark:border-white/10 dark:bg-white/5">
      <p className={`text-2xl font-bold tabular-nums ${count > 0 ? color : "text-slate-400 dark:text-slate-500"}`}>
        {count}
      </p>
      <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
    </div>
  );
}

/* ---------- Building blocks ---------- */

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-slate-50/60 px-4 py-3 dark:border-white/10 dark:bg-white/5">
      <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
      <p className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{value}</p>
    </div>
  );
}

function ChipList({ items }: { items: string[] }) {
  return (
    <ul className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <li
          key={item}
          className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 font-mono text-xs text-slate-700 dark:border-white/10 dark:bg-white/5 dark:text-slate-300"
        >
          {item}
        </li>
      ))}
    </ul>
  );
}

function LinkRow({ href }: { href: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="group flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-sm text-slate-700 transition hover:border-indigo-300 hover:bg-indigo-50/50 dark:border-white/10 dark:bg-white/5 dark:text-slate-300 dark:hover:border-indigo-500/40 dark:hover:bg-indigo-500/10"
    >
      <svg className="h-4 w-4 shrink-0 text-slate-400 group-hover:text-indigo-500" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        <path d="M8 12a3 3 0 0 0 4.24 0l2.5-2.5a3 3 0 1 0-4.24-4.24l-.7.7" />
        <path d="M12 8a3 3 0 0 0-4.24 0l-2.5 2.5a3 3 0 1 0 4.24 4.24l.7-.7" />
      </svg>
      <span className="truncate">{href}</span>
    </a>
  );
}

const TONES = {
  info: "border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-200",
  success: "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200",
  warning: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200",
  danger: "border-red-200 bg-red-50 text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-200",
} as const;

const TONE_ICONS = {
  info: "ℹ️",
  success: "✅",
  warning: "⚠️",
  danger: "🚨",
} as const;

function Alert({ tone, children }: { tone: keyof typeof TONES; children: ReactNode }) {
  return (
    <div className={`flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-sm ${TONES[tone]}`}>
      <span className="mt-px text-sm leading-none">{TONE_ICONS[tone]}</span>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

function Spinner() {
  return (
    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 0 1 8-8V0C5.4 0 0 5.4 0 12h4z" />
    </svg>
  );
}

function LoadingSkeleton() {
  return (
    <div className="mt-10 space-y-4">
      <div className="h-24 animate-pulse rounded-2xl border border-slate-200/80 bg-white/60 dark:border-white/10 dark:bg-white/5" />
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className="h-16 animate-pulse rounded-2xl border border-slate-200/80 bg-white/60 dark:border-white/10 dark:bg-white/5"
        />
      ))}
    </div>
  );
}
