import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "FB Watchdog — E-Commerce Fraud Detector",
  description: "Analyze e-commerce domains for fraud indicators, suspicious patterns, and compliance issues.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="app-backdrop min-h-full flex flex-col">
        <header className="sticky top-0 z-20 border-b border-slate-200/70 bg-white/70 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/60">
          <div className="mx-auto flex w-full max-w-5xl items-center justify-between px-4 py-3 sm:px-8">
            <div className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-sky-500 text-lg shadow-sm shadow-indigo-500/30">
                🛡️
              </span>
              <div className="leading-tight">
                <p className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                  FB Watchdog
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Fraud Detection
                </p>
              </div>
            </div>
            <span className="hidden items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-500 sm:inline-flex dark:border-white/10 dark:bg-white/5 dark:text-slate-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Live analysis
            </span>
          </div>
        </header>
        {children}
      </body>
    </html>
  );
}
