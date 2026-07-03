import type { ReactNode } from "react";

export function Section({
  icon,
  title,
  hint,
  defaultOpen = false,
  children,
}: {
  icon?: ReactNode;
  title: string;
  hint?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  return (
    <details
      open={defaultOpen}
      className="group overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm shadow-slate-900/5 backdrop-blur transition-colors open:border-slate-300 hover:border-slate-300 dark:border-white/10 dark:bg-white/3 dark:open:border-white/20 dark:hover:border-white/20"
    >
      <summary className="flex cursor-pointer list-none items-center gap-3 px-5 py-4 marker:content-['']">
        {icon != null && (
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-base dark:bg-white/10">
            {icon}
          </span>
        )}
        <span className="min-w-0 flex-1">
          <span className="block truncate font-semibold text-slate-900 dark:text-slate-50">
            {title}
          </span>
          {hint != null && (
            <span className="mt-0.5 block truncate text-xs text-slate-500 dark:text-slate-400">
              {hint}
            </span>
          )}
        </span>
        <svg
          className="h-5 w-5 shrink-0 text-slate-400 transition-transform duration-200 group-open:rotate-180"
          viewBox="0 0 20 20"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M5 7.5 10 12.5 15 7.5" />
        </svg>
      </summary>
      <div className="border-t border-slate-200/70 px-5 py-4 dark:border-white/10">
        {children}
      </div>
    </details>
  );
}
