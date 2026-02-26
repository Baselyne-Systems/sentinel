"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "⬡" },
  { href: "/graph", label: "Graph Explorer", icon: "◈" },
  { href: "/findings", label: "Findings", icon: "◉" },
  { href: "/scans", label: "Scans", icon: "⟳" },
  { href: "/remediations", label: "Remediations", icon: "⬢" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <nav className="flex flex-col w-52 bg-[#1a1d2e] border-r border-[#2a2d3e] py-6 gap-1 shrink-0">
      {/* Logo */}
      <div className="px-4 mb-6">
        <span className="text-xl font-bold tracking-widest text-blue-400">SENTINEL</span>
        <p className="text-xs text-slate-500 mt-0.5">Cloud Security</p>
      </div>

      {NAV_ITEMS.map(({ href, label, icon }) => (
        <Link
          key={href}
          href={href}
          className={clsx(
            "flex items-center gap-3 px-4 py-2.5 text-sm transition-colors",
            pathname === href
              ? "bg-blue-600/20 text-blue-300 border-r-2 border-blue-400"
              : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
          )}
        >
          <span className="text-base">{icon}</span>
          {label}
        </Link>
      ))}

      {/* Bottom info */}
      <div className="mt-auto px-4 pt-6 border-t border-[#2a2d3e]">
        <p className="text-xs text-slate-600">Phase 3 · Action</p>
      </div>
    </nav>
  );
}
