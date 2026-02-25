import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: "#0f1117",
          surface: "#1a1d2e",
          border: "#2a2d3e",
          text: "#e2e8f0",
          muted: "#94a3b8",
          // Node type colors
          iam: "#3b82f6",       // blue
          compute: "#f97316",   // orange
          storage: "#22c55e",   // green
          network: "#ef4444",   // red
          // Severity colors
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#ca8a04",
          low: "#2563eb",
        },
      },
    },
  },
  plugins: [],
};

export default config;
