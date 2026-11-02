/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0B0F14",
        surface: "#111821",
        panel: "#151D27",
        raised: "#1A2430",
        border: "#243140",
        "border-strong": "#2F4052",
        accent: "#36D399",
        "accent-dim": "#1F8F68",
        cyan: "#38BDF8",
        ink: "#E5E7EB",
        muted: "#8995A5",
        critical: "#F87171",
        high: "#FB923C",
        medium: "#FBBF24",
        low: "#38BDF8",
        info: "#94A3B8",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        "2xs": ["0.68rem", { lineHeight: "1rem" }],
      },
      boxShadow: {
        panel: "0 1px 0 rgba(255,255,255,0.03) inset, 0 8px 24px rgba(0,0,0,0.28)",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "fade-in": "fade-in 160ms ease-out",
        shimmer: "shimmer 1.6s infinite",
      },
    },
  },
  plugins: [],
};
