/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "rgb(var(--atlas-base) / <alpha-value>)",
        surface: "rgb(var(--atlas-surface) / <alpha-value>)",
        panel: "rgb(var(--atlas-panel) / <alpha-value>)",
        raised: "rgb(var(--atlas-raised) / <alpha-value>)",
        border: "rgb(var(--atlas-border) / <alpha-value>)",
        "border-strong": "rgb(var(--atlas-border-strong) / <alpha-value>)",
        accent: "rgb(var(--atlas-accent) / <alpha-value>)",
        "accent-dim": "rgb(var(--atlas-accent-dim) / <alpha-value>)",
        "on-accent": "rgb(var(--atlas-on-accent) / <alpha-value>)",
        cyan: "rgb(var(--atlas-cyan) / <alpha-value>)",
        ink: "rgb(var(--atlas-ink) / <alpha-value>)",
        muted: "rgb(var(--atlas-muted) / <alpha-value>)",
        critical: "rgb(var(--atlas-critical) / <alpha-value>)",
        high: "rgb(var(--atlas-high) / <alpha-value>)",
        medium: "rgb(var(--atlas-medium) / <alpha-value>)",
        low: "rgb(var(--atlas-low) / <alpha-value>)",
        info: "rgb(var(--atlas-info) / <alpha-value>)",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        "2xs": ["0.68rem", { lineHeight: "1rem" }],
      },
      boxShadow: {
        panel: "var(--atlas-shadow)",
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
