import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "@/components/navigation/Sidebar";
import { Topbar } from "@/components/navigation/Topbar";
import { cn } from "@/utils";

export function MainLayout() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("atlas.nav.collapsed") === "true");
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    localStorage.setItem("atlas.nav.collapsed", String(collapsed));
  }, [collapsed]);

  useEffect(() => {
    setMobileOpen(false);
    window.scrollTo({ top: 0 });
  }, [location.pathname]);

  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [mobileOpen]);

  return (
    <div className="min-h-screen bg-base">
      <Sidebar
        collapsed={collapsed && !mobileOpen}
        onToggle={() => setCollapsed((value) => !value)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />
      {mobileOpen ? (
        <div className="fixed inset-0 z-[35] bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} aria-hidden />
      ) : null}
      <div className={cn("flex min-h-screen flex-col transition-[margin] duration-200", collapsed ? "lg:ml-[62px]" : "lg:ml-[236px]")}>        <Topbar onOpenNav={() => setMobileOpen(true)} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 md:px-6">
          <Outlet />
        </main>
        <footer className="border-t border-border/60 px-6 py-3">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-2 text-[10px] text-muted/70">
            <span>ATLAS · Advanced Threat &amp; Asset Lifecycle Security</span>
            <span>Unified Intelligence. Complete Visibility. Proactive Defence.</span>
          </div>
        </footer>
      </div>
    </div>
  );
}
