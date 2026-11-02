import { useMemo } from "react";
import { NavLink } from "react-router-dom";
import {
  Activity,
  Bell,
  Boxes,
  BrainCircuit,
  ChevronLeft,
  Crosshair,
  FileBarChart2,
  Gauge,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Plug,
  ScanSearch,
  ServerCog,
  Settings,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Users,
  Waypoints,
  X,
} from "lucide-react";
import { cn } from "@/utils";
import { useAuth } from "@/context/AuthContext";

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  permission?: string;
  badge?: "findings";
}

interface NavSection {
  label: string;
  items: NavItem[];
}

const SECTIONS: NavSection[] = [
  {
    label: "Overview",
    items: [{ to: "/", label: "Command Center", icon: LayoutDashboard, permission: "dashboard:read" }],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/assets", label: "Asset Intelligence", icon: ServerCog, permission: "assets:read" },
      { to: "/microservices", label: "Microservice Map", icon: Waypoints, permission: "microservices:read" },
      { to: "/sbom", label: "SBOM Intelligence", icon: Boxes, permission: "sbom:read" },
      { to: "/ai-triage", label: "AI Triage", icon: BrainCircuit, permission: "findings:triage" },
      { to: "/attack-surface", label: "Attack Surface", icon: Crosshair, permission: "scans:read" },
      { to: "/api-inventory", label: "API Inventory", icon: GitBranch, permission: "apis:read" },
      { to: "/data-classification", label: "Data Classification", icon: ShieldCheck, permission: "classification:read" },
    ],
  },
  {
    label: "Security Operations",
    items: [
      { to: "/vulnerabilities", label: "Vulnerability Management", icon: ShieldAlert, permission: "findings:read" },
      { to: "/risk-management", label: "Risk Management", icon: TriangleAlert, permission: "risks:read" },
      { to: "/notifications", label: "Notifications", icon: Bell, permission: "notifications:read" },
      { to: "/scan-management", label: "Scan Management", icon: ScanSearch, permission: "scans:read" },
    ],
  },
  {
    label: "Reporting",
    items: [
      { to: "/executive", label: "Executive Intelligence", icon: Gauge, permission: "executive:read" },
      { to: "/reports", label: "Security Reports", icon: FileBarChart2, permission: "reports:read" },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug, permission: "integrations:read" },
      { to: "/users", label: "User Management", icon: Users, permission: "users:read" },
      { to: "/rbac", label: "RBAC", icon: KeyRound, permission: "users:read" },
      { to: "/settings", label: "Organization Settings", icon: Settings, permission: "settings:read" },
      { to: "/system", label: "System Configuration", icon: Activity, permission: "settings:read" },
    ],
  },
];

export function Sidebar({
  collapsed,
  onToggle,
  mobileOpen,
  onCloseMobile,
}: {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}) {
  const { can, user } = useAuth();

  const sections = useMemo(
    () =>
      SECTIONS.map((section) => ({
        ...section,
        items: section.items.filter((item) => !item.permission || can(item.permission)),
      })).filter((section) => section.items.length > 0),
    [can],
  );

  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border bg-surface/95 backdrop-blur transition-[width,transform] duration-200",
        collapsed ? "w-[62px]" : "w-[236px]",
        mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
      )}
    >
      <div className={cn("flex h-14 items-center border-b border-border px-3", collapsed ? "justify-center" : "justify-between")}>
        <div className="flex items-center gap-2.5 overflow-hidden">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded border border-accent/30 bg-accent/10">
            <ShieldCheck className="h-4 w-4 text-accent" />
          </div>
          {!collapsed ? (
            <div className="leading-tight">
              <p className="text-sm font-bold tracking-[0.18em] text-ink">ATLAS</p>
              <p className="text-[9px] uppercase tracking-[0.08em] text-muted">Security Orchestration</p>
            </div>
          ) : null}
        </div>
        {!collapsed ? (
          <button
            onClick={() => (mobileOpen && onCloseMobile ? onCloseMobile() : onToggle())}
            className="rounded p-1 text-muted hover:bg-raised hover:text-ink"
            aria-label={mobileOpen ? "Close navigation" : "Collapse navigation"}
          >
            {mobileOpen ? <X className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        ) : null}
      </div>

      <nav className="scrollbar-thin flex-1 overflow-y-auto px-2 py-3">
        {sections.map((section) => (
          <div key={section.label} className="mb-4">
            {!collapsed ? <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted/60">{section.label}</p> : null}
            <div className="space-y-0.5">
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  title={collapsed ? item.label : undefined}
                  onClick={onCloseMobile}
                  className={({ isActive }) =>
                    cn(
                      "group flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] transition-colors",
                      isActive
                        ? "bg-accent/10 text-ink shadow-[inset_2px_0_0_0_rgb(var(--atlas-accent))]"
                        : "text-muted hover:bg-raised/70 hover:text-ink",
                      collapsed && "justify-center px-0",
                    )
                  }
                >
                  <item.icon className="h-4 w-4 shrink-0" />
                  {!collapsed ? <span className="truncate">{item.label}</span> : null}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className={cn("border-t border-border p-2.5", collapsed && "flex justify-center")}>
        {collapsed ? (
          <button onClick={onToggle} className="rounded p-1.5 text-muted hover:bg-raised hover:text-ink" aria-label="Expand navigation">
            <Activity className="h-4 w-4" />
          </button>
        ) : (
          <div className="flex items-center gap-2 rounded-md border border-border bg-base/60 px-2.5 py-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-40" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
            </span>
            <div className="min-w-0 leading-tight">
              <p className="truncate text-2xs font-medium text-ink">ATLAS Online</p>
              <p className="truncate text-[10px] text-muted">{user?.role_labels?.[0] || "Authenticated"}</p>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
