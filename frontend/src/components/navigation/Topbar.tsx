import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Bell,
  BrainCircuit,
  Boxes,
  ChevronDown,
  Crosshair,
  LayoutDashboard,
  LogOut,
  Menu,
  Search,
  ServerCog,
  Settings,
  ShieldAlert,
  ShieldCheck,
  UserCircle2,
  Waypoints,
  X,
} from "lucide-react";
import { cn, initials, relativeTime } from "@/utils";
import { useAuth } from "@/context/AuthContext";
import { useEnvironment } from "@/context/EnvironmentContext";
import { notificationApi, dashboardApi } from "@/api/endpoints";
import { Badge, Button, SeverityBadge, StatusBadge } from "@/components/ui/primitives";

const QUICK_LINKS = [
  { to: "/", label: "Command Center", icon: LayoutDashboard },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/sbom", label: "SBOM Intelligence", icon: Boxes },
  { to: "/microservices", label: "Microservice Map", icon: Waypoints },
  { to: "/ai-triage", label: "AI Triage", icon: BrainCircuit },
  { to: "/attack-surface", label: "Attack Surface", icon: Crosshair },
  { to: "/assets", label: "Asset Intelligence", icon: ServerCog },
  { to: "/executive", label: "Executive Intelligence", icon: ShieldCheck },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Topbar({ onOpenNav }: { onOpenNav: () => void }) {
  const { user, logout } = useAuth();
  const { environments, selectedEnvironmentId, setSelectedEnvironmentId } = useEnvironment();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [jobsOpen, setJobsOpen] = useState(false);

  const unread = useQuery({ queryKey: ["notifications", "unread"], queryFn: notificationApi.unread, refetchInterval: 30000 });
  const notifications = useQuery({
    queryKey: ["notifications", "recent"],
    queryFn: () => notificationApi.list({ page_size: 6 }),
    enabled: notificationsOpen,
  });
  const jobs = useQuery({ queryKey: ["dashboard", "jobs"], queryFn: dashboardApi.jobs, enabled: jobsOpen, refetchInterval: 15000 });

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen((open) => !open);
      }
      if (event.key === "Escape") {
        setSearchOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    setNotificationsOpen(false);
    setProfileOpen(false);
    setJobsOpen(false);
    setSearchOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const closeOnOutside = (event: MouseEvent) => {
      const target = event.target as Element | null;
      if (!target?.closest("[data-topbar-popover]")) {
        setNotificationsOpen(false);
        setProfileOpen(false);
        setJobsOpen(false);
      }
    };
    document.addEventListener("mousedown", closeOnOutside);
    return () => document.removeEventListener("mousedown", closeOnOutside);
  }, []);

  const results = useMemo(
    () => QUICK_LINKS.filter((link) => link.label.toLowerCase().includes(query.toLowerCase())),
    [query],
  );

  const markAll = async () => {
    await notificationApi.markAll();
    unread.refetch();
    notifications.refetch();
  };

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-base/85 px-4 backdrop-blur">
      <button onClick={onOpenNav} className="rounded p-1.5 text-muted hover:bg-raised hover:text-ink lg:hidden" aria-label="Open navigation">
        <Menu className="h-5 w-5" />
      </button>

      <button
        onClick={() => setSearchOpen(true)}
        className="flex h-8 min-w-0 w-full max-w-sm items-center gap-2 rounded-md border border-border bg-surface/80 px-2.5 text-left text-xs text-muted transition hover:border-border-strong hover:text-ink"
      >
        <Search className="h-3.5 w-3.5 shrink-0" />
        <span className="min-w-0 flex-1 truncate whitespace-nowrap">Search ATLAS…</span>
        <kbd className="hidden shrink-0 rounded border border-border bg-base px-1.5 py-0.5 text-[9px] text-muted sm:block">Ctrl K</kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <div className="hidden items-center gap-1.5 md:flex">
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface/70 px-2 py-1.5">
            <span className="text-[10px] uppercase tracking-wide text-muted">Env</span>
            <select
              value={selectedEnvironmentId}
              onChange={(event) => setSelectedEnvironmentId(event.target.value)}
              className="bg-transparent text-xs text-ink focus:outline-none"
              aria-label="Environment selector"
            >
              <option value="">All environments</option>
              {environments.map((environment) => (
                <option key={environment.id} value={environment.id}>
                  {environment.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={() => {
            setJobsOpen((open) => !open);
            setNotificationsOpen(false);
            setProfileOpen(false);
          }}
          data-topbar-popover
          className="relative rounded-md border border-border bg-surface/70 p-1.5 text-muted hover:text-ink"
          aria-label="Background jobs"
          title="Background jobs"
        >
          <Activity className="h-4 w-4" />
        </button>

        <div className="relative" data-topbar-popover>
          <button
            onClick={() => {
              setNotificationsOpen((open) => !open);
              setProfileOpen(false);
              setJobsOpen(false);
            }}
            className="relative rounded-md border border-border bg-surface/70 p-1.5 text-muted hover:text-ink"
            aria-label="Notification center"
          >
            <Bell className="h-4 w-4" />
            {(unread.data?.unread ?? 0) > 0 ? (
              <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[9px] font-bold text-base">
                {Math.min(99, unread.data!.unread)}
              </span>
            ) : null}
          </button>
          {notificationsOpen ? (
            <div className="absolute right-0 top-10 w-80 animate-fade-in overflow-hidden rounded-lg border border-border-strong bg-panel shadow-2xl">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <p className="text-xs font-semibold text-ink">Notifications</p>
                <button onClick={markAll} className="text-2xs text-muted hover:text-accent">
                  Mark all read
                </button>
              </div>
              <div className="max-h-80 overflow-y-auto">
                {(notifications.data?.items ?? []).length === 0 ? (
                  <p className="px-3 py-6 text-center text-xs text-muted">No notifications yet</p>
                ) : (
                  notifications.data!.items.map((notification) => (
                    <button
                      key={notification.id}
                      onClick={async () => {
                        await notificationApi.markRead(notification.id);
                        unread.refetch();
                        notifications.refetch();
                        if (notification.event_key.includes("dependency")) navigate("/vulnerabilities");
                      }}
                      className={cn(
                        "block w-full border-b border-border/60 px-3 py-2.5 text-left hover:bg-raised/60",
                        !notification.read_at && "bg-accent/5",
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <SeverityBadge severity={notification.severity} />
                        <span className="text-[10px] text-muted">{relativeTime(notification.created_at)}</span>
                      </div>
                      <p className="mt-1 line-clamp-1 text-xs font-medium text-ink">{notification.subject}</p>
                      <p className="line-clamp-2 text-[11px] text-muted">{notification.body}</p>
                    </button>
                  ))
                )}
              </div>
              <button onClick={() => navigate("/notifications")} className="w-full border-t border-border px-3 py-2 text-2xs text-muted hover:text-accent">
                Open notification center
              </button>
            </div>
          ) : null}
        </div>

        <div className="relative" data-topbar-popover>
          <button
            onClick={() => {
              setProfileOpen((open) => !open);
              setNotificationsOpen(false);
              setJobsOpen(false);
            }}
            className="flex items-center gap-2 rounded-md border border-border bg-surface/70 px-1.5 py-1 hover:border-border-strong"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded bg-accent/15 text-2xs font-semibold text-accent">
              {initials(user?.full_name)}
            </span>
            <span className="hidden max-w-[130px] truncate text-xs text-ink sm:block">{user?.full_name}</span>
            <ChevronDown className="h-3 w-3 text-muted" />
          </button>
          {profileOpen ? (
            <div className="absolute right-0 top-10 w-60 animate-fade-in overflow-hidden rounded-lg border border-border-strong bg-panel shadow-2xl">
              <div className="border-b border-border px-3 py-3">
                <p className="text-sm font-medium text-ink">{user?.full_name}</p>
                <p className="truncate text-2xs text-muted">{user?.email}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(user?.role_labels ?? []).map((role) => (
                    <Badge key={role} tone="border-accent/30 bg-accent/10 text-accent">
                      {role}
                    </Badge>
                  ))}
                </div>
              </div>
              <button onClick={() => navigate("/settings")} className="flex w-full items-center gap-2 px-3 py-2 text-xs text-muted hover:bg-raised hover:text-ink">
                <UserCircle2 className="h-3.5 w-3.5" /> Account & MFA
              </button>
              <button onClick={() => navigate("/system")} className="flex w-full items-center gap-2 px-3 py-2 text-xs text-muted hover:bg-raised hover:text-ink">
                <Settings className="h-3.5 w-3.5" /> System configuration
              </button>
              <button
                onClick={async () => {
                  await logout();
                  navigate("/login");
                }}
                className="flex w-full items-center gap-2 border-t border-border px-3 py-2 text-xs text-critical hover:bg-critical/10"
              >
                <LogOut className="h-3.5 w-3.5" /> Sign out
              </button>
            </div>
          ) : null}
        </div>
      </div>

      {jobsOpen ? (
        <div className="absolute right-4 top-14 w-72 animate-fade-in rounded-lg border border-border-strong bg-panel p-3 shadow-2xl" data-topbar-popover>
          <div className="mb-2 flex items-center justify-between">
            <p className="text-xs font-semibold text-ink">Background jobs</p>
            <button onClick={() => setJobsOpen(false)} className="text-muted hover:text-ink">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {(jobs.data?.items ?? []).length === 0 ? (
            <p className="py-4 text-center text-2xs text-muted">No recent background jobs</p>
          ) : (
            <div className="space-y-1.5">
              {jobs.data!.items.map((job) => (
                <div key={job.id} className="rounded border border-border bg-base/50 px-2 py-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-2xs text-ink">{job.job_type}</span>
                    <StatusBadge status={job.status} />
                  </div>
                  <p className="text-[10px] text-muted">{job.progress}% · {relativeTime(job.created_at)}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : null}

      {searchOpen ? (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[12vh]" onClick={() => setSearchOpen(false)}>
          <div className="w-full max-w-lg animate-fade-in overflow-hidden rounded-lg border border-border-strong bg-panel shadow-2xl" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="h-4 w-4 text-muted" />
              <input
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Jump to a module…"
                className="h-11 flex-1 bg-transparent text-sm text-ink placeholder:text-muted focus:outline-none"
              />
              <kbd className="rounded border border-border px-1.5 py-0.5 text-[9px] text-muted">ESC</kbd>
            </div>
            <div className="max-h-72 overflow-y-auto p-1.5">
              {results.map((link) => (
                <button
                  key={link.to}
                  onClick={() => {
                    navigate(link.to);
                    setSearchOpen(false);
                    setQuery("");
                  }}
                  className="flex w-full items-center gap-2.5 rounded px-2.5 py-2 text-left text-sm text-muted hover:bg-raised hover:text-ink"
                >
                  <link.icon className="h-4 w-4" />
                  {link.label}
                </button>
              ))}
              {results.length === 0 ? <p className="px-3 py-6 text-center text-xs text-muted">No matching modules</p> : null}
            </div>
          </div>
        </div>
      ) : null}
    </header>
  );
}
