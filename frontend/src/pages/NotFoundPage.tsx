import { Link } from "react-router-dom";
import { ShieldQuestion } from "lucide-react";

export function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-lg border border-border bg-raised text-muted">
        <ShieldQuestion className="h-7 w-7" />
      </div>
      <p className="mono text-xs uppercase tracking-[0.2em] text-accent">404</p>
      <h1 className="mt-2 text-xl font-semibold text-ink">Module not found</h1>
      <p className="mt-1 max-w-md text-sm text-muted">The requested ATLAS module or record does not exist, or your role cannot access it.</p>
      <Link to="/" className="mt-4 rounded-md border border-accent/40 bg-accent/10 px-3.5 py-2 text-sm text-accent hover:bg-accent/20">Return to Command Center</Link>
    </div>
  );
}

export function ForbiddenPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-lg border border-critical/30 bg-critical/10 text-critical">
        <ShieldQuestion className="h-7 w-7" />
      </div>
      <p className="mono text-xs uppercase tracking-[0.2em] text-critical">403</p>
      <h1 className="mt-2 text-xl font-semibold text-ink">Insufficient permissions</h1>
      <p className="mt-1 max-w-md text-sm text-muted">Your role does not grant access to this module. Authorization is enforced on the backend; contact an administrator if you need access.</p>
      <Link to="/" className="mt-4 rounded-md border border-border-strong px-3.5 py-2 text-sm text-ink hover:border-accent/40">Return to Command Center</Link>
    </div>
  );
}
