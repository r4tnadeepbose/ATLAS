import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { MainLayout } from "@/layouts/MainLayout";
import { LoginPage } from "@/pages/LoginPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { AssetsPage, AssetDetailPage } from "@/pages/assets/AssetsPage";
import { MicroservicesPage } from "@/pages/microservices/MicroservicesPage";
import { MicroserviceDetailPage } from "@/pages/microservices/MicroserviceDetailPage";
import { SbomPage } from "@/pages/sbom/SbomPage";
import { SbomDetailPage } from "@/pages/sbom/SbomDetailPage";
import { TriagePage } from "@/pages/triage/TriagePage";
import { AttackSurfacePage } from "@/pages/attack-surface/AttackSurfacePage";
import { ApiInventoryPage } from "@/pages/api-inventory/ApiInventoryPage";
import { ApiDetailPage } from "@/pages/api-inventory/ApiDetailPage";
import { ClassificationPage } from "@/pages/classification/ClassificationPage";
import { VulnerabilitiesPage } from "@/pages/vulnerabilities/VulnerabilitiesPage";
import { FindingDetailPage } from "@/pages/vulnerabilities/FindingDetailPage";
import { RiskManagementPage } from "@/pages/risk/RiskManagementPage";
import { NotificationsPage } from "@/pages/notifications/NotificationsPage";
import { ScanManagementPage } from "@/pages/scans/ScanManagementPage";
import { ExecutivePage } from "@/pages/executive/ExecutivePage";
import { ReportsPage } from "@/pages/reports/ReportsPage";
import { UsersPage } from "@/pages/admin/UsersPage";
import { RbacPage } from "@/pages/admin/RbacPage";
import { IntegrationsPage } from "@/pages/admin/IntegrationsPage";
import { SettingsPage } from "@/pages/admin/SettingsPage";
import { SystemPage } from "@/pages/admin/SystemPage";
import { ForbiddenPage, NotFoundPage } from "@/pages/NotFoundPage";
import { Spinner } from "@/components/ui/primitives";

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-base">
        <div className="flex flex-col items-center gap-3">
          <Spinner className="h-6 w-6 text-accent" />
          <p className="text-[10px] uppercase tracking-[0.2em] text-muted">Initialising ATLAS</p>
        </div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  return <>{children}</>;
}

function Guard({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth();
  return can(permission) ? <>{children}</> : <ForbiddenPage />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <MainLayout />
          </RequireAuth>
        }
      >
        <Route index element={<Guard permission="dashboard:read"><DashboardPage /></Guard>} />
        <Route path="assets" element={<Guard permission="assets:read"><AssetsPage /></Guard>} />
        <Route path="assets/:id" element={<Guard permission="assets:read"><AssetDetailPage /></Guard>} />
        <Route path="microservices" element={<Guard permission="microservices:read"><MicroservicesPage /></Guard>} />
        <Route path="microservices/:id" element={<Guard permission="microservices:read"><MicroserviceDetailPage /></Guard>} />
        <Route path="sbom" element={<Guard permission="sbom:read"><SbomPage /></Guard>} />
        <Route path="sbom/:id" element={<Guard permission="sbom:read"><SbomDetailPage /></Guard>} />
        <Route path="ai-triage" element={<Guard permission="findings:triage"><TriagePage /></Guard>} />
        <Route path="attack-surface" element={<Guard permission="scans:read"><AttackSurfacePage /></Guard>} />
        <Route path="api-inventory" element={<Guard permission="apis:read"><ApiInventoryPage /></Guard>} />
        <Route path="api-inventory/:id" element={<Guard permission="apis:read"><ApiDetailPage /></Guard>} />
        <Route path="data-classification" element={<Guard permission="classification:read"><ClassificationPage /></Guard>} />
        <Route path="vulnerabilities" element={<Guard permission="findings:read"><VulnerabilitiesPage /></Guard>} />
        <Route path="vulnerabilities/:id" element={<Guard permission="findings:read"><FindingDetailPage /></Guard>} />
        <Route path="risk-management" element={<Guard permission="risks:read"><RiskManagementPage /></Guard>} />
        <Route path="notifications" element={<Guard permission="notifications:read"><NotificationsPage /></Guard>} />
        <Route path="scan-management" element={<Guard permission="scans:read"><ScanManagementPage /></Guard>} />
        <Route path="executive" element={<Guard permission="executive:read"><ExecutivePage /></Guard>} />
        <Route path="reports" element={<Guard permission="reports:read"><ReportsPage /></Guard>} />
        <Route path="users" element={<Guard permission="users:read"><UsersPage /></Guard>} />
        <Route path="rbac" element={<Guard permission="users:read"><RbacPage /></Guard>} />
        <Route path="integrations" element={<Guard permission="integrations:read"><IntegrationsPage /></Guard>} />
        <Route path="settings" element={<Guard permission="settings:read"><SettingsPage /></Guard>} />
        <Route path="system" element={<Guard permission="settings:read"><SystemPage /></Guard>} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
