import { Routes, Route, Navigate } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuth } from './store/auth';
import AppLayout from './components/layout/AppLayout';
import LoginPage from './pages/Login';
import DashboardPage from './pages/Dashboard';
import CertificateInventory from './pages/Certificates/Inventory';
import CertificateDetail from './pages/Certificates/Detail';
import AuthoritiesList from './pages/Authorities/List';
import CAHealthDashboard from './pages/Authorities/Health';
import AlertsRules from './pages/Alerts/Rules';
import AlertsEvents from './pages/Alerts/Events';
import AlertsChannels from './pages/Alerts/Channels';
import DatacentersList from './pages/Datacenters/List';
import ReportsList from './pages/Reports/List';
import AdminUsers from './pages/Admin/Users';
import AdminAgents from './pages/Admin/Agents';
import AuditLogPage from './pages/AuditLog';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <AppLayout>{children}</AppLayout>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />

      <Route
        path="/certificates"
        element={
          <ProtectedRoute>
            <CertificateInventory />
          </ProtectedRoute>
        }
      />

      <Route
        path="/certificates/:id"
        element={
          <ProtectedRoute>
            <CertificateDetail />
          </ProtectedRoute>
        }
      />

      <Route
        path="/authorities"
        element={
          <ProtectedRoute>
            <AuthoritiesList />
          </ProtectedRoute>
        }
      />

      <Route
        path="/authorities/health"
        element={
          <ProtectedRoute>
            <CAHealthDashboard />
          </ProtectedRoute>
        }
      />

      <Route
        path="/alerts/rules"
        element={
          <ProtectedRoute>
            <AlertsRules />
          </ProtectedRoute>
        }
      />

      <Route
        path="/alerts/channels"
        element={
          <ProtectedRoute>
            <AlertsChannels />
          </ProtectedRoute>
        }
      />

      <Route
        path="/alerts/events"
        element={
          <ProtectedRoute>
            <AlertsEvents />
          </ProtectedRoute>
        }
      />

      <Route
        path="/datacenters"
        element={
          <ProtectedRoute>
            <DatacentersList />
          </ProtectedRoute>
        }
      />

      <Route
        path="/reports"
        element={
          <ProtectedRoute>
            <ReportsList />
          </ProtectedRoute>
        }
      />

      <Route
        path="/admin/users"
        element={
          <ProtectedRoute>
            <AdminUsers />
          </ProtectedRoute>
        }
      />

      <Route
        path="/admin/agents"
        element={
          <ProtectedRoute>
            <AdminAgents />
          </ProtectedRoute>
        }
      />

      <Route
        path="/audit-log"
        element={
          <ProtectedRoute>
            <AuditLogPage />
          </ProtectedRoute>
        }
      />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
