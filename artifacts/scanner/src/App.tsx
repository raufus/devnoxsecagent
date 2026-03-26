import { Switch, Route, Router as WouterRouter, useLocation, Redirect } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/lib/auth";
import NotFound from "@/pages/not-found";
import LoginPage from "@/pages/login";
import RegisterPage from "@/pages/register";
import LandingPage from "@/pages/landing";

import Dashboard from "@/pages/dashboard";
import NewScan from "@/pages/new-scan";
import LiveScan from "@/pages/live-scan";
import Report from "@/pages/report";
import ScanHistory from "@/pages/scan-history";
import ReconPage from "@/pages/recon";
import AIBrainPage from "@/pages/ai-brain";
import GraphPage from "@/pages/graph";
import ExploitPage from "@/pages/exploit";
import AdvancedAnalysis from "@/pages/advanced-analysis";
import IntruderPage from "@/pages/intruder";
import RepeaterPage from "@/pages/repeater";
import InterceptorPage from "@/pages/interceptor";
import ComparerPage from "@/pages/comparer";
import SequencerPage from "@/pages/sequencer";
import HttpHistoryPage from "@/pages/http-history";
import MatchReplacePage from "@/pages/match-replace";
import ScopePage from "@/pages/scope";
import WebSocketsPage from "@/pages/websockets";
import LoggerPage from "@/pages/logger";
import DecoderPage from "@/pages/decoder";
import AdminDashboard from "@/pages/admin/index";
import AdminUsers from "@/pages/admin/users";
import AdminScans from "@/pages/admin/scans";
import AdminSettings from "@/pages/admin/settings";
import AdminFindings from "@/pages/admin/findings";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } }
});

function ProtectedRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  if (!isAuthenticated) return <Redirect to="/login" />;
  return <Component />;
}
function Router() {
  return (
    <Switch>
      <Route path="/" component={LandingPage} />
      <Route path="/login" component={LoginPage} />
      <Route path="/register" component={RegisterPage} />
      <Route path="/dashboard" component={() => <ProtectedRoute component={Dashboard} />} />      <Route path="/scans/new" component={() => <ProtectedRoute component={NewScan} />} />
      <Route path="/scans/:id/live" component={() => <ProtectedRoute component={LiveScan} />} />
      <Route path="/scans/:id/report" component={() => <ProtectedRoute component={Report} />} />
      <Route path="/scans/:id/advanced" component={() => <ProtectedRoute component={AdvancedAnalysis} />} />
      <Route path="/scans/:id/recon" component={() => <ProtectedRoute component={ReconPage} />} />
      <Route path="/scans/:id/ai-brain" component={() => <ProtectedRoute component={AIBrainPage} />} />
      <Route path="/scans/:id/graph" component={() => <ProtectedRoute component={GraphPage} />} />
      <Route path="/scans/:id/exploit" component={() => <ProtectedRoute component={ExploitPage} />} />
      <Route path="/scans" component={() => <ProtectedRoute component={ScanHistory} />} />
      <Route path="/tools/intruder" component={() => <ProtectedRoute component={IntruderPage} />} />
      <Route path="/tools/repeater" component={() => <ProtectedRoute component={RepeaterPage} />} />
      <Route path="/tools/interceptor" component={() => <ProtectedRoute component={InterceptorPage} />} />
      <Route path="/tools/comparer" component={() => <ProtectedRoute component={ComparerPage} />} />
      <Route path="/tools/sequencer" component={() => <ProtectedRoute component={SequencerPage} />} />
      <Route path="/tools/http-history" component={() => <ProtectedRoute component={HttpHistoryPage} />} />
      <Route path="/tools/match-replace" component={() => <ProtectedRoute component={MatchReplacePage} />} />
      <Route path="/tools/scope" component={() => <ProtectedRoute component={ScopePage} />} />
      <Route path="/tools/websockets" component={() => <ProtectedRoute component={WebSocketsPage} />} />
      <Route path="/tools/logger" component={() => <ProtectedRoute component={LoggerPage} />} />
      <Route path="/tools/decoder" component={() => <ProtectedRoute component={DecoderPage} />} />
      <Route path="/admin" component={() => <ProtectedRoute component={AdminDashboard} />} />
      <Route path="/admin/users" component={() => <ProtectedRoute component={AdminUsers} />} />
      <Route path="/admin/scans" component={() => <ProtectedRoute component={AdminScans} />} />
      <Route path="/admin/settings" component={() => <ProtectedRoute component={AdminSettings} />} />
      <Route path="/admin/findings" component={() => <ProtectedRoute component={AdminFindings} />} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <WouterRouter base={(import.meta as any).env?.BASE_URL?.replace(/\/$/, "") ?? ""}>
            <div className="dark">
              <Router />
            </div>
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
