import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Missions } from './pages/Missions';
import { Workflow } from './pages/Workflow';
import { Detection } from './pages/Detection';
import { Login } from './pages/Login';
import { useAuthStore } from './stores/authStore';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,
    },
  },
});

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/*"
            element={
              <PrivateRoute>
                <Layout>
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/missions" element={<Missions />} />
                    <Route path="/workflow" element={<Workflow />} />
                    <Route path="/detection" element={<Detection />} />
                  </Routes>
                </Layout>
              </PrivateRoute>
            }
          />
        </Routes>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
