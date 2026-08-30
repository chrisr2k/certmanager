import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import {
  QueryClient,
  QueryClientProvider,
  QueryCache,
  MutationCache,
} from '@tanstack/react-query';
import { ConfigProvider, App as AntApp, message } from 'antd';
import App from './App';
import { AuthProvider } from './store/auth';
import './index.css';

// Turn axios errors into a user-facing message. Returns null when the error
// is already handled elsewhere (401 session-expiry redirects to /login).
function getErrorMessage(error: unknown): string | null {
  const err = error as any;
  const status = err?.response?.status;
  const backendMsg = err?.response?.data?.message || err?.response?.data?.detail;

  if (status === 403) {
    return backendMsg
      ? `Access denied: ${backendMsg}`
      : 'You do not have permission to perform this action.';
  }
  if (status === 401) {
    return null; // handled by the API client's session-expiry redirect
  }
  if (backendMsg) return backendMsg;
  if (status) return `Request failed (HTTP ${status}). Please try again.`;
  return 'Network error — is the API server reachable?';
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,       // 30 seconds
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
  queryCache: new QueryCache({
    onError: (error) => {
      const msg = getErrorMessage(error);
      if (msg) message.error(msg);
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      const msg = getErrorMessage(error);
      if (msg) message.error(msg);
    },
  }),
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <ConfigProvider
          theme={{
            token: {
              colorPrimary: '#1677ff',
              borderRadius: 6,
            },
          }}
        >
          <AntApp>
            <AuthProvider>
              <App />
            </AuthProvider>
          </AntApp>
        </ConfigProvider>
      </QueryClientProvider>
    </BrowserRouter>
  </React.StrictMode>
);
