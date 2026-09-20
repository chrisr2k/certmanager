import axios from 'axios';
import type { AxiosRequestConfig } from 'axios';

// Empty string (production, behind nginx /api proxy) stays relative;
// only null/undefined falls back to the local dev server.
const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor — attach JWT
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Endpoints where a 401 means the request itself failed (bad credentials, MFA
// challenge, invalid refresh token) — NOT an expired access token. These must
// reject immediately so the caller can handle the error instead of being
// redirected through the refresh flow.
const NO_REFRESH_URLS = ['/auth/login', '/auth/refresh'];

// Registered by the auth store so a session expiry resets React state (not
// just localStorage). Falls back to a hard redirect if none is registered.
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

function clearSession() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  if (unauthorizedHandler) {
    unauthorizedHandler();
  } else {
    window.location.href = '/login';
  }
}

// Response interceptor — handle 401 token refresh
let isRefreshing = false;
let failedQueue: Array<{ resolve: Function; reject: Function }> = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      const url: string = originalRequest?.url || '';
      if (NO_REFRESH_URLS.some((endpoint) => url.includes(endpoint))) {
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        clearSession();
        return Promise.reject(error);
      }

      try {
        const { data } = await axios.post(`${API_BASE}/api/v1/auth/refresh`, {
          refresh_token: refreshToken,
        });

        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);

        processQueue(null, data.access_token);
        originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        clearSession();
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

/** GET a resource, unwrapping the backend's `{"data": ...}` response envelope. */
export async function getEnveloped<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const { data } = await apiClient.get(url, config);
  return data?.data ?? data;
}

export default apiClient;
