import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import apiClient, { setUnauthorizedHandler } from '../api/client';

interface UserProfile {
  id: string;
  email: string;
  full_name: string | null;
  is_superuser: boolean;
  is_active: boolean;
  mfa_enabled: boolean;
  roles: string[];
  permissions: string[];
}

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshProfile = useCallback(async () => {
    try {
      const { data } = await apiClient.get('/auth/me');
      setUser(data);
    } catch {
      setUser(null);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }, []);

  // On mount, check for existing token
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      refreshProfile().finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, [refreshProfile]);

  // Let the API client reset React state when a session expires (e.g. after a
  // failed token refresh), so the app redirects via state instead of a full
  // page reload.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const login = async (email: string, password: string, mfaCode?: string) => {
    const { data } = await apiClient.post('/auth/login', {
      email,
      password,
      mfa_code: mfaCode,
    });

    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);

    await refreshProfile();
  };

  const logout = async () => {
    try {
      await apiClient.post('/auth/logout');
    } catch {
      // Swallow — token may already be invalid
    }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        refreshProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

/**
 * Whether a user may see admin-only areas (user management, agent admin,
 * audit log). Backend seeds roles: admin, operator, viewer, auditor.
 */
export function canAccessAdmin(user: UserProfile | null | undefined): boolean {
  if (!user) return false;
  return user.is_superuser || (user.roles ?? []).includes('admin');
}
