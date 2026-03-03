import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  setUser: (user: User) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      token: null,
      
      login: async (email: string, password: string) => {
        try {
          // Simulation d'une authentification
          // En production, remplacer par un appel API réel
          if (email === 'admin@defensive-ops.com' && password === 'admin123') {
            const user: User = {
              id: '1',
              email,
              name: 'Administrator',
              role: 'admin'
            };
            const token = 'mock-jwt-token';
            
            set({
              user,
              isAuthenticated: true,
              token
            });
          } else {
            throw new Error('Identifiants invalides');
          }
        } catch (error) {
          console.error('Erreur de connexion:', error);
          throw error;
        }
      },
      
      logout: () => {
        set({
          user: null,
          isAuthenticated: false,
          token: null
        });
      },
      
      setUser: (user: User) => {
        set({ user });
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
        token: state.token
      })
    }
  )
);