import { defineStore } from 'pinia'

import { apiGet, apiPost } from '../api/client'

export interface User {
  id: string
  username: string
  displayName?: string
  role: string
  assistantName?: string
  assistantAvatar?: string
  userAvatar?: string
}

interface AuthResponse {
  user: User
  csrfToken?: string
  expiresAt?: string
}

interface PermissionResponse {
  user: User
  permissions: string[] | null
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    permissions: [] as string[],
    initialized: false,
    loading: false,
    error: '',
  }),
  getters: {
    isAuthenticated: (state) => state.user !== null,
    hasPermission: (state) => (permission: string) =>
      state.permissions.includes('*') || state.permissions.includes(permission),
  },
  actions: {
    async loadPermissions() {
      try {
        const response = await apiGet<PermissionResponse>('/rbac/me')
        this.permissions = response.permissions ?? []
      } catch {
        this.permissions = []
      }
    },
    async initialize() {
      if (this.initialized) {
        return
      }
      this.initialized = true
      this.loading = true
      try {
        const response = await apiGet<AuthResponse>('/auth/me')
        this.user = response.user
        await this.loadPermissions()
      } catch {
        this.user = null
        this.permissions = []
      } finally {
        this.loading = false
      }
    },
    async login(username: string, password: string) {
      this.loading = true
      this.error = ''
      try {
        const response = await apiPost<AuthResponse>('/auth/login', {
          username,
          password,
        })
        this.user = response.user
        this.initialized = true
        await this.loadPermissions()
      } catch (error) {
        this.error = error instanceof Error ? error.message : '登录失败'
        throw error
      } finally {
        this.loading = false
      }
    },
    async logout() {
      try {
        await apiPost<void>('/auth/logout')
      } finally {
        this.user = null
        this.permissions = []
        this.initialized = true
      }
    },
    applyUserProfile(user: User) {
      this.user = user
      this.initialized = true
    },
  },
})
