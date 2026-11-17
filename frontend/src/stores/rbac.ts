import { defineStore } from 'pinia'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'

export interface Role {
  name: string
  description: string
  permissions: string[]
  builtin: boolean
}

export interface RoleUser {
  id: string
  username: string
  displayName: string
  role: string
  enabled: boolean
  createdAt: string
}

export interface UserInput {
  username: string
  displayName: string
  password: string
  role: string
  enabled: boolean
}

export interface RoleInput {
  name: string
  description: string
  permissions: string[]
}

interface ListResponse<T> {
  items: T[]
  total?: number
  page?: number
  pageSize?: number
  totalPages?: number
  stats?: {
    total?: number
    enabled?: number
  }
}

interface MetadataResponse {
  permissions: Record<string, string[]>
}

export const useRbacStore = defineStore('rbac', {
  state: () => ({
    roles: [] as Role[],
    users: [] as RoleUser[],
    userPagination: {
      page: 1,
      pageSize: 20,
      total: 0,
      totalPages: 1,
    },
    userStats: {
      total: 0,
      enabled: 0,
    },
    catalog: {} as Record<string, string[]>,
    loading: false,
    error: '',
  }),
  getters: {
    permissionList: (state) => {
      const result: string[] = []
      Object.keys(state.catalog)
        .sort()
        .forEach((module) => {
          state.catalog[module].forEach((permission) => {
            if (!result.includes(permission)) {
              result.push(permission)
            }
          })
        })
      return result
    },
  },
  actions: {
    async load() {
      this.loading = true
      this.error = ''
      try {
        const [roles, users, metadata] = await Promise.all([
          apiGet<ListResponse<Role>>('/rbac/roles'),
          apiGet<ListResponse<RoleUser>>('/rbac/users?limit=20&offset=0&sort=username_asc'),
          apiGet<MetadataResponse>('/rbac/metadata'),
        ])
        this.roles = roles.items ?? []
        this.applyUserPage(users)
        this.catalog = metadata.permissions ?? {}
      } catch (error) {
        this.error = error instanceof Error ? error.message : '读取权限数据失败'
      } finally {
        this.loading = false
      }
    },
    applyUserPage(response: ListResponse<RoleUser>) {
      this.users = response.items ?? []
      this.userPagination = {
        page: response.page ?? 1,
        pageSize: response.pageSize ?? 20,
        total: response.total ?? 0,
        totalPages: response.totalPages ?? 1,
      }
      this.userStats = {
        total: response.stats?.total ?? 0,
        enabled: response.stats?.enabled ?? 0,
      }
    },
    async loadUsers(options: {
      page?: number
      pageSize?: number
      search?: string
      status?: string
      sort?: string
    } = {}) {
      const page = options.page ?? this.userPagination.page
      const pageSize = options.pageSize ?? this.userPagination.pageSize
      const query = new URLSearchParams({
        limit: String(pageSize),
        offset: String((page - 1) * pageSize),
        sort: options.sort ?? 'username_asc',
      })
      if (options.search?.trim()) {
        query.set('search', options.search.trim())
      }
      if (options.status) {
        query.set('status', options.status)
      }
      const response = await apiGet<ListResponse<RoleUser>>(`/rbac/users?${query.toString()}`)
      this.applyUserPage(response)
    },
    async createUser(input: UserInput) {
      await apiPost('/rbac/users', input)
      await this.load()
    },
    async updateUser(id: string, input: UserInput) {
      await apiPut(`/rbac/users/${id}`, input)
      await this.load()
    },
    async deleteUser(id: string) {
      await apiDelete(`/rbac/users/${id}`)
      await this.load()
    },
    async createRole(input: RoleInput) {
      await apiPost('/rbac/roles', input)
      await this.load()
    },
    async updateRole(name: string, input: RoleInput) {
      await apiPut(`/rbac/roles/${name}`, input)
      await this.load()
    },
    async deleteRole(name: string) {
      await apiDelete(`/rbac/roles/${name}`)
      await this.load()
    },
  },
})
