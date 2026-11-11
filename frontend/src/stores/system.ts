import { defineStore } from 'pinia'

import { apiGet } from '../api/client'

export interface HealthPayload {
  status: string
  service: string
  version: string
  uptime_seconds: number
  time: string
}

export interface VersionPayload {
  service: string
  version: string
  apiVersion: string
  capabilities: string[]
}

export interface SystemStats {
  hostname: string
  os: string
  arch: string
  cpuPercent: number
  cpuSupported: boolean
  memoryPercent: number
  memoryUsedBytes: number
  memoryTotalBytes: number
  memorySource: string
  collectedAt: string
}

export const useSystemStore = defineStore('system', {
  state: () => ({
    health: null as HealthPayload | null,
    version: null as VersionPayload | null,
    stats: null as SystemStats | null,
    loading: false,
    error: '',
  }),
  actions: {
    async refresh() {
      this.loading = true
      this.error = ''
      try {
        const [health, version, stats] = await Promise.all([
          apiGet<HealthPayload>('/health'),
          apiGet<VersionPayload>('/version'),
          apiGet<SystemStats>('/system/stats'),
        ])
        this.health = health
        this.version = version
        this.stats = stats
      } catch (error) {
        this.error = error instanceof Error ? error.message : '无法连接后端'
      } finally {
        this.loading = false
      }
    },
  },
})
