import { defineStore } from 'pinia'

import { apiGet } from '../api/client'

export interface AIStatus {
  llm: {
    baseUrl: string
    model: string
    allowPrivateNetwork: boolean
    mock: boolean
    configured: boolean
  }
  embedding: {
    baseUrl: string
    model: string
    mode: string
    dimensions: number
    configured: boolean
  }
  hitl: {
    enabled: boolean
    tools: string[]
    timeoutSeconds: number
  }
  context: {
    maxChars: number
  }
}

export const useSettingsStore = defineStore('settings', {
  state: () => ({
    status: null as AIStatus | null,
    loading: false,
    error: '',
  }),
  actions: {
    async load() {
      this.loading = true
      this.error = ''
      try {
        this.status = await apiGet<AIStatus>('/settings/ai')
      } catch (error) {
        this.error = error instanceof Error ? error.message : '读取设置失败'
      } finally {
        this.loading = false
      }
    },
  },
})
