<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'

import { useSystemStore } from '../stores/system'
import { useI18n } from '../i18n'

const { t } = useI18n()

const system = useSystemStore()
let refreshTimer: number | undefined

const memoryText = computed(() =>
  system.stats ? `${system.stats.memoryPercent.toFixed(1)}%` : '-',
)
const cpuText = computed(() =>
  system.stats?.cpuSupported ? `${system.stats.cpuPercent.toFixed(1)}%` : '-',
)

function formatBytes(value: number) {
  if (!value) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index++
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function barWidth(value?: number) {
  const percent = typeof value === 'number' ? Math.min(100, Math.max(0, value)) : 0
  return `${percent}%`
}

function barTone(value?: number) {
  const percent = value ?? 0
  if (percent >= 80) {
    return 'bar-danger'
  }
  if (percent >= 60) {
    return 'bar-warn'
  }
  return 'bar-ok'
}

onMounted(() => {
  void system.refresh()
  refreshTimer = window.setInterval(() => {
    void system.refresh()
  }, 10000)
})

onUnmounted(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
})
</script>

<template>
  <section class="page factory-page page-home">
    <header class="page-header">
      <div>
        <p class="eyebrow">SYSTEM OVERVIEW</p>
        <h1>{{ t('nav.home') }}</h1>
        <p class="muted">{{ t('home.subtitle') }}</p>
      </div>
      <button class="button" :disabled="system.loading" @click="system.refresh">
        {{ system.loading ? t('home.checking') : t('home.recheck') }}
      </button>
    </header>

    <div v-if="system.error" class="alert error">{{ system.error }}</div>

    <div class="status-grid">
      <article class="status-card">
        <span class="status-dot" :class="{ online: system.health }"></span>
        <div>
          <small>Go API</small>
          <strong>{{ system.health ? 'ONLINE' : 'UNKNOWN' }}</strong>
        </div>
      </article>

      <article class="status-card">
        <span class="status-dot" :class="{ online: system.version }"></span>
        <div>
          <small>API Version</small>
          <strong>{{ system.version?.apiVersion || '-' }}</strong>
        </div>
      </article>

      <article class="status-card">
        <span class="status-dot online"></span>
        <div>
          <small>Frontend</small>
          <strong>Vue 3</strong>
        </div>
      </article>
    </div>

    <div class="resource-grid">
      <article class="resource-card">
        <small>{{ t('home.hostname') }}</small>
        <strong class="resource-value">{{ system.stats?.hostname || '-' }}</strong>
        <span class="resource-hint">
          {{ system.stats?.os || '-' }} / {{ system.stats?.arch || '-' }}
        </span>
      </article>

      <article class="resource-card">
        <small>{{ t('home.memoryUsage') }}</small>
        <strong class="resource-value">{{ memoryText }}</strong>
        <span class="resource-bar">
          <i
            :class="barTone(system.stats?.memoryPercent)"
            :style="{ width: barWidth(system.stats?.memoryPercent) }"
          ></i>
        </span>
        <span class="resource-hint">
          <template v-if="system.stats?.memoryTotalBytes">
            {{ formatBytes(system.stats.memoryUsedBytes) }} /
            {{ formatBytes(system.stats.memoryTotalBytes) }} ·
            {{ system.stats.memorySource }}
          </template>
          <template v-else>{{ t('home.unsupported') }}</template>
        </span>
      </article>

      <article class="resource-card">
        <small>{{ t('home.cpuUsage') }}</small>
        <strong class="resource-value">{{ cpuText }}</strong>
        <span class="resource-bar">
          <i
            :class="barTone(system.stats?.cpuPercent)"
            :style="{ width: barWidth(system.stats?.cpuPercent) }"
          ></i>
        </span>
        <span class="resource-hint">
          {{ system.stats?.cpuSupported ? t('home.cpuHint') : t('home.unsupported') }}
        </span>
      </article>
    </div>

    <p class="muted auto-refresh-hint">{{ t('home.autoRefresh') }}</p>

    <div class="factory-table-scroll">
      <table class="data-table">
        <tbody>
          <tr>
            <th>{{ t('home.service') }}</th>
            <td>{{ system.health?.service || '-' }}</td>
          </tr>
          <tr>
            <th>{{ t('home.backendVersion') }}</th>
            <td>{{ system.health?.version || '-' }}</td>
          </tr>
          <tr>
            <th>{{ t('home.uptime') }}</th>
            <td>{{ t('home.seconds', { count: system.health?.uptime_seconds ?? '-' }) }}</td>
          </tr>
          <tr>
            <th>{{ t('home.backendTime') }}</th>
            <td>{{ system.health?.time || '-' }}</td>
          </tr>
          <tr>
            <th>{{ t('home.capabilities') }}</th>
            <td>{{ system.version?.capabilities.join(', ') || '-' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.resource-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.resource-card {
  position: relative;
  display: grid;
  gap: 6px;
  padding: 16px 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.resource-card::before {
  position: absolute;
  top: -1px;
  left: -1px;
  width: 42px;
  height: 4px;
  content: '';
  background: var(--accent);
  opacity: 1;
}

.resource-card small {
  color: var(--text-muted);
  font-size: 12px;
}

.resource-value {
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}

.resource-hint {
  color: var(--text-muted);
  font-size: 12px;
}

.resource-bar {
  height: 8px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.resource-bar i {
  display: block;
  height: 100%;
  border-radius: var(--radius);
  transition: width 0.3s ease;
}

.bar-ok {
  background: var(--success);
}

.bar-warn {
  background: var(--warning);
}

.bar-danger {
  background: var(--danger);
}

.auto-refresh-hint {
  margin-top: 14px;
  font-size: 12px;
}
</style>
