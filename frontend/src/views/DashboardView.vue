<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import { apiGet } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useSystemStore } from '../stores/system'

const { t, locale } = useI18n()
const system = useSystemStore()

interface Summary {
  conversations: number
  vulnerabilities: number
  toolCalls: number
  assets?: {
    total: number
    criticality: Record<string, number>
    status: Record<string, number>
  }
  tokens: {
    prompt: number
    cacheRead?: number
    completion: number
    total: number
    estimated: boolean
  }
  vulnerabilityStatus: Record<string, number>
  vulnerabilitySeverity: Record<string, number>
}

interface TokenDay {
  date: string
  inputTokens: number
  cacheReadTokens: number
  outputTokens: number
}

interface TokenModel {
  model: string
  calls: number
  tasks: number
  inputTokens: number
  cacheReadTokens: number
  outputTokens: number
}

interface TokenStats {
  inputTokens: number
  cacheReadTokens: number
  outputTokens: number
  totalTokens: number
  taskCount: number
  calls: number
  estimated: boolean
  days: number
  models: TokenModel[]
  daily: TokenDay[]
}

interface TokenTooltipBar {
  date: string
  input: number
  cache: number
  output: number
  total: number
}

interface TokenTooltipState {
  x: number
  y: number
  bar: TokenTooltipBar
}

interface RowDefinition {
  key: string
  label: string
  tone: string
}

interface DistributionRow extends RowDefinition {
  count: number
}

const SEVERITY_ROWS: RowDefinition[] = [
  { key: 'critical', label: t('severity.critical'), tone: 'bar-critical' },
  { key: 'high', label: t('severity.high'), tone: 'bar-high' },
  { key: 'medium', label: t('severity.medium'), tone: 'bar-medium' },
  { key: 'low', label: t('severity.low'), tone: 'bar-low' },
  { key: 'info', label: t('severity.info'), tone: 'bar-info' },
]

const ASSET_CRITICALITY_ROWS: RowDefinition[] = [
  { key: 'critical', label: t('assetCriticality.critical'), tone: 'bar-critical' },
  { key: 'high', label: t('assetCriticality.high'), tone: 'bar-high' },
  { key: 'medium', label: t('assetCriticality.medium'), tone: 'bar-medium' },
  { key: 'low', label: t('assetCriticality.low'), tone: 'bar-low' },
  { key: 'info', label: t('assetCriticality.info'), tone: 'bar-info' },
]

const summary = ref<Summary | null>(null)
const tokenStats = ref<TokenStats | null>(null)
const tokenVersion = ref<'old' | 'new'>('new')
const tokenDays = ref(30)
const tokenModel = ref('')
const tokenSource = ref('token_usage')
const tokenLoading = ref(false)
const tokenError = ref('')
const tokenTooltip = ref<TokenTooltipState | null>(null)
const loading = ref(false)
const error = ref('')
const now = ref(new Date())
const lastUpdated = ref<Date | null>(null)
const refreshSeconds = ref(30)
let clockTimer: number | undefined

const TOKEN_RANGES = [
  { days: 7, label: 'dashboard.tokenRange7' },
  { days: 30, label: 'dashboard.tokenRange30' },
  { days: 90, label: 'dashboard.tokenRange90' },
  { days: 180, label: 'dashboard.tokenRange180' },
  { days: 365, label: 'dashboard.tokenRange365' },
]

const severityRows = computed<DistributionRow[]>(() =>
  buildRows(SEVERITY_ROWS, summary.value?.vulnerabilitySeverity),
)
const assetCriticalityRows = computed<DistributionRow[]>(() =>
  buildRows(ASSET_CRITICALITY_ROWS, summary.value?.assets?.criticality),
)
const severityTotal = computed(() => sumRows(severityRows.value))
const severityMax = computed(() => maxRow(severityRows.value))
const assetTotal = computed(() => summary.value?.assets?.total ?? 0)
const assetCriticalityTotal = computed(() => sumRows(assetCriticalityRows.value))
const assetCriticalityMax = computed(() => maxRow(assetCriticalityRows.value))

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff3e1d',
  high: '#ffab00',
  medium: '#ffbc33',
  low: '#03c3ec',
  info: '#8592a3',
}

const ASSET_COLORS: Record<string, string> = {
  critical: '#ff8a4c',
  high: '#ffd166',
  medium: '#35c8dc',
  low: '#4fd6a0',
  info: '#7f91aa',
}

function countOf(counts: Record<string, number> | undefined, key: string) {
  return counts?.[key] ?? 0
}

const criticalCount = computed(() =>
  countOf(summary.value?.vulnerabilitySeverity, 'critical'),
)
const highCount = computed(() => countOf(summary.value?.vulnerabilitySeverity, 'high'))
const openCount = computed(() => countOf(summary.value?.vulnerabilityStatus, 'open'))
const confirmedCount = computed(() =>
  countOf(summary.value?.vulnerabilityStatus, 'confirmed'),
)
const criticalHighCount = computed(() => criticalCount.value + highCount.value)
const unresolvedCount = computed(() => openCount.value + confirmedCount.value)
const highRiskAssetCount = computed(
  () =>
    countOf(summary.value?.assets?.criticality, 'critical') +
    countOf(summary.value?.assets?.criticality, 'high'),
)
const activeAssetCount = computed(() => summary.value?.assets?.status.active ?? 0)
const inactiveAssetCount = computed(() => summary.value?.assets?.status.inactive ?? 0)
const assetGradient = computed(() => {
  const total = assetCriticalityTotal.value
  if (total <= 0) {
    return 'conic-gradient(var(--border) 0 100%)'
  }
  let cursor = 0
  const parts: string[] = []
  for (const row of assetCriticalityRows.value) {
    if (row.count <= 0) {
      continue
    }
    const next = cursor + (row.count / total) * 100
    parts.push(`${ASSET_COLORS[row.key] ?? 'var(--text-muted)'} ${cursor}% ${next}%`)
    cursor = next
  }
  return parts.length ? `conic-gradient(${parts.join(', ')})` : 'conic-gradient(var(--border) 0 100%)'
})
const severityGradient = computed(() => {
  const total = severityTotal.value
  if (total <= 0) {
    return 'conic-gradient(var(--border) 0 100%)'
  }
  let cursor = 0
  const parts: string[] = []
  for (const row of severityRows.value) {
    if (row.count <= 0) {
      continue
    }
    const next = cursor + (row.count / total) * 100
    parts.push(`${SEVERITY_COLORS[row.key] ?? 'var(--text-muted)'} ${cursor}% ${next}%`)
    cursor = next
  }
  return parts.length ? `conic-gradient(${parts.join(', ')})` : 'conic-gradient(var(--border) 0 100%)'
})
const cpuPercent = computed(() =>
  Math.max(0, Math.min(100, Math.round(system.stats?.cpuPercent ?? 0))),
)
const memoryPercent = computed(() =>
  Math.max(0, Math.min(100, Math.round(system.stats?.memoryPercent ?? 0))),
)
const memoryText = computed(() => {
  const stats = system.stats
  if (!stats) {
    return '-'
  }
  return `${formatBytes(stats.memoryUsedBytes)} / ${formatBytes(stats.memoryTotalBytes)}`
})
const versionLabel = computed(
  () => system.version?.version || system.health?.version || 'dev',
)
const uptimeLabel = computed(() =>
  system.health ? t('home.seconds', { count: system.health.uptime_seconds }) : '-',
)
const nowText = computed(() =>
  now.value.toLocaleTimeString(locale.value, { hour12: false }),
)
const dateText = computed(() =>
  now.value.toLocaleDateString(locale.value, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }),
)
const lastUpdatedText = computed(() =>
  lastUpdated.value
    ? lastUpdated.value.toLocaleTimeString(locale.value, { hour12: false })
    : '-',
)

const tokenInputUncached = computed(() =>
  Math.max((tokenStats.value?.inputTokens ?? 0) - (tokenStats.value?.cacheReadTokens ?? 0), 0),
)
const tokenCacheRead = computed(() => tokenStats.value?.cacheReadTokens ?? 0)
const tokenOutput = computed(() => tokenStats.value?.outputTokens ?? 0)
const tokenTotal = computed(() => tokenStats.value?.totalTokens ?? 0)
const tokenHitRate = computed(() => {
  const input = tokenStats.value?.inputTokens ?? 0
  return input > 0 ? Math.round((tokenCacheRead.value / input) * 100) : 0
})
const tokenChartRows = computed(() => {
  const rows = tokenStats.value?.daily ?? []
  return rows.map((item) => {
    const input = Math.max(item.inputTokens - item.cacheReadTokens, 0)
    const cache = Math.max(item.cacheReadTokens, 0)
    const output = Math.max(item.outputTokens, 0)
    return {
      date: item.date,
      input,
      cache,
      output,
      total: input + cache + output,
    }
  })
})
const tokenChartMax = computed(() =>
  tokenChartRows.value.reduce((maximum, item) => Math.max(maximum, item.total), 0),
)
const tokenChartGeometry = computed(() => {
  const rows = tokenChartRows.value
  const width = Math.max(720, rows.length * 42)
  const height = 210
  const top = 14
  const bottom = 28
  const plotHeight = height - top - bottom
  const step = rows.length > 0 ? width / rows.length : width
  const barWidth = Math.min(24, Math.max(8, step * 0.54))
  const maximum = Math.max(tokenChartMax.value, 1)
  const cellCount = 6
  const cellGap = 2
  const cellHeight = plotHeight / cellCount
  return {
    width,
    height,
    top,
    bottom,
    plotHeight,
    bars: rows.map((item, index) => {
      const inputHeight = (item.input / maximum) * plotHeight
      const cacheHeight = (item.cache / maximum) * plotHeight
      const outputHeight = (item.output / maximum) * plotHeight
      const x = index * step + (step - barWidth) / 2
      const inputY = top + plotHeight - inputHeight
      const outputY = inputY - outputHeight
      const cacheY = outputY - cacheHeight
      const shellWidth = barWidth + 10
      const terminalWidth = Math.max(8, Math.round(barWidth * 0.48))
      return {
        ...item,
        x,
        barWidth,
        shellX: x - 5,
        shellY: top,
        shellWidth,
        shellHeight: plotHeight,
        terminalX: x + (barWidth - terminalWidth) / 2,
        terminalY: top - 6,
        terminalWidth,
        terminalHeight: 6,
        cells: Array.from({ length: cellCount }, (_, cellIndex) => ({
          x: x - 3,
          y: top + cellIndex * cellHeight + cellGap / 2,
          width: barWidth + 6,
          height: cellHeight - cellGap,
        })),
        cellGaps: Array.from({ length: cellCount - 1 }, (_, cellIndex) => ({
          x1: x - 4,
          x2: x + barWidth + 4,
          y: top + (cellIndex + 1) * cellHeight,
        })),
        inputY,
        inputHeight,
        outputY,
        outputHeight,
        cacheY,
        cacheHeight,
      }
    }),
  }
})

function formatNumber(value: number) {
  return value.toLocaleString(locale.value)
}

function formatTokenCompact(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '0'
  }
  if (value >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(1)}B`
  }
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(1)}k`
  }
  return String(value)
}

function tokenModelLabel(model: string) {
  return model.trim() || t('dashboard.tokenDefaultModel')
}

function showTokenTooltip(event: MouseEvent | FocusEvent, bar: TokenTooltipBar) {
  const width = 230
  const height = 150
  let x = 0
  let y = 0
  if (event instanceof MouseEvent) {
    x = event.clientX + 14
    y = event.clientY + 14
  } else {
    const rect = (event.currentTarget as SVGGElement | null)?.getBoundingClientRect()
    x = rect ? rect.right + 10 : 12
    y = rect ? rect.top - 8 : 12
  }
  tokenTooltip.value = {
    x: Math.min(Math.max(x, 8), Math.max(8, window.innerWidth - width - 8)),
    y: Math.min(Math.max(y, 8), Math.max(8, window.innerHeight - height - 8)),
    bar,
  }
}

function moveTokenTooltip(event: MouseEvent) {
  if (!tokenTooltip.value) {
    return
  }
  showTokenTooltip(event, tokenTooltip.value.bar)
}

function hideTokenTooltip() {
  tokenTooltip.value = null
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit++
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
}

function buildRows(definitions: RowDefinition[], counts?: Record<string, number>): DistributionRow[] {
  return definitions.map((definition) => ({
    ...definition,
    count: counts?.[definition.key] ?? 0,
  }))
}

function sumRows(rows: DistributionRow[]) {
  return rows.reduce((total, row) => total + row.count, 0)
}

function maxRow(rows: DistributionRow[]) {
  return rows.reduce((max, row) => Math.max(max, row.count), 0)
}

function percent(count: number, total: number) {
  if (total <= 0) {
    return 0
  }
  return Math.round((count / total) * 100)
}

// barWidth 给非零项至少 2% 宽度，避免 1/500 这类占比在视觉上消失。
function barWidth(count: number, total: number) {
  if (count <= 0 || total <= 0) {
    return '0%'
  }
  return `${Math.max(percent(count, total), 2)}%`
}

async function load() {
  if (loading.value) {
    return
  }
  loading.value = true
  error.value = ''
  try {
    summary.value = await apiGet<Summary>('/dashboard/summary')
    await loadTokenStats()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '读取仪表盘数据失败'
  } finally {
    await system.refresh()
    loading.value = false
    lastUpdated.value = new Date()
    refreshSeconds.value = 30
  }
}

async function loadTokenStats() {
  tokenLoading.value = true
  tokenError.value = ''
  try {
    const query = new URLSearchParams({
      days: String(tokenDays.value),
      version: tokenVersion.value,
    })
    if (tokenModel.value) {
      query.set('model', tokenModel.value)
    }
    const response = await apiGet<{
      version: string
      source: string
      stats: TokenStats
    }>(`/dashboard/tokens?${query.toString()}`)
    tokenStats.value = response.stats
    tokenSource.value = response.source
  } catch (err) {
    tokenError.value = err instanceof Error ? err.message : t('dashboard.tokenLoadFailed')
  } finally {
    tokenLoading.value = false
  }
}

watch([tokenVersion, tokenDays, tokenModel], () => {
  void loadTokenStats()
})

onMounted(() => {
  now.value = new Date()
  void load()
  clockTimer = window.setInterval(() => {
    now.value = new Date()
    if (refreshSeconds.value > 0) {
      refreshSeconds.value--
    }
    if (refreshSeconds.value === 0) {
      void load()
    }
  }, 1000)
})

onUnmounted(() => {
  if (clockTimer) {
    window.clearInterval(clockTimer)
  }
})
</script>

<template>
  <section class="page dashboard-screen">
    <header class="dashboard-header factory-header">
      <div class="dashboard-heading">
        <span class="factory-code">OPS FLOOR // 01</span>
        <p class="eyebrow">SECURITY OPERATIONS</p>
        <div class="dashboard-title-row">
          <PageTitleRobot tone="sky" />
          <h1>{{ t('dashboard.title') }}</h1>
        </div>
      </div>
      <div class="factory-route" aria-hidden="true">
        <span>RAW</span>
        <i></i>
        <span>WORK</span>
        <i></i>
        <span>OUTPUT</span>
      </div>
      <div class="dashboard-live">
        <span class="live-badge"><i></i>{{ t('dashboard.realtime') }}</span>
        <div class="dashboard-clock">
          <strong>{{ nowText }}</strong>
          <small>{{ dateText }}</small>
        </div>
        <button class="button compact" type="button" :disabled="loading" @click="load">
          {{ loading ? t('common.loading') : t('common.refresh') }}
        </button>
        <small class="refresh-countdown">
          {{ t('dashboard.refreshIn', { seconds: refreshSeconds }) }}
        </small>
      </div>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>

    <section v-if="summary" class="factory-stage raw-stage">
      <header class="stage-rail">
        <span class="stage-index">01</span>
        <span class="stage-title">RAW MATERIAL</span>
        <span class="stage-meta">04 INPUTS</span>
      </header>

      <div class="kpi-grid">
        <RouterLink
          class="kpi-card"
          data-code="RAW-01 / INPUT"
          to="/chat"
          :aria-label="t('dashboard.viewConversations')"
        >
          <span class="kpi-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M21 15a2 2 0 0 1-2 2H8l-5 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
            </svg>
          </span>
          <p class="kpi-label">{{ t('dashboard.conversations') }}</p>
          <strong class="kpi-value">{{ formatNumber(summary.conversations) }}</strong>
          <p class="kpi-hint">{{ t('dashboard.conversationsHint') }}</p>
        </RouterLink>

        <RouterLink
          class="kpi-card accent-vulnerability"
          data-code="RAW-02 / RISK"
          to="/vulnerabilities"
          :aria-label="t('dashboard.viewVulnerabilities')"
        >
          <span class="kpi-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M20 13c0 5-3.5 7.5-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1z" />
              <path d="M12 8v4M12 16h.01" />
            </svg>
          </span>
          <p class="kpi-label">{{ t('dashboard.vulnerabilities') }}</p>
          <strong class="kpi-value">{{ formatNumber(summary.vulnerabilities) }}</strong>
          <p class="kpi-hint">{{ t('dashboard.vulnerabilitiesHint') }}</p>
        </RouterLink>

        <RouterLink
          class="kpi-card accent-tool"
          data-code="RAW-03 / TOOL"
          to="/mcp-servers"
          :aria-label="t('dashboard.viewTools')"
        >
          <span class="kpi-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="m4 17 6-6-6-6M12 19h8" />
            </svg>
          </span>
          <p class="kpi-label">{{ t('dashboard.toolCalls') }}</p>
          <strong class="kpi-value">{{ formatNumber(summary.toolCalls) }}</strong>
          <p class="kpi-hint">{{ t('dashboard.toolCallsHint') }}</p>
        </RouterLink>

        <RouterLink
          class="kpi-card accent-token"
          data-code="RAW-04 / TOKEN"
          to="/chat"
          :aria-label="t('dashboard.viewTokens')"
        >
          <span class="kpi-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <ellipse cx="12" cy="5" rx="7" ry="3" />
              <path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5" />
              <path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
            </svg>
          </span>
          <p class="kpi-label">{{ t('dashboard.tokens') }}</p>
          <strong class="kpi-value">{{ formatNumber(summary.tokens.total) }}</strong>
          <p class="kpi-hint token-detail">
            prompt {{ formatNumber(summary.tokens.prompt) }} · completion
            {{ formatNumber(summary.tokens.completion) }}
          </p>
          <span v-if="summary.tokens.estimated" class="token-flag">{{ t('dashboard.estimated') }}</span>
        </RouterLink>
      </div>
    </section>

    <section v-if="summary" class="factory-stage work-stage">
      <div class="flow-connector flow-connector-feed" aria-hidden="true">
        <span class="flow-connector-track">
          <i class="flow-connector-packet packet-1"></i>
          <i class="flow-connector-packet packet-2"></i>
          <i class="flow-connector-packet packet-3"></i>
        </span>
      </div>

      <header class="stage-rail">
        <span class="stage-index">02</span>
        <span class="stage-title">ROBOT CELL</span>
        <span class="stage-meta">RUNNING</span>
      </header>

      <div class="pipeline-strip" aria-label="Agent pipeline">
        <header class="pipeline-header">
          <span>WORK-05 / AUTOMATION LINE</span>
          <span class="pipeline-live"><i></i>RUNNING</span>
        </header>
        <div class="pipeline-track">
          <span class="pipeline-channel channel-inlet" aria-hidden="true">
            <small>IN</small>
          </span>
          <span class="pipeline-robot robot-loader" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M12 8V4H8" />
              <rect x="4" y="8" width="16" height="12" rx="2" />
              <path d="M2 14h2M20 14h2M9 13v2M15 13v2" />
            </svg>
          </span>
          <span class="pipeline-robot robot-inspector" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M12 8V4H8" />
              <rect x="4" y="8" width="16" height="12" rx="2" />
              <path d="M2 14h2M20 14h2M9 13v2M15 13v2" />
            </svg>
          </span>
          <span class="pipeline-robot robot-packer" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M12 8V4H8" />
              <rect x="4" y="8" width="16" height="12" rx="2" />
              <path d="M2 14h2M20 14h2M9 13v2M15 13v2" />
            </svg>
          </span>
          <span class="pipeline-packet packet-a" aria-hidden="true"></span>
          <span class="pipeline-packet packet-b" aria-hidden="true"></span>
          <span class="pipeline-packet packet-c" aria-hidden="true"></span>
          <span class="pipeline-node node-scan">SCAN</span>
          <span class="pipeline-node node-verify">VERIFY</span>
          <span class="pipeline-node node-evidence">EVIDENCE</span>
          <span class="pipeline-node node-archive">ARCHIVE</span>
          <span class="pipeline-channel channel-outlet" aria-hidden="true">
            <small>OUT</small>
          </span>
        </div>
      </div>

      <div class="flow-connector flow-connector-output" aria-hidden="true">
        <span class="flow-connector-track">
          <i class="flow-connector-packet packet-1"></i>
          <i class="flow-connector-packet packet-2"></i>
          <i class="flow-connector-packet packet-3"></i>
        </span>
      </div>
    </section>

    <section v-if="summary" class="factory-stage output-stage">
      <header class="stage-rail">
        <span class="stage-index">03</span>
        <span class="stage-title">FINISHED GOODS</span>
        <span class="stage-meta">VERIFIED</span>
      </header>

      <div class="command-band">
        <article class="screen-panel asset-overview" data-code="OUT-06 / ASSET STATS">
        <header class="screen-panel-header">
          <h2>{{ t('dashboard.assetTitle') }}</h2>
          <span class="panel-total">{{ formatNumber(assetTotal) }}</span>
        </header>
        <div class="asset-overview-body">
          <div class="asset-ring" :style="{ background: assetGradient }">
            <div class="asset-ring-core">
              <strong>{{ formatNumber(assetTotal) }}</strong>
              <small>ASSETS</small>
            </div>
          </div>
          <div class="asset-metrics">
            <div>
              <small>{{ t('dashboard.assetHighRisk') }}</small>
              <strong>{{ formatNumber(highRiskAssetCount) }}</strong>
            </div>
            <div>
              <small>{{ t('assetStatus.active') }}</small>
              <strong>{{ formatNumber(activeAssetCount) }}</strong>
            </div>
            <div>
              <small>{{ t('assetStatus.inactive') }}</small>
              <strong>{{ formatNumber(inactiveAssetCount) }}</strong>
            </div>
          </div>
        </div>
        <p class="asset-hint">{{ t('dashboard.assetHint') }}</p>
        </article>

        <article class="screen-panel severity-panel" data-code="OUT-07 / SEVERITY">
        <header class="screen-panel-header">
          <h2>{{ t('dashboard.severityTitle') }}</h2>
          <span class="panel-total">{{ t('common.total', { count: formatNumber(severityTotal) }) }}</span>
        </header>
        <div v-if="severityTotal > 0" class="severity-donut-row">
          <div class="severity-donut" :style="{ background: severityGradient }">
            <div class="severity-donut-core">
              <strong>{{ formatNumber(severityTotal) }}</strong>
              <small>{{ t('dashboard.vulnerabilities') }}</small>
            </div>
          </div>
          <div class="severity-highlights">
            <div>
              <small>{{ t('dashboard.criticalHigh') }}</small>
              <strong>{{ formatNumber(criticalHighCount) }}</strong>
            </div>
            <div>
              <small>{{ t('dashboard.openRisk') }}</small>
              <strong>{{ formatNumber(unresolvedCount) }}</strong>
            </div>
          </div>
        </div>
        <p v-if="severityTotal === 0" class="empty">{{ t('dashboard.empty') }}</p>
        <ul v-else class="dist-list">
          <li
            v-for="row in severityRows"
            :key="row.key"
            :class="[row.tone, { empty: row.count === 0, lead: row.count === severityMax }]"
          >
            <span class="dist-dot"></span>
            <span class="dist-label">{{ row.label }}</span>
            <span class="dist-bar">
              <i :style="{ width: barWidth(row.count, severityTotal) }"></i>
            </span>
            <span class="dist-count">{{ row.count === 0 ? '—' : formatNumber(row.count) }}</span>
            <span class="dist-percent">
              {{ row.count === 0 ? '—' : `${percent(row.count, severityTotal)}%` }}
            </span>
          </li>
        </ul>
        </article>

        <article class="screen-panel system-overview" data-code="OUT-08 / SYSTEM">
        <header class="screen-panel-header">
          <h2>{{ t('dashboard.systemTitle') }}</h2>
          <span class="panel-total">{{ versionLabel }}</span>
        </header>
        <div class="system-gauges">
          <div class="system-gauge">
            <div
              class="gauge-ring cpu-ring"
              :style="{ background: `conic-gradient(var(--accent) 0 ${cpuPercent}%, var(--surface-soft) ${cpuPercent}% 100%)` }"
            >
              <div class="gauge-core"><strong>{{ cpuPercent }}%</strong></div>
            </div>
            <small>{{ t('home.cpuUsage') }}</small>
          </div>
          <div class="system-gauge">
            <div
              class="gauge-ring memory-ring"
              :style="{ background: `conic-gradient(var(--success) 0 ${memoryPercent}%, var(--surface-soft) ${memoryPercent}% 100%)` }"
            >
              <div class="gauge-core"><strong>{{ memoryPercent }}%</strong></div>
            </div>
            <small>{{ t('home.memoryUsage') }}</small>
          </div>
        </div>
        <dl class="system-meta">
          <div>
            <dt>{{ t('home.hostname') }}</dt>
            <dd>{{ system.stats?.hostname || '-' }}</dd>
          </div>
          <div>
            <dt>{{ t('dashboard.os') }}</dt>
            <dd>{{ system.stats?.os || '-' }} / {{ system.stats?.arch || '-' }}</dd>
          </div>
          <div>
            <dt>{{ t('home.memoryUsage') }}</dt>
            <dd>{{ memoryText }}</dd>
          </div>
          <div>
            <dt>{{ t('home.uptime') }}</dt>
            <dd>{{ uptimeLabel }}</dd>
          </div>
        </dl>
        <p v-if="system.error" class="system-error">{{ t('dashboard.systemUnavailable') }}</p>
        </article>
      </div>
    </section>

    <section v-if="summary" class="factory-stage token-stage">
      <header class="stage-rail">
        <span class="stage-index">04</span>
        <span class="stage-title">LLM TOKEN</span>
        <span class="stage-meta">{{ tokenSource.toUpperCase() }}</span>
      </header>

      <article class="token-console" :class="{ loading: tokenLoading }">
        <header class="token-console-head">
          <div class="token-title">
            <span class="token-bolt" aria-hidden="true">ϟ</span>
            <div>
              <h2>{{ t('dashboard.tokenTitle') }}</h2>
              <small>{{ tokenSource }}</small>
            </div>
          </div>
          <div class="token-segments" :aria-label="t('dashboard.tokenVersion')">
            <button
              type="button"
              :class="{ active: tokenVersion === 'old' }"
              @click="tokenVersion = 'old'"
            >
              {{ t('dashboard.tokenVersionOld') }}
            </button>
            <button
              type="button"
              :class="{ active: tokenVersion === 'new' }"
              @click="tokenVersion = 'new'"
            >
              {{ t('dashboard.tokenVersionNew') }}
            </button>
          </div>
          <div class="token-models" :aria-label="t('dashboard.tokenModel')">
            <button
              type="button"
              :class="{ active: tokenModel === '' }"
              @click="tokenModel = ''"
            >
              {{ t('dashboard.tokenAllModels') }}
            </button>
            <button
              v-for="model in tokenStats?.models ?? []"
              :key="model.model || '__default__'"
              type="button"
              :class="{ active: tokenModel === (model.model || '__default__') }"
              @click="tokenModel = model.model || '__default__'"
            >
              {{ tokenModelLabel(model.model) }}
              <small v-if="model.model === ''">{{ t('dashboard.tokenDefaultBadge') }}</small>
            </button>
          </div>
        </header>

        <p v-if="tokenError" class="token-error">{{ tokenError }}</p>

        <div class="token-layout">
          <section class="token-metrics">
            <div class="token-total">
              <small>{{ t('dashboard.tokenTotal') }}</small>
              <strong>{{ formatTokenCompact(tokenTotal) }}</strong>
              <span>{{ t('dashboard.tokenTasks', { count: tokenStats?.taskCount ?? 0 }) }}</span>
            </div>

            <div class="token-metric-list">
              <div class="token-metric input">
                <header>
                  <span>{{ t('dashboard.tokenUncachedInput') }}</span>
                  <strong>{{ formatTokenCompact(tokenInputUncached) }}</strong>
                </header>
                <i :style="{ width: `${tokenTotal > 0 ? (tokenInputUncached / tokenTotal) * 100 : 0}%` }"></i>
              </div>
              <div class="token-metric cache">
                <header>
                  <span>{{ t('dashboard.tokenCacheHit') }}</span>
                  <strong>{{ formatTokenCompact(tokenCacheRead) }}</strong>
                </header>
                <i :style="{ width: `${tokenTotal > 0 ? (tokenCacheRead / tokenTotal) * 100 : 0}%` }"></i>
              </div>
              <div class="token-metric output">
                <header>
                  <span>{{ t('dashboard.tokenOutput') }}</span>
                  <strong>{{ formatTokenCompact(tokenOutput) }}</strong>
                </header>
                <i :style="{ width: `${tokenTotal > 0 ? (tokenOutput / tokenTotal) * 100 : 0}%` }"></i>
              </div>
            </div>

            <div class="token-hit-rate">
              <span>{{ t('dashboard.tokenCacheRate') }}</span>
              <strong>{{ tokenHitRate }}%</strong>
            </div>
            <span v-if="tokenStats?.estimated" class="token-estimated">
              {{ t('dashboard.estimated') }}
            </span>
          </section>

          <section class="token-chart-panel">
            <header>
              <div class="token-legend">
                <span class="input"><i></i>{{ t('dashboard.tokenInput') }}</span>
                <span class="output"><i></i>{{ t('dashboard.tokenOutput') }}</span>
                <span class="cache"><i></i>{{ t('dashboard.tokenCacheRead') }}</span>
              </div>
              <div class="token-ranges">
                <button
                  v-for="range in TOKEN_RANGES"
                  :key="range.days"
                  type="button"
                  :class="{ active: tokenDays === range.days }"
                  @click="tokenDays = range.days"
                >
                  {{ t(range.label) }}
                </button>
              </div>
            </header>

            <div v-if="tokenChartRows.length === 0" class="token-chart-empty">
              {{ t('dashboard.tokenNoData') }}
            </div>
            <div v-else class="token-chart-scroll">
              <svg
                class="token-chart"
                :viewBox="`0 0 ${tokenChartGeometry.width} ${tokenChartGeometry.height}`"
                role="img"
                :aria-label="t('dashboard.tokenChartLabel')"
              >
                <line
                  v-for="line in 4"
                  :key="line"
                  class="token-grid-line"
                  x1="0"
                  :x2="tokenChartGeometry.width"
                  :y1="tokenChartGeometry.top + (tokenChartGeometry.plotHeight / 4) * (line - 1)"
                  :y2="tokenChartGeometry.top + (tokenChartGeometry.plotHeight / 4) * (line - 1)"
                />
                <g
                  v-for="(bar, index) in tokenChartGeometry.bars"
                  :key="bar.date"
                  tabindex="0"
                  role="img"
                  class="token-battery"
                  :class="{ full: tokenChartMax > 0 && bar.total === tokenChartMax }"
                  :aria-label="`${bar.date} ${t('dashboard.tokenTotal')} ${formatNumber(bar.total)}`"
                  @mouseenter="showTokenTooltip($event, bar)"
                  @mousemove="moveTokenTooltip"
                  @mouseleave="hideTokenTooltip"
                  @focus="showTokenTooltip($event, bar)"
                  @blur="hideTokenTooltip"
                >
                  <rect
                    class="token-battery-shell"
                    :x="bar.shellX"
                    :y="bar.shellY"
                    :width="bar.shellWidth"
                    :height="bar.shellHeight"
                    rx="4"
                  />
                  <rect
                    class="token-battery-terminal"
                    :x="bar.terminalX"
                    :y="bar.terminalY"
                    :width="bar.terminalWidth"
                    :height="bar.terminalHeight"
                    rx="2"
                  />
                  <rect
                    v-for="(cell, cellIndex) in bar.cells"
                    :key="`cell-${cellIndex}`"
                    class="token-battery-cell"
                    :x="cell.x"
                    :y="cell.y"
                    :width="cell.width"
                    :height="cell.height"
                    rx="1.5"
                  />
                  <rect
                    class="token-bar input"
                    :x="bar.x"
                    :y="bar.inputY"
                    :width="bar.barWidth"
                    :height="bar.inputHeight"
                    rx="1"
                  />
                  <rect
                    class="token-bar output"
                    :x="bar.x"
                    :y="bar.outputY"
                    :width="bar.barWidth"
                    :height="bar.outputHeight"
                    rx="1"
                  />
                  <rect
                    class="token-bar cache"
                    :x="bar.x"
                    :y="bar.cacheY"
                    :width="bar.barWidth"
                    :height="bar.cacheHeight"
                    rx="1"
                  />
                  <line
                    v-for="(gap, gapIndex) in bar.cellGaps"
                    :key="`gap-${gapIndex}`"
                    class="token-battery-gap"
                    :x1="gap.x1"
                    :x2="gap.x2"
                    :y1="gap.y"
                    :y2="gap.y"
                  />
                  <text
                    v-if="tokenChartRows.length <= 14 || index % Math.ceil(tokenChartRows.length / 8) === 0"
                    class="token-axis-label"
                    :x="bar.x + bar.barWidth / 2"
                    :y="tokenChartGeometry.height - 7"
                    text-anchor="middle"
                  >
                    {{ bar.date.slice(5) }}
                  </text>
                </g>
              </svg>
            </div>
          </section>
        </div>
      </article>

      <div
        v-if="tokenTooltip"
        class="token-chart-tooltip"
        role="tooltip"
        :style="{ left: `${tokenTooltip.x}px`, top: `${tokenTooltip.y}px` }"
      >
        <strong>{{ tokenTooltip.bar.date }}</strong>
        <dl>
          <div><dt>{{ t('dashboard.tokenInput') }}</dt><dd>{{ formatNumber(tokenTooltip.bar.input) }}</dd></div>
          <div><dt>{{ t('dashboard.tokenCacheRead') }}</dt><dd>{{ formatNumber(tokenTooltip.bar.cache) }}</dd></div>
          <div><dt>{{ t('dashboard.tokenOutput') }}</dt><dd>{{ formatNumber(tokenTooltip.bar.output) }}</dd></div>
          <div class="total"><dt>{{ t('dashboard.tokenTotal') }}</dt><dd>{{ formatNumber(tokenTooltip.bar.total) }}</dd></div>
        </dl>
      </div>
    </section>

    <footer v-if="summary" class="screen-footer">
      <span><i class="footer-dot"></i>{{ t('dashboard.dataSource') }}</span>
      <span>{{ t('dashboard.lastUpdated') }} {{ lastUpdatedText }}</span>
      <span>{{ t('dashboard.refreshIn', { seconds: refreshSeconds }) }}</span>
    </footer>
  </section>
</template>

<style scoped>
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 12px;
}

.kpi-card {
  position: relative;
  display: grid;
  gap: 6px;
  min-height: 112px;
  align-content: center;
  padding: 16px 16px 16px 76px;
  overflow: hidden;
  border: 1px dashed color-mix(in srgb, var(--text-muted) 48%, var(--border));
  border-radius: 4px;
  color: inherit;
  background: var(--surface);
  background-image: repeating-linear-gradient(
    135deg,
    color-mix(in srgb, var(--text-primary) 2%, transparent) 0 1px,
    transparent 1px 7px
  );
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--text-primary) 5%, transparent),
    0 1px 2px rgba(0, 0, 0, 0.28);
  text-decoration: none;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.kpi-icon {
  position: absolute;
  top: 50%;
  left: 16px;
  display: grid;
  width: 44px;
  height: 44px;
  place-items: center;
  border: 1px dashed var(--border-strong);
  border-radius: 4px;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 8%, transparent);
  transform: translateY(-50%);
}

.kpi-icon svg {
  width: 24px;
  height: 24px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.kpi-card:nth-child(2) .kpi-icon {
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 16%, transparent);
}

.kpi-card:nth-child(3) .kpi-icon {
  color: var(--accent-strong);
  background: color-mix(in srgb, var(--accent-strong) 16%, transparent);
}

.kpi-card:nth-child(4) .kpi-icon {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 16%, transparent);
}

.kpi-card::after {
  position: absolute;
  right: 16px;
  bottom: 9px;
  left: 76px;
  height: 3px;
  content: '';
  background-image: repeating-linear-gradient(
    90deg,
    var(--border) 0 1px,
    transparent 1px 8px
  );
  opacity: 0.3;
}

.kpi-card:hover,
.kpi-card:focus-visible {
  border-color: var(--accent);
  border-style: solid;
  outline: none;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.34);
  transform: none;
}

.kpi-card::before {
  position: absolute;
  top: 10px;
  right: 16px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
  letter-spacing: 0.06em;
  content: attr(data-code);
}

.kpi-card:nth-child(1) {
  color: inherit;
  background: var(--surface);
}

.kpi-card:nth-child(2) {
  color: inherit;
  background: var(--surface);
}

.kpi-card:nth-child(3) {
  color: inherit;
  background: var(--surface);
}

.kpi-label {
  margin: 0;
  color: var(--text-muted);
  font-size: 13px;
}

.kpi-value {
  font-size: 28px;
  font-weight: 400;
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.kpi-card:nth-child(1) .kpi-value {
  color: var(--text-primary);
}

.kpi-card:nth-child(1) .kpi-label,
.kpi-card:nth-child(1) .kpi-hint {
  color: var(--text-muted);
}

.kpi-card:nth-child(2) .kpi-label,
.kpi-card:nth-child(2) .kpi-hint,
.kpi-card:nth-child(3) .kpi-label,
.kpi-card:nth-child(3) .kpi-hint {
  color: var(--text-muted);
}

.kpi-hint {
  margin: 0;
  color: var(--text-muted);
  font-size: 12px;
}

.token-detail {
  color: var(--text-muted);
  font-size: 12px;
}

.token-flag {
  justify-self: start;
  padding: 2px 8px;
  border: 1px solid var(--warning);
  border-radius: var(--radius);
  color: var(--warning);
  background: var(--accent-soft);
  font-size: 12px;
}

.panel-total {
  padding: 3px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: var(--field-bg);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}

.empty {
  margin: 0;
  padding: 14px 0;
  color: var(--text-muted);
  font-size: 13px;
}

.dist-list {
  display: grid;
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.dist-list li {
  display: grid;
  grid-template-columns: 8px minmax(56px, auto) minmax(0, 1fr) 40px 48px;
  gap: 10px;
  align-items: center;
  font-size: 12.5px;
  transition: opacity 0.15s ease;
}

.dist-list li.empty {
  opacity: 0.55;
}

.dist-list li.lead .dist-label {
  color: var(--text-primary);
  font-weight: 600;
}

.dist-list li.lead .dist-count {
  color: var(--tone-to);
}

.dist-dot {
  width: 7px;
  height: 7px;
  border: 1px solid var(--line);
  border-radius: 50%;
  background: var(--tone-to);
}

.dist-label {
  color: var(--text-secondary);
  font-weight: 500;
  white-space: nowrap;
}

.dist-bar {
  position: relative;
  height: 10px;
  overflow: hidden;
  border-radius: var(--radius);
  background: var(--surface-soft);
  box-shadow: inset 0 0 0 1px var(--border-strong);
  transition: box-shadow 0.15s ease;
}

.dist-list li:hover .dist-bar {
  box-shadow: inset 0 0 0 1px var(--line);
}

.dist-bar i {
  display: block;
  height: 100%;
  border-radius: var(--radius);
  background: var(--tone-to);
  transform-origin: left center;
  animation: dist-grow 0.5s ease-out both;
}

.dist-count {
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 600;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.dist-percent {
  color: var(--text-muted);
  font-size: 11px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

@keyframes dist-grow {
  from {
    transform: scaleX(0);
  }

  to {
    transform: scaleX(1);
  }
}

@media (prefers-reduced-motion: reduce) {
  .dist-bar i {
    animation: none;
  }
}

.bar-critical {
  --tone-from: var(--danger);
  --tone-to: var(--danger);
}

.bar-high {
  --tone-from: var(--warning);
  --tone-to: var(--warning);
}

.bar-medium {
  --tone-from: #ffbc33;
  --tone-to: #ffbc33;
}

.bar-low {
  --tone-from: var(--accent-strong);
  --tone-to: var(--accent-strong);
}

.bar-info {
  --tone-from: #8b949e;
  --tone-to: #6e7681;
}

.asset-overview .bar-critical {
  --tone-from: #ff8a4c;
  --tone-to: #ff8a4c;
}

.asset-overview .bar-high {
  --tone-from: #ffd166;
  --tone-to: #ffd166;
}

.asset-overview .bar-medium {
  --tone-from: #35c8dc;
  --tone-to: #35c8dc;
}

.asset-overview .bar-low {
  --tone-from: #4fd6a0;
  --tone-to: #4fd6a0;
}

.asset-overview .bar-info {
  --tone-from: #7f91aa;
  --tone-to: #7f91aa;
}

.severity-panel .bar-critical {
  --tone-from: #ff3e1d;
  --tone-to: #ff3e1d;
}

.severity-panel .bar-high {
  --tone-from: #ffab00;
  --tone-to: #ffab00;
}

.severity-panel .bar-medium {
  --tone-from: #ffbc33;
  --tone-to: #ffbc33;
}

.severity-panel .bar-low {
  --tone-from: #03c3ec;
  --tone-to: #03c3ec;
}

.severity-panel .bar-info {
  --tone-from: #8592a3;
  --tone-to: #8592a3;
}

@media (max-width: 520px) {
  .dist-list li {
    grid-template-columns: 8px minmax(48px, auto) minmax(0, 1fr) 34px;
  }

  .dist-percent {
    display: none;
  }
}

.dashboard-screen {
  display: grid;
  gap: 12px;
}

.dashboard-header {
  position: relative;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  min-height: 96px;
  padding: 16px 20px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-primary);
  background-color: var(--surface);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.28);
}

.dashboard-header::before {
  position: absolute;
  top: 0;
  left: 0;
  width: 180px;
  height: 3px;
  content: '';
  background: linear-gradient(to right, #2c5364, #203a43, #0f2027);
  box-shadow: none;
}

.dashboard-heading {
  position: relative;
  z-index: 1;
}

.dashboard-title-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.dashboard-heading h1 {
  margin: 0;
  font-size: 28px;
  font-weight: 400;
  line-height: 1.15;
}

.dashboard-heading .eyebrow {
  color: var(--accent-strong);
}

.dashboard-heading .brand-icon {
  border-color: var(--border-strong);
  box-shadow: none;
}

.dashboard-live {
  position: relative;
  z-index: 1;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 10px 14px;
}

.dashboard-clock strong {
  color: var(--text-primary);
}

.dashboard-clock small,
.dashboard-header .refresh-countdown {
  color: var(--sidebar-text);
}

.live-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 5px 10px;
  border: 1px solid var(--accent-line);
  border-radius: var(--radius);
  color: var(--accent-strong);
  background: var(--accent-soft);
  font-size: 12px;
  font-weight: 700;
}

.live-badge i {
  width: 7px;
  height: 7px;
  border: 1px solid var(--line);
  border-radius: 50%;
  background: var(--success);
  box-shadow: none;
  animation: live-pulse 1.6s ease-in-out infinite;
}

@keyframes live-pulse {
  0%,
  100% {
    opacity: 0.45;
  }

  50% {
    opacity: 1;
  }
}

.dashboard-clock {
  display: grid;
  justify-items: end;
}

.dashboard-clock strong {
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
}

.dashboard-clock small,
.refresh-countdown {
  color: var(--text-muted);
  font-size: 11px;
}

.flow-connector {
  --connector-lane: 0;
  --connector-color: var(--border-strong);
  display: grid;
  grid-template-columns: 160px minmax(0, 1fr);
  gap: 18px;
  align-items: stretch;
  min-height: 54px;
  padding: 0 16px;
}

.flow-connector-label {
  align-self: center;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
  letter-spacing: 0.08em;
  white-space: nowrap;
}

.flow-connector-feed {
  --connector-color: var(--accent);
}

.flow-connector-output {
  --connector-lane: calc(100% - 13px);
  --connector-color: var(--success);
}

.flow-connector-feed .flow-connector-label {
  color: var(--accent);
}

.flow-connector-output .flow-connector-label {
  color: var(--success);
}

.flow-connector-track {
  position: relative;
  display: block;
  height: 54px;
  overflow: hidden;
}

.flow-connector-track::before {
  position: absolute;
  top: 0;
  bottom: 0;
  left: var(--connector-lane);
  width: 13px;
  border-inline: 1px dashed color-mix(in srgb, var(--connector-color) 50%, var(--border));
  background-image: repeating-linear-gradient(
    180deg,
    color-mix(in srgb, var(--connector-color) 34%, transparent) 0 1px,
    transparent 1px 7px
  );
  content: '';
}

.flow-connector-track::after {
  position: absolute;
  bottom: 0;
  left: calc(var(--connector-lane) + 3px);
  width: 5px;
  height: 5px;
  border-right: 1px solid var(--connector-color);
  border-bottom: 1px solid var(--connector-color);
  content: '';
  transform: rotate(45deg);
}

.flow-connector-packet {
  position: absolute;
  top: -10px;
  left: calc(var(--connector-lane) + 1px);
  z-index: 1;
  width: 11px;
  height: 9px;
  border: 1px solid color-mix(in srgb, var(--text-primary) 22%, transparent);
  border-radius: 1px;
  background: var(--connector-color);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.28);
  animation: connector-drop 3.6s linear infinite;
}

.flow-connector-packet::after {
  position: absolute;
  inset: 2px;
  border-inline: 1px solid color-mix(in srgb, var(--text-primary) 32%, transparent);
  content: '';
}

.flow-connector-packet.packet-2 {
  animation-delay: 1.2s;
}

.flow-connector-packet.packet-3 {
  animation-delay: 2.4s;
}

@keyframes connector-drop {
  0% {
    top: -10px;
    opacity: 0;
  }

  10% {
    opacity: 1;
  }

  90% {
    opacity: 1;
  }

  100% {
    top: 100%;
    opacity: 0;
  }
}

.command-band {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 12px;
}

.screen-panel {
  --panel-accent: var(--stage-output);
  --panel-mark: 'S';
  position: relative;
  min-width: 0;
  padding: 34px 18px 22px;
  border: 1px solid color-mix(in srgb, var(--panel-accent) 20%, var(--border));
  border-radius: 8px;
  background: var(--surface);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--panel-accent) 18%, transparent),
    0 8px 22px rgba(20, 20, 29, 0.2);
}

.screen-panel::before {
  position: absolute;
  top: 12px;
  left: 18px;
  color: color-mix(in srgb, var(--panel-accent) 72%, var(--text-muted));
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
  letter-spacing: 0.08em;
  content: attr(data-code);
}

.screen-panel::after {
  position: absolute;
  right: 18px;
  bottom: 9px;
  left: 18px;
  height: 3px;
  content: '';
  background-image: repeating-linear-gradient(
    90deg,
    color-mix(in srgb, var(--panel-accent) 55%, transparent) 0 7px,
    transparent 7px 11px
  );
  opacity: 0.38;
}

.asset-overview,
.severity-panel,
.system-overview {
  grid-column: span 4;
}

.asset-overview {
  --panel-accent: #35c8dc;
  --panel-mark: 'A';
}

.severity-panel {
  --panel-accent: #ff6b4a;
  --panel-mark: '!';
}

.system-overview {
  --panel-accent: #7f91aa;
  --panel-mark: 'S';
}

.screen-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.screen-panel-header h2 {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  margin: 0;
  font-size: 15px;
}

.screen-panel-header h2::before {
  display: grid;
  width: 16px;
  height: 16px;
  flex: 0 0 auto;
  place-items: center;
  content: var(--panel-mark);
  border: 1px solid color-mix(in srgb, var(--panel-accent) 52%, var(--border));
  border-radius: 4px;
  color: var(--panel-accent);
  background: color-mix(in srgb, var(--panel-accent) 10%, transparent);
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 700;
  line-height: 1;
}

.asset-overview-body {
  display: flex;
  align-items: center;
  gap: 22px;
  min-height: 144px;
}

.asset-ring,
.gauge-ring {
  position: relative;
  display: grid;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 50%;
}

.asset-ring {
  width: 138px;
  height: 138px;
  box-shadow: 0 0 24px color-mix(in srgb, #35c8dc 10%, transparent);
}

.asset-ring-core,
.gauge-core {
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: var(--surface);
  text-align: center;
}

.asset-ring-core {
  width: 104px;
  height: 104px;
  box-shadow: inset 0 0 0 1px var(--border-strong);
}

.asset-ring-core strong {
  font-family: var(--mono);
  font-size: 32px;
  line-height: 1;
}

.asset-ring-core small {
  color: var(--text-muted);
  font-size: 11px;
}

.asset-metrics {
  display: grid;
  flex: 1;
  gap: 10px;
  min-width: 0;
}

.asset-metrics > div {
  display: grid;
  gap: 3px;
  padding: 9px 10px;
  border-left: 3px solid var(--panel-accent);
  background: var(--surface-soft);
}

.asset-metrics small {
  color: var(--text-muted);
  font-size: 11px;
}

.asset-metrics strong {
  font-family: var(--mono);
  font-size: 19px;
  font-variant-numeric: tabular-nums;
}

.asset-hint {
  margin: 10px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.asset-overview .panel-total {
  border-color: color-mix(in srgb, #35c8dc 34%, var(--border));
  color: #35c8dc;
}

.severity-panel .panel-total {
  border-color: color-mix(in srgb, #ff6b4a 34%, var(--border));
  color: #ff6b4a;
}

.system-gauges {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}

.system-gauge {
  display: grid;
  justify-items: center;
  gap: 7px;
}

.system-gauge small {
  color: var(--text-muted);
  font-size: 11px;
  text-align: center;
}

.gauge-ring {
  width: 88px;
  height: 88px;
}

.gauge-core {
  width: 66px;
  height: 66px;
  box-shadow: inset 0 0 0 1px var(--border-strong);
}

.gauge-core strong {
  font-family: var(--mono);
  font-size: 15px;
}

.system-meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 12px;
  margin: 0;
}

.system-meta div {
  min-width: 0;
}

.system-meta dt {
  color: var(--text-muted);
  font-size: 10px;
}

.system-meta dd {
  margin: 2px 0 0;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.system-error {
  margin: 10px 0 0;
  color: var(--warning);
  font-size: 11px;
}

.severity-donut-row {
  display: flex;
  align-items: center;
  gap: 22px;
  margin-bottom: 18px;
  padding: 14px;
  border: 1px solid color-mix(in srgb, #ff6b4a 22%, var(--border));
  border-radius: var(--radius);
  background: color-mix(in srgb, #ff6b4a 4%, var(--surface-soft));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, #ff6b4a 12%, var(--border));
}

.severity-donut {
  display: grid;
  width: 108px;
  height: 108px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 50%;
  box-shadow: 0 0 24px color-mix(in srgb, #ff6b4a 10%, transparent);
}

.severity-donut-core {
  display: grid;
  width: 78px;
  height: 78px;
  place-items: center;
  border-radius: 50%;
  background: var(--surface);
  box-shadow: inset 0 0 0 1px var(--border);
  text-align: center;
}

.severity-donut-core strong {
  font-family: var(--mono);
  font-size: 22px;
  line-height: 1;
}

.severity-donut-core small {
  color: var(--text-muted);
  font-size: 10px;
}

.severity-highlights {
  display: grid;
  flex: 1;
  gap: 9px;
}

.severity-highlights > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 7px;
  border-bottom: 1px solid var(--border);
}

.severity-highlights > div:last-child {
  padding-bottom: 0;
  border-bottom: 0;
}

.severity-highlights small {
  color: var(--text-muted);
  font-size: 11px;
}

.severity-highlights strong {
  font-family: var(--mono);
  font-size: 18px;
  font-variant-numeric: tabular-nums;
}

.pipeline-strip {
  display: grid;
  grid-template-columns: 160px minmax(0, 1fr);
  gap: 18px;
  align-items: center;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: 0 4px 18px rgba(20, 20, 29, 0.18);
}

.pipeline-header {
  display: grid;
  gap: 5px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 600;
  letter-spacing: 0.1em;
}

.pipeline-live {
  display: inline-flex;
  gap: 6px;
  align-items: center;
  color: var(--success);
  font-size: 8px;
}

.pipeline-live i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: live-pulse 1.6s ease-in-out infinite;
}

.pipeline-track {
  --pipeline-start: 42px;
  position: relative;
  display: grid;
  height: 38px;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  align-items: center;
  padding-left: var(--pipeline-start);
}

.pipeline-track::before {
  position: absolute;
  top: 50%;
  right: 0;
  left: var(--pipeline-start);
  height: 2px;
  content: '';
  background: var(--border);
}

.pipeline-track::after {
  position: absolute;
  top: calc(50% + 5px);
  right: 0;
  left: var(--pipeline-start);
  height: 5px;
  content: '';
  background-image: repeating-linear-gradient(
    90deg,
    var(--border) 0 1px,
    transparent 1px 10px
  );
  opacity: 0.7;
}

.pipeline-robot {
  position: absolute;
  top: 50%;
  left: 2px;
  z-index: 4;
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 1px solid var(--accent-line);
  border-radius: 50%;
  color: var(--accent);
  background: var(--surface-soft);
  box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 10%, transparent);
  transform: translateY(-50%);
  animation: robot-hover 2.4s ease-in-out infinite;
}

.pipeline-robot::after {
  position: absolute;
  bottom: -11px;
  left: 50%;
  width: 2px;
  height: 10px;
  content: '';
  background: var(--accent-line);
}

.pipeline-robot svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

@keyframes robot-hover {
  0%,
  100% {
    transform: translateY(-50%);
  }

  50% {
    transform: translateY(calc(-50% - 2px));
  }
}

.pipeline-node {
  position: relative;
  z-index: 2;
  display: inline-flex;
  gap: 5px;
  align-items: center;
  justify-self: center;
  padding: 4px 7px;
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-muted);
  background: var(--surface);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
  letter-spacing: 0.05em;
}

.pipeline-node::before {
  width: 5px;
  height: 5px;
  content: '';
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent);
}

.pipeline-node:nth-of-type(6)::before {
  background: var(--accent-strong);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-strong) 14%, transparent);
}

.pipeline-node:nth-of-type(7)::before {
  background: var(--warning);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--warning) 14%, transparent);
}

.pipeline-node:nth-of-type(8)::before {
  background: var(--success);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--success) 14%, transparent);
}

.pipeline-packet {
  position: absolute;
  top: 50%;
  left: var(--pipeline-start);
  z-index: 3;
  width: 17px;
  height: 13px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--text-primary) 28%, transparent);
  border-radius: 2px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.28);
  transform: translateY(-50%);
  animation: pipeline-run 6s linear infinite;
}

.pipeline-packet::before {
  position: absolute;
  inset: 1px;
  content: '';
  background:
    linear-gradient(
      45deg,
      transparent 46%,
      color-mix(in srgb, var(--text-primary) 36%, transparent) 47% 53%,
      transparent 54%
    ),
    linear-gradient(
      -45deg,
      transparent 46%,
      color-mix(in srgb, var(--text-primary) 36%, transparent) 47% 53%,
      transparent 54%
    );
}

.packet-a {
  background: var(--accent);
}

.packet-b {
  background: var(--accent-strong);
  animation-delay: 2s;
}

.packet-c {
  background: var(--success);
  animation-delay: 4s;
}

@keyframes pipeline-run {
  0% {
    left: var(--pipeline-start);
    opacity: 0;
  }

  8% {
    opacity: 1;
  }

  90% {
    opacity: 1;
  }

  100% {
    left: calc(100% + 4px);
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .flow-connector-packet {
    display: none;
  }

  .pipeline-packet {
    display: none;
  }

  .pipeline-live i {
    animation: none;
  }

  .pipeline-robot {
    animation: none;
  }
}

.screen-footer {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px 18px;
  padding: 10px 4px 0;
  color: var(--text-muted);
  font-size: 11px;
}

.screen-footer span {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.footer-dot {
  width: 6px;
  height: 6px;
  border: 1px solid var(--line);
  border-radius: 50%;
  background: var(--success);
  box-shadow: none;
}

@media (max-width: 1100px) {
  .command-band {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .asset-overview,
  .severity-panel,
  .system-overview {
    grid-column: span 1;
  }

  .system-overview {
    grid-column: span 2;
  }
}

@media (max-width: 760px) {
  .dashboard-header {
    flex-direction: column;
    padding: 20px;
  }

  .dashboard-live {
    justify-content: flex-start;
  }

  .command-band {
    grid-template-columns: 1fr;
  }

  .pipeline-strip {
    grid-template-columns: 1fr;
    gap: 10px;
    padding: 12px;
  }

  .flow-connector {
    grid-template-columns: 132px minmax(0, 1fr);
    gap: 10px;
    min-height: 44px;
    padding-inline: 4px;
  }

  .flow-connector-track {
    height: 44px;
  }

  .pipeline-track {
    --pipeline-start: 36px;
    height: 42px;
  }

  .pipeline-robot {
    left: 0;
    width: 25px;
    height: 25px;
  }

  .pipeline-node {
    padding: 3px 5px;
    font-size: 7px;
  }

  .asset-overview,
  .severity-panel,
  .system-overview {
    grid-column: span 1;
  }

  .asset-overview-body,
  .severity-donut-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .asset-overview-body {
    display: grid;
    grid-template-columns: 108px minmax(0, 1fr);
  }

  .asset-ring {
    width: 108px;
    height: 108px;
  }

  .asset-ring-core {
    width: 82px;
    height: 82px;
  }

  .asset-ring-core strong {
    font-size: 26px;
  }

  .asset-metrics > div {
    padding: 7px 8px;
  }

  .asset-metrics strong {
    font-size: 16px;
  }

  .system-meta {
    grid-template-columns: 1fr;
  }
}

/* Factory floor redesign */
.dashboard-screen {
  --stage-raw: #f0a43a;
  --stage-work: #55c7e8;
  --stage-output: var(--success);
  --factory-panel: color-mix(in srgb, var(--surface) 94%, #0b0b10);
  --factory-line: color-mix(in srgb, var(--border-strong) 72%, transparent);
  gap: 12px;
}

.factory-header {
  position: relative;
  display: grid;
  grid-template-columns: minmax(230px, 1fr) auto minmax(340px, auto);
  align-items: center;
  gap: 22px;
  min-height: 88px;
  padding: 14px 18px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--stage-raw) 7%, transparent), transparent 28%),
    var(--factory-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--text-primary) 5%, transparent),
    0 8px 24px rgba(0, 0, 0, 0.18);
}

.factory-header::before {
  top: 0;
  left: 0;
  width: 72px;
  height: 2px;
  background: var(--stage-raw);
}

.factory-code {
  display: block;
  margin-bottom: 4px;
  color: var(--stage-raw);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.14em;
}

.dashboard-heading .eyebrow {
  margin: 0 0 3px;
  color: var(--text-muted);
  font-size: 9px;
  letter-spacing: 0.12em;
}

.dashboard-heading h1 {
  font-size: 26px;
  font-weight: 500;
}

.factory-route {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.1em;
  white-space: nowrap;
}

.factory-route span:nth-of-type(1) {
  color: var(--stage-raw);
}

.factory-route span:nth-of-type(2) {
  color: var(--stage-work);
}

.factory-route span:nth-of-type(3) {
  color: var(--stage-output);
}

.factory-route i {
  position: relative;
  width: 28px;
  height: 1px;
  background: var(--factory-line);
}

.factory-route i::after {
  position: absolute;
  top: -2px;
  right: 0;
  width: 4px;
  height: 4px;
  border-top: 1px solid var(--text-muted);
  border-right: 1px solid var(--text-muted);
  content: '';
  transform: rotate(45deg);
}

.factory-header .dashboard-live {
  gap: 9px 12px;
}

.factory-header .live-badge {
  border-radius: 3px;
  color: var(--stage-output);
  border-color: color-mix(in srgb, var(--stage-output) 35%, var(--border));
  background: color-mix(in srgb, var(--stage-output) 8%, transparent);
  font-size: 10px;
  letter-spacing: 0.04em;
}

.dashboard-clock strong {
  font-size: 18px;
}

.factory-stage {
  --stage-color: var(--border-strong);
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 12px;
  align-items: stretch;
}

.raw-stage {
  --stage-color: var(--stage-raw);
}

.work-stage {
  position: relative;
  --stage-color: var(--stage-work);
}

.output-stage {
  --stage-color: var(--stage-output);
}

.stage-rail {
  position: relative;
  display: grid;
  grid-template-rows: auto 1fr auto;
  justify-items: start;
  min-width: 0;
  padding: 12px 10px 11px 12px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-left: 2px solid var(--stage-color);
  border-radius: 5px;
  background:
    repeating-linear-gradient(
      180deg,
      color-mix(in srgb, var(--stage-color) 7%, transparent) 0 1px,
      transparent 1px 8px
    ),
    var(--factory-panel);
}

.stage-rail::after {
  position: absolute;
  top: 0;
  right: 7px;
  bottom: 0;
  width: 1px;
  content: '';
  background: repeating-linear-gradient(
    180deg,
    var(--factory-line) 0 2px,
    transparent 2px 8px
  );
  opacity: 0.55;
}

.stage-index {
  color: var(--stage-color);
  font-family: var(--mono);
  font-size: 27px;
  font-weight: 400;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}

.stage-title {
  align-self: center;
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.09em;
  line-height: 1.25;
  text-orientation: mixed;
  writing-mode: vertical-rl;
}

.stage-meta {
  color: var(--stage-color);
  font-family: var(--mono);
  font-size: 7px;
  font-weight: 700;
  letter-spacing: 0.06em;
  white-space: nowrap;
}

.kpi-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.kpi-card {
  min-height: 132px;
  padding: 24px 16px 20px 70px;
  border: 1px solid color-mix(in srgb, var(--stage-raw) 18%, var(--border));
  border-radius: 4px;
  background-color: var(--factory-panel);
  background-image:
    linear-gradient(90deg, color-mix(in srgb, var(--stage-raw) 5%, transparent), transparent 28%),
    repeating-linear-gradient(
      90deg,
      color-mix(in srgb, var(--text-primary) 2%, transparent) 0 1px,
      transparent 1px 12px
    );
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--stage-raw) 10%, transparent),
    0 3px 12px rgba(0, 0, 0, 0.17);
}

.kpi-card::before {
  top: 12px;
  right: 14px;
  color: color-mix(in srgb, var(--stage-raw) 65%, var(--text-muted));
  font-size: 7px;
}

.kpi-card::after {
  right: 16px;
  bottom: 0;
  left: 70px;
  width: auto;
  height: 2px;
  background: repeating-linear-gradient(
    90deg,
    color-mix(in srgb, var(--stage-raw) 62%, transparent) 0 8px,
    transparent 8px 13px
  );
  opacity: 0.55;
}

.kpi-card:hover,
.kpi-card:focus-visible {
  border-color: color-mix(in srgb, var(--stage-raw) 58%, var(--border));
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--stage-raw) 16%, transparent),
    0 7px 18px rgba(0, 0, 0, 0.24);
  transform: translateY(-2px);
}

.kpi-icon {
  top: 42%;
  left: 16px;
  width: 40px;
  height: 40px;
  border-style: solid;
  border-color: color-mix(in srgb, var(--stage-raw) 34%, var(--border));
  border-radius: 3px;
  background: color-mix(in srgb, var(--stage-raw) 8%, transparent);
  box-shadow: inset 0 0 0 3px color-mix(in srgb, var(--surface) 62%, transparent);
}

.kpi-label {
  font-size: 12px;
}

.kpi-value {
  font-size: 30px;
  font-weight: 500;
}

.kpi-hint {
  font-size: 11px;
}

.flow-connector {
  position: absolute;
  z-index: 9;
  display: block;
  width: 30px;
  height: 54px;
  min-height: 0;
  padding: 0;
  pointer-events: none;
}

.flow-connector-label {
  max-width: 88px;
  padding-left: 12px;
  overflow-wrap: anywhere;
  color: var(--text-muted);
  font-size: 7px;
  line-height: 1.55;
  white-space: normal;
}

.flow-connector-feed {
  --connector-lane: 0;
  top: -26px;
  left: calc(92px + 12px + 18px + 154px + 16px + 2px);
}

.flow-connector-output {
  --connector-lane: 0;
  right: 20px;
  bottom: -26px;
}

.flow-connector-track {
  width: 30px;
  height: 54px;
}

.flow-connector-track::before {
  top: 2px;
  bottom: 2px;
  left: var(--connector-lane);
  width: 30px;
  border: 1px dashed color-mix(in srgb, var(--connector-color) 55%, var(--border));
  border-radius: 3px 3px 14px 14px;
  background-image:
    repeating-linear-gradient(
      180deg,
      color-mix(in srgb, var(--connector-color) 34%, transparent) 0 1px,
      transparent 1px 7px
    ),
    linear-gradient(
      90deg,
      color-mix(in srgb, var(--connector-color) 8%, transparent),
      transparent 35% 65%,
      color-mix(in srgb, var(--connector-color) 8%, transparent)
    );
}

.flow-connector-track::after {
  bottom: 3px;
  left: calc(var(--connector-lane) + 11px);
}

.flow-connector-packet {
  left: calc(var(--connector-lane) + 10px);
  width: 11px;
  height: 9px;
}

.pipeline-strip {
  position: relative;
  grid-template-columns: 154px minmax(0, 1fr);
  gap: 16px;
  min-height: 154px;
  padding: 15px 18px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--stage-work) 24%, var(--border));
  border-radius: 6px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--stage-work) 7%, transparent), transparent 36%),
    repeating-linear-gradient(
      0deg,
      color-mix(in srgb, var(--text-primary) 2%, transparent) 0 1px,
      transparent 1px 18px
    ),
    var(--factory-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--stage-work) 14%, transparent),
    0 7px 22px rgba(0, 0, 0, 0.2);
}

.pipeline-header {
  align-content: center;
  gap: 8px;
  color: color-mix(in srgb, var(--stage-work) 62%, var(--text-muted));
  font-size: 8px;
}

.pipeline-live {
  color: var(--stage-output);
  font-size: 7px;
}

.pipeline-track {
  --pipeline-start: 64px;
  height: 108px;
}

.pipeline-track::before {
  top: 58%;
  right: 28px;
  left: 28px;
  height: 3px;
  background: color-mix(in srgb, var(--stage-work) 34%, var(--border));
  box-shadow: 0 0 10px color-mix(in srgb, var(--stage-work) 12%, transparent);
}

.pipeline-track::after {
  top: calc(58% + 6px);
  right: 28px;
  left: 28px;
  height: 7px;
  background-image: repeating-linear-gradient(
    90deg,
    color-mix(in srgb, var(--stage-work) 30%, var(--border)) 0 1px,
    transparent 1px 9px
  );
}

.pipeline-robot {
  top: 16px;
  right: auto;
  left: auto;
  width: 38px;
  height: 38px;
  border-style: solid;
  border-color: color-mix(in srgb, var(--stage-work) 52%, var(--border));
  border-radius: 6px;
  color: var(--stage-work);
  background: color-mix(in srgb, var(--stage-work) 10%, var(--factory-panel));
  box-shadow:
    0 0 0 5px color-mix(in srgb, var(--stage-work) 7%, transparent),
    0 0 18px color-mix(in srgb, var(--stage-work) 10%, transparent);
  animation: robot-work 2.8s ease-in-out infinite;
}

.pipeline-robot::before {
  position: absolute;
  top: 20px;
  left: 30px;
  width: 15px;
  height: 2px;
  content: '';
  border-radius: 2px;
  background: currentColor;
  transform-origin: 0 50%;
  animation: robot-arm-lift 2.4s ease-in-out infinite;
}

.pipeline-robot::after {
  bottom: -19px;
  height: 18px;
  background: color-mix(in srgb, var(--stage-work) 45%, var(--border));
}

.pipeline-robot svg {
  width: 22px;
  height: 22px;
  stroke-width: 1.6;
}

.pipeline-robot.robot-loader {
  left: 46px;
}

.pipeline-robot.robot-inspector {
  left: 50%;
  margin-left: -19px;
  animation-name: robot-inspect;
  animation-delay: -0.9s;
}

.pipeline-robot.robot-inspector::before {
  animation-name: robot-arm-scan;
  animation-duration: 2s;
  animation-delay: -0.4s;
}

.pipeline-robot.robot-packer {
  right: 46px;
  animation-delay: -1.5s;
}

.pipeline-robot.robot-packer::before {
  animation-delay: -1.2s;
}

.pipeline-channel {
  position: absolute;
  top: 12px;
  bottom: 10px;
  z-index: 5;
  display: block;
  width: 34px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--stage-work) 35%, var(--border));
  border-radius: 3px;
  background:
    repeating-linear-gradient(
      180deg,
      color-mix(in srgb, var(--stage-work) 26%, transparent) 0 1px,
      transparent 1px 7px
    ),
    color-mix(in srgb, var(--stage-work) 7%, var(--factory-panel));
  box-shadow: inset 0 0 0 3px color-mix(in srgb, var(--factory-panel) 70%, transparent);
}

.pipeline-channel::before {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  content: '';
  background: color-mix(in srgb, var(--stage-work) 55%, var(--border));
}

.pipeline-channel::after {
  position: absolute;
  left: 13px;
  width: 6px;
  height: 6px;
  border-right: 1px solid var(--stage-work);
  border-bottom: 1px solid var(--stage-work);
  content: '';
  transform: rotate(45deg);
  animation: channel-signal 1.4s ease-in-out infinite;
}

.pipeline-channel small {
  position: absolute;
  right: 3px;
  bottom: 4px;
  left: 3px;
  color: color-mix(in srgb, var(--stage-work) 72%, var(--text-muted));
  font-family: var(--mono);
  font-size: 6px;
  font-weight: 700;
  text-align: center;
}

.channel-inlet {
  left: 0;
}

.channel-inlet::before {
  left: 7px;
}

.channel-inlet::after {
  bottom: 17px;
}

.channel-outlet {
  right: 0;
  border-color: color-mix(in srgb, var(--stage-output) 38%, var(--border));
}

.channel-outlet::before {
  right: 7px;
  background: color-mix(in srgb, var(--stage-output) 55%, var(--border));
}

.channel-outlet::after {
  bottom: 17px;
  border-color: var(--stage-output);
}

.channel-outlet small {
  color: color-mix(in srgb, var(--stage-output) 76%, var(--text-muted));
}

.pipeline-node {
  padding: 6px 9px;
  border-color: color-mix(in srgb, var(--stage-work) 18%, var(--border));
  border-radius: 3px;
  color: var(--text-secondary);
  background: color-mix(in srgb, var(--factory-panel) 88%, var(--stage-work));
  font-size: 8px;
  box-shadow: 0 3px 9px rgba(0, 0, 0, 0.18);
}

.pipeline-packet {
  width: 20px;
  height: 15px;
  border-radius: 2px;
}

.node-scan::before {
  background: var(--stage-work);
}

.node-verify::before {
  background: var(--accent-strong);
}

.node-evidence::before {
  background: var(--warning);
}

.node-archive::before {
  background: var(--stage-output);
}

@keyframes robot-work {
  0%,
  100% {
    transform: translateY(0);
  }

  50% {
    transform: translateY(-2px);
  }
}

@keyframes robot-inspect {
  0%,
  100% {
    transform: translateY(0) rotate(-1deg);
  }

  50% {
    transform: translateY(-2px) rotate(1deg);
  }
}

@keyframes robot-arm-lift {
  0%,
  100% {
    transform: rotate(18deg);
  }

  50% {
    transform: rotate(-24deg);
  }
}

@keyframes robot-arm-scan {
  0%,
  100% {
    transform: rotate(-32deg);
  }

  50% {
    transform: rotate(24deg);
  }
}

@keyframes channel-signal {
  0%,
  100% {
    opacity: 0.35;
    transform: translateY(0) rotate(45deg);
  }

  50% {
    opacity: 1;
    transform: translateY(3px) rotate(45deg);
  }
}

.command-band {
  gap: 10px;
}

.screen-panel {
  min-height: 330px;
  padding: 35px 16px 22px;
  border: 1px solid color-mix(in srgb, var(--panel-accent) 26%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--panel-accent) 6%, transparent), transparent 22%),
    var(--factory-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--panel-accent) 16%, transparent),
    0 7px 20px rgba(0, 0, 0, 0.18);
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease;
}

.screen-panel:hover {
  border-color: color-mix(in srgb, var(--panel-accent) 46%, var(--border));
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--panel-accent) 20%, transparent),
    0 10px 24px rgba(0, 0, 0, 0.22);
}

.screen-panel::before {
  top: 12px;
  left: 16px;
  color: color-mix(in srgb, var(--panel-accent) 78%, var(--text-muted));
  font-size: 7px;
}

.screen-panel::after {
  right: 16px;
  bottom: 9px;
  left: 16px;
  background-image: repeating-linear-gradient(
    90deg,
    color-mix(in srgb, var(--panel-accent) 54%, transparent) 0 7px,
    transparent 7px 12px
  );
}

.screen-panel-header {
  margin-bottom: 15px;
}

.screen-panel-header h2 {
  font-size: 14px;
  font-weight: 600;
}

.panel-total {
  border-radius: 3px;
}

.screen-footer {
  padding: 8px 4px 0;
  border-top: 1px solid color-mix(in srgb, var(--border) 72%, transparent);
}

.token-stage {
  --stage-color: #4fd1c5;
}

.token-console {
  min-width: 0;
  padding: 16px;
  border: 1px solid color-mix(in srgb, #4fd1c5 28%, var(--border));
  border-radius: var(--radius);
  background:
    linear-gradient(90deg, color-mix(in srgb, #4fd1c5 4%, transparent), transparent 36%),
    var(--surface);
  transition: opacity 0.2s ease;
}

.token-console.loading {
  opacity: 0.68;
}

.token-console-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 16px;
  margin-bottom: 16px;
}

.token-title {
  display: flex;
  align-items: center;
  gap: 9px;
  min-width: 180px;
}

.token-title h2 {
  margin: 0;
  font-size: 14px;
}

.token-title small {
  color: var(--text-muted);
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
}

.token-bolt {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border: 1px solid color-mix(in srgb, #4fd1c5 46%, var(--border));
  border-radius: 50%;
  color: #4fd1c5;
  font-size: 19px;
}

.token-segments,
.token-ranges {
  display: inline-flex;
  gap: 2px;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--field-bg);
}

.token-segments button,
.token-ranges button,
.token-models button {
  border: 0;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
}

.token-segments button {
  padding: 4px 8px;
  border-radius: 2px;
  font-size: 10px;
}

.token-segments button.active {
  color: var(--text-primary);
  background: var(--surface-soft);
}

.token-models {
  display: flex;
  flex: 1;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 4px;
  min-width: 180px;
}

.token-models button {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 8px;
  border: 1px solid transparent;
  border-radius: 3px;
  font-size: 10px;
}

.token-models button:hover,
.token-models button.active {
  border-color: color-mix(in srgb, #4fd1c5 34%, var(--border));
  color: var(--text-primary);
  background: color-mix(in srgb, #4fd1c5 9%, var(--surface-soft));
}

.token-models button small {
  color: #4fd1c5;
  font-size: 8px;
}

.token-error {
  margin: 0 0 12px;
  color: var(--danger);
  font-size: 11px;
}

.token-layout {
  display: grid;
  grid-template-columns: minmax(220px, 270px) minmax(0, 1fr);
  gap: 24px;
  align-items: stretch;
}

.token-metrics {
  display: flex;
  flex-direction: column;
  gap: 15px;
  min-width: 0;
}

.token-total > small {
  display: block;
  color: var(--text-muted);
  font-size: 10px;
}

.token-total > strong {
  display: block;
  margin-top: 2px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: clamp(28px, 3vw, 40px);
  font-weight: 700;
  line-height: 1;
  letter-spacing: 0;
}

.token-total > span {
  color: var(--text-muted);
  font-size: 10px;
}

.token-metric-list {
  display: grid;
  gap: 11px;
}

.token-metric header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 4px;
  font-size: 10px;
}

.token-metric header span {
  color: var(--text-muted);
}

.token-metric header strong {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.token-metric > i {
  display: block;
  min-width: 0;
  height: 4px;
  border-radius: 2px;
}

.token-metric.input > i {
  background: #4ea1ff;
}

.token-metric.cache > i {
  background: #45d6a4;
}

.token-metric.output > i {
  background: #a78bfa;
}

.token-hit-rate {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 9px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  font-size: 10px;
}

.token-hit-rate strong {
  color: #45d6a4;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 14px;
}

.token-estimated {
  width: fit-content;
  padding: 2px 6px;
  border: 1px solid color-mix(in srgb, var(--warning) 35%, var(--border));
  border-radius: 3px;
  color: var(--warning);
  font-size: 9px;
}

.token-chart-panel {
  min-width: 0;
  padding-left: 20px;
  border-left: 1px solid var(--border);
}

.token-chart-panel > header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 16px;
  margin-bottom: 10px;
}

.token-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  color: var(--text-muted);
  font-size: 9px;
}

.token-legend span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.token-legend i {
  width: 8px;
  height: 8px;
  border-radius: 2px;
}

.token-legend .input i {
  background: #4ea1ff;
}

.token-legend .output i {
  background: #a78bfa;
}

.token-legend .cache i {
  background: #45d6a4;
}

.token-ranges button {
  padding: 3px 7px;
  border-radius: 2px;
  font-size: 9px;
}

.token-ranges button.active {
  color: var(--text-primary);
  background: var(--surface-soft);
}

.token-chart-scroll {
  min-width: 0;
  overflow-x: auto;
}

.token-chart {
  display: block;
  width: 100%;
  min-width: 640px;
  height: 210px;
}

.token-grid-line {
  stroke: color-mix(in srgb, var(--border) 72%, transparent);
  stroke-dasharray: 3 5;
  stroke-width: 1;
}

.token-battery-shell {
  fill: color-mix(in srgb, var(--field-bg) 80%, transparent);
  stroke: color-mix(in srgb, var(--text-muted) 28%, var(--border));
  stroke-width: 1.2;
}

.token-battery-terminal {
  fill: color-mix(in srgb, var(--text-muted) 45%, var(--border));
}

.token-battery-cell {
  fill: color-mix(in srgb, var(--field-bg) 72%, transparent);
  stroke: color-mix(in srgb, var(--text-muted) 18%, var(--border));
  stroke-width: 0.7;
}

.token-battery-gap {
  stroke: var(--surface);
  stroke-linecap: butt;
  stroke-width: 2;
}

.token-battery.full .token-battery-shell {
  stroke: #45d6a4;
  filter: drop-shadow(0 0 4px color-mix(in srgb, #45d6a4 40%, transparent));
}

.token-battery.full .token-battery-terminal {
  fill: #45d6a4;
}

.token-bar.input {
  fill: #4ea1ff;
}

.token-bar.output {
  fill: #a78bfa;
}

.token-bar.cache {
  fill: #45d6a4;
}

.token-axis-label {
  fill: var(--text-muted);
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
}

.token-chart g {
  outline: none;
}

.token-chart g:focus-visible .token-bar {
  filter: brightness(1.2);
  stroke: var(--text-primary);
  stroke-width: 1;
}

.token-chart-tooltip {
  position: fixed;
  z-index: 1200;
  width: 230px;
  padding: 10px 11px;
  border: 1px solid color-mix(in srgb, #4fd1c5 38%, var(--border));
  border-radius: 4px;
  color: var(--text-primary);
  background: color-mix(in srgb, var(--surface) 96%, transparent);
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
  pointer-events: none;
}

.token-chart-tooltip > strong {
  display: block;
  margin-bottom: 7px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 10px;
}

.token-chart-tooltip dl {
  display: grid;
  gap: 5px;
  margin: 0;
}

.token-chart-tooltip dl > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  color: var(--text-muted);
  font-size: 10px;
}

.token-chart-tooltip dt,
.token-chart-tooltip dd {
  margin: 0;
}

.token-chart-tooltip dd {
  color: var(--text-primary);
  font-family: "SFMono-Regular", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}

.token-chart-tooltip .total {
  padding-top: 5px;
  border-top: 1px solid var(--border);
  color: var(--text-secondary);
}

.token-chart-tooltip .total dd {
  color: #4fd1c5;
  font-weight: 700;
}

.token-chart-empty {
  display: grid;
  place-items: center;
  min-height: 210px;
  border: 1px dashed var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  font-size: 11px;
}

@media (prefers-reduced-motion: reduce) {
  .flow-connector-packet,
  .pipeline-packet {
    display: none;
  }

  .pipeline-live i,
  .pipeline-robot,
  .pipeline-robot::before,
  .pipeline-channel::after {
    animation: none;
  }
}

@media (max-width: 1180px) {
  .factory-header {
    grid-template-columns: minmax(220px, 1fr) auto;
  }

  .factory-route {
    display: none;
  }

  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .command-band {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .asset-overview,
  .severity-panel,
  .system-overview {
    grid-column: span 1;
  }

  .system-overview {
    grid-column: span 2;
  }

  .token-layout {
    grid-template-columns: 1fr;
  }

  .token-chart-panel {
    padding-top: 16px;
    padding-left: 0;
    border-top: 1px solid var(--border);
    border-left: 0;
  }
}

@media (max-width: 820px) {
  .factory-stage {
    grid-template-columns: 1fr;
    gap: 7px;
  }

  .stage-rail {
    display: flex;
    min-height: 42px;
    grid-template-rows: none;
    align-items: center;
    gap: 10px;
    padding: 8px 11px;
    border-left-width: 1px;
    border-top: 2px solid var(--stage-color);
  }

  .stage-rail::after {
    top: auto;
    right: 0;
    bottom: 5px;
    left: 0;
    width: auto;
    height: 1px;
    background: repeating-linear-gradient(
      90deg,
      var(--factory-line) 0 2px,
      transparent 2px 8px
    );
  }

  .stage-index {
    min-width: 25px;
    font-size: 18px;
  }

  .stage-title {
    color: var(--text-secondary);
    font-size: 9px;
    writing-mode: horizontal-tb;
  }

  .stage-meta {
    margin-left: auto;
  }

  .flow-connector {
    width: 28px;
    height: 50px;
    min-height: 0;
  }

  .flow-connector-feed {
    --connector-lane: 0;
    top: -24px;
    left: 12px;
  }

  .flow-connector-output {
    --connector-lane: 0;
    right: 15px;
    bottom: -24px;
  }

  .flow-connector-track {
    width: 28px;
    height: 50px;
  }

  .pipeline-strip {
    grid-template-columns: 1fr;
    gap: 8px;
    min-height: 138px;
    padding: 12px;
  }

  .pipeline-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .pipeline-track {
    --pipeline-start: 43px;
    height: 92px;
  }

  .pipeline-robot {
    top: 12px;
    width: 34px;
    height: 34px;
  }

  .pipeline-robot.robot-loader {
    left: 36px;
  }

  .pipeline-robot.robot-inspector {
    margin-left: -17px;
  }

  .pipeline-robot.robot-packer {
    right: 36px;
  }

  .pipeline-robot::after {
    bottom: -16px;
    height: 15px;
  }

  .pipeline-channel {
    top: 8px;
    bottom: 8px;
    width: 28px;
  }

  .pipeline-channel small {
    display: none;
  }

  .pipeline-channel::after {
    left: 10px;
  }

  .pipeline-track::before,
  .pipeline-track::after {
    right: 22px;
    left: 22px;
  }
}

@media (max-width: 760px) {
  .dashboard-screen {
    gap: 12px;
  }

  .factory-header {
    grid-template-columns: 1fr;
    gap: 13px;
    padding: 15px;
  }

  .dashboard-live {
    justify-content: flex-start;
  }

  .factory-header .dashboard-clock {
    justify-items: start;
  }

  .kpi-grid,
  .command-band {
    grid-template-columns: 1fr;
  }

  .token-console {
    padding: 12px;
  }

  .token-models {
    flex-basis: 100%;
    justify-content: flex-start;
  }

  .token-chart {
    min-width: 560px;
  }

  .kpi-card {
    min-height: 112px;
    padding-top: 21px;
  }

  .kpi-icon {
    top: 50%;
  }

  .screen-panel {
    min-height: 0;
  }

  .asset-overview,
  .severity-panel,
  .system-overview {
    grid-column: span 1;
  }

  .flow-connector {
    height: 50px;
    min-height: 0;
  }

  .flow-connector-track {
    width: 28px;
    height: 50px;
  }

  .flow-connector-feed {
    --connector-lane: 0;
    top: -24px;
    left: 12px;
  }

  .flow-connector-output {
    --connector-lane: 0;
    right: 15px;
    bottom: -24px;
  }

  .pipeline-node {
    padding: 4px 5px;
    font-size: 7px;
  }
}
</style>
