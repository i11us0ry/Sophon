<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'

import { apiGet, apiPost } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()

interface AuditLog {
  id: string
  username: string
  action: string
  resourceType: string
  resourceId: string
  result: string
  detail: string
  createdAt: string
}

interface ToolExecution {
  id: string
  conversationId: string
  toolName: string
  arguments: Record<string, unknown> | null
  status: string
  result: string
  error: string
  startedAt: string
  finishedAt: string | null
}

interface HITLRequest {
  id: string
  conversationId: string
  toolName: string
  arguments: Record<string, unknown> | null
  status: string
  createdAt: string
}

interface ContextMetrics {
  compactions: {
    total: number
    minor: number
    major: number
    avgRatio: number
    avgLatencyMs: number
    lastAt: string | null
  }
  memoryWrites: {
    ADD: number
    UPDATE: number
    NONE: number
    SUPERSEDE: number
    total: number
  }
  injections: {
    total: number
  }
}

interface ContextCompaction {
  id: string
  conversationId: string
  tokensBefore: number
  tokensAfter: number
  summaryTokens: number
  kind: string
  model: string
  latencyMs: number
  createdAt: string
}

const auditLogs = ref<AuditLog[]>([])
const auditTotal = ref(0)
const auditPage = ref(1)
const auditPageSize = ref(50)
const auditTotalPages = ref(1)
const toolExecutions = ref<ToolExecution[]>([])
const pendingHITL = ref<HITLRequest[]>([])
const contextMetrics = ref<ContextMetrics>({
  compactions: { total: 0, minor: 0, major: 0, avgRatio: 0, avgLatencyMs: 0, lastAt: null },
  memoryWrites: { ADD: 0, UPDATE: 0, NONE: 0, SUPERSEDE: 0, total: 0 },
  injections: { total: 0 },
})
const contextCompactions = ref<ContextCompaction[]>([])
const contextError = ref('')
const comments = ref<Record<string, string>>({})
const selectedExecution = ref<ToolExecution | null>(null)
const error = ref('')
const notice = ref('')
const loading = ref(false)
const autoRefresh = ref(false)
const resultFilter = ref('')
const keyword = ref('')
const auditScope = ref<'self' | 'all'>('self')
const activeTab = ref<'approvals' | 'executions' | 'audit' | 'context'>('approvals')
const expandedHITL = ref('')
const selectedAudit = ref<AuditLog | null>(null)
const executionFilter = ref<'' | 'running' | 'success' | 'failed'>('')
const executionSearch = ref('')
const isAdmin = computed(() => auth.user?.role === 'admin')
let refreshTimer: number | undefined
let searchTimer: number | undefined

const failedExecutions = computed(
  () => toolExecutions.value.filter((item) => item.status === 'failed' || item.error).length,
)
const failedAudits = computed(
  () => auditLogs.value.filter((item) => item.result && item.result !== 'success').length,
)
const successfulAudits = computed(
  () => auditLogs.value.filter((item) => item.result === 'success').length,
)
const runningExecutions = computed(
  () =>
    toolExecutions.value.filter(
      (item) => item.status !== 'failed' && !item.error && !item.finishedAt,
    ).length,
)
const executionSuccessRate = computed(() => {
  const total = toolExecutions.value.length
  if (!total) {
    return 0
  }
  return Math.round(((total - failedExecutions.value) / total) * 100)
})
const auditSuccessRate = computed(() => {
  const total = auditLogs.value.length
  if (!total) {
    return 0
  }
  return Math.round((successfulAudits.value / total) * 100)
})
const filteredExecutions = computed(() => {
  const query = executionSearch.value.trim().toLowerCase()
  return toolExecutions.value.filter((execution) => {
    if (executionFilter.value === 'running' && executionStatusClass(execution) !== 'state-running') {
      return false
    }
    if (executionFilter.value === 'success' && executionStatusClass(execution) !== 'state-success') {
      return false
    }
    if (executionFilter.value === 'failed' && executionStatusClass(execution) !== 'state-failed') {
      return false
    }
    if (!query) {
      return true
    }
    return `${execution.toolName} ${execution.conversationId} ${execution.result} ${execution.error}`
      .toLowerCase()
      .includes(query)
  })
})

function formatTime(value: string | null) {
  if (!value) {
    return '-'
  }
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function duration(execution: ToolExecution) {
  if (!execution.finishedAt) {
    return t('governance.running')
  }
  const started = new Date(execution.startedAt).getTime()
  const finished = new Date(execution.finishedAt).getTime()
  if (!Number.isFinite(started) || !Number.isFinite(finished)) {
    return '-'
  }
  return t('governance.durationMs', { value: Math.max(0, finished - started) })
}

function executionStatus(execution: ToolExecution) {
  if (execution.status === 'failed' || execution.error) {
    return t('governance.failed')
  }
  if (!execution.finishedAt) {
    return t('governance.running')
  }
  return t('governance.success')
}

function executionStatusClass(execution: ToolExecution) {
  if (execution.status === 'failed' || execution.error) {
    return 'state-failed'
  }
  if (!execution.finishedAt) {
    return 'state-running'
  }
  return 'state-success'
}

function executionTone(execution: ToolExecution) {
  const state = executionStatusClass(execution)
  if (state === 'state-failed') {
    return 'failed'
  }
  if (state === 'state-running') {
    return 'running'
  }
  return 'success'
}

function auditTone(log: AuditLog) {
  return log.result === 'success' ? 'success' : 'failed'
}

function switchTab(tab: 'approvals' | 'executions' | 'audit' | 'context') {
  activeTab.value = tab
}

function toggleHITL(request: HITLRequest) {
  expandedHITL.value = expandedHITL.value === request.id ? '' : request.id
}

function openExecution(execution: ToolExecution) {
  selectedExecution.value = execution
}

function openAudit(log: AuditLog) {
  selectedAudit.value = log
}

function closeExecution() {
  selectedExecution.value = null
}

function closeAudit() {
  selectedAudit.value = null
}

function summarize(value: string, max = 120) {
  const text = (value || '').replace(/\s+/g, ' ').trim()
  if (!text) {
    return '-'
  }
  return text.length > max ? `${text.slice(0, max)}…` : text
}

function formatJSON(value: Record<string, unknown> | null) {
  if (!value || Object.keys(value).length === 0) {
    return '{}'
  }
  return JSON.stringify(value, null, 2)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [, monitor, hitl] = await Promise.all([
      loadAudit(),
      apiGet<{ items: ToolExecution[] }>('/monitor/executions'),
      apiGet<{ items: HITLRequest[] }>('/hitl/pending'),
    ])
    toolExecutions.value = monitor.items ?? []
    pendingHITL.value = hitl.items ?? []
    await loadContextMetrics()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '读取治理数据失败'
  } finally {
    loading.value = false
  }
}

// 指标接口单独降级：无 dashboard 权限时不影响其余治理数据展示。
async function loadContextMetrics() {
  const scopeQuery = auditScope.value === 'all' && isAdmin.value ? 'scope=all' : ''
  try {
    const [metrics, compactions] = await Promise.all([
      apiGet<ContextMetrics>(`/context/metrics${scopeQuery ? `?${scopeQuery}` : ''}`),
      apiGet<{ items: ContextCompaction[] }>(
        `/context/compactions?limit=20${scopeQuery ? `&${scopeQuery}` : ''}`,
      ),
    ])
    contextMetrics.value = metrics
    contextCompactions.value = compactions.items ?? []
    contextError.value = ''
  } catch (err) {
    contextCompactions.value = []
    contextError.value = err instanceof Error ? err.message : t('governance.contextUnavailable')
  }
}

function formatRatio(value: number) {
  if (!value || value <= 0) {
    return '-'
  }
  return `${Math.round(value * 100)}%`
}

async function loadAudit() {
  const params = new URLSearchParams()
  if (auditScope.value === 'all' && isAdmin.value) {
    params.set('scope', 'all')
  }
  params.set('limit', String(auditPageSize.value))
  params.set('offset', String((auditPage.value - 1) * auditPageSize.value))
  if (resultFilter.value) {
    params.set('result', resultFilter.value)
  }
  if (keyword.value.trim()) {
    params.set('search', keyword.value.trim())
  }
  const response = await apiGet<{
    items: AuditLog[]
    total: number
    page: number
    pageSize: number
    totalPages: number
  }>(`/audit/logs?${params.toString()}`)
  auditLogs.value = response.items ?? []
  auditTotal.value = response.total ?? 0
  auditPage.value = response.page ?? 1
  auditPageSize.value = response.pageSize ?? auditPageSize.value
  auditTotalPages.value = response.totalPages ?? 1
}

function goAuditPage(offset: number) {
  const next = auditPage.value + offset
  if (next < 1 || next > auditTotalPages.value) {
    return
  }
  auditPage.value = next
  void loadAudit()
}

watch(resultFilter, () => {
  auditPage.value = 1
  void loadAudit()
})

watch(auditPageSize, () => {
  auditPage.value = 1
  void loadAudit()
})

watch(keyword, () => {
  if (searchTimer) {
    window.clearTimeout(searchTimer)
  }
  searchTimer = window.setTimeout(() => {
    auditPage.value = 1
    void loadAudit()
  }, 300)
})

watch(auditScope, () => {
  auditPage.value = 1
  void loadAudit()
})

async function decide(request: HITLRequest, approved: boolean) {
  error.value = ''
  notice.value = ''
  try {
    await apiPost(`/hitl/${request.id}/decision`, {
      approved,
      comment: comments.value[request.id] || '',
    })
    delete comments.value[request.id]
    notice.value = approved ? t('governance.approved') : t('governance.rejected')
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '提交审批结果失败'
  }
}

function toggleAutoRefresh() {
  autoRefresh.value = !autoRefresh.value
}

watch(autoRefresh, (enabled) => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
    refreshTimer = undefined
  }
  if (enabled) {
    refreshTimer = window.setInterval(() => {
      void load()
    }, 10000)
  }
})

onMounted(load)

onUnmounted(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
  if (searchTimer) {
    window.clearTimeout(searchTimer)
  }
})
</script>

<template>
  <section class="page factory-page page-governance audit-control">
    <header class="page-header audit-command-header">
      <div class="audit-heading page-heading-with-robot">
        <PageTitleRobot tone="lime" />
        <div>
          <p class="eyebrow">AUDIT FLOOR // SECURITY QC</p>
          <h1>{{ t('governance.controlCenter') }}</h1>
          <p class="audit-page-hint">{{ t('governance.controlHint') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button
          class="button audit-refresh-toggle"
          type="button"
          :class="{ active: autoRefresh }"
          @click="toggleAutoRefresh"
        >
          <span class="audit-live-led" aria-hidden="true"></span>
          {{ t('governance.autoRefresh') }} {{ autoRefresh ? '· 10s' : '' }}
        </button>
        <button class="button" type="button" :disabled="loading" @click="load">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" />
          </svg>
          {{ t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error audit-alert">{{ error }}</div>
    <div v-if="notice" class="alert ok audit-alert">{{ notice }}</div>

    <section class="audit-status-rail">
      <article class="audit-stat tone-pending">
        <small>
          <svg class="audit-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m12 3 7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          {{ t('governance.statPending') }}
        </small>
        <strong>{{ pendingHITL.length }}</strong>
      </article>
      <article class="audit-stat tone-running">
        <small>
          <svg class="audit-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 12h4l2-6 4 12 2-6h6" />
          </svg>
          {{ t('governance.running') }}
        </small>
        <strong>{{ runningExecutions }}</strong>
      </article>
      <article class="audit-stat tone-failed">
        <small>
          <svg class="audit-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M8 3h8l5 5v8l-5 5H8l-5-5V8l5-5Z" />
            <path d="m9 9 6 6M15 9l-6 6" />
          </svg>
          {{ t('governance.failed') }}
        </small>
        <strong>{{ failedExecutions }}</strong>
      </article>
      <article class="audit-stat tone-audit">
        <small>
          <svg class="audit-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M5 4h14v16H5z" />
            <path d="M8 8h8M8 12h8M8 16h5" />
            <path d="m15 16 2 2 3-3" />
          </svg>
          {{ t('governance.statAudit') }}
        </small>
        <strong>{{ auditTotal }}</strong>
      </article>
      <article class="audit-stat tone-injection">
        <small>
          <svg class="audit-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="5" width="16" height="14" rx="2" />
            <path d="M8 9h.01M12 9h.01M16 9h.01M8 13h8M8 16h5" />
          </svg>
          {{ t('governance.injections') }}
        </small>
        <strong>{{ contextMetrics.injections.total }}</strong>
      </article>
      <div class="audit-status-scan" aria-hidden="true"><i></i></div>
    </section>

    <nav class="audit-tabs" :aria-label="t('governance.controlCenter')">
      <button type="button" :class="{ active: activeTab === 'approvals' }" @click="switchTab('approvals')">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v4M6 7h12v14H6zM9 12h6M9 16h4" /></svg>
        <span><strong>{{ t('governance.approvalGate') }}</strong><small>{{ t('governance.pendingGateHint') }}</small></span>
        <b>{{ pendingHITL.length }}</b>
      </button>
      <button type="button" :class="{ active: activeTab === 'executions' }" @click="switchTab('executions')">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m13 2-9 12h7l-1 8 9-12h-7z" /></svg>
        <span><strong>{{ t('governance.executionMonitor') }}</strong><small>{{ t('governance.executionsHint') }}</small></span>
        <b>{{ toolExecutions.length }}</b>
      </button>
      <button type="button" :class="{ active: activeTab === 'audit' }" @click="switchTab('audit')">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" /></svg>
        <span><strong>{{ t('governance.auditTrace') }}</strong><small>{{ t('governance.auditHint') }}</small></span>
        <b>{{ auditTotal }}</b>
      </button>
      <button type="button" :class="{ active: activeTab === 'context' }" @click="switchTab('context')">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 3a4 4 0 0 0-4 4v1a4 4 0 0 0 0 8v1a4 4 0 0 0 4 4M15 3a4 4 0 0 1 4 4v1a4 4 0 0 1 0 8v1a4 4 0 0 1-4 4M12 3v18M9 9h.01M15 15h.01" /></svg>
        <span><strong>{{ t('governance.memoryEngine') }}</strong><small>{{ t('governance.memoryHint') }}</small></span>
        <b>{{ contextMetrics.compactions.total }}</b>
      </button>
    </nav>

    <section v-if="activeTab === 'approvals'" class="audit-floor-panel">
      <header class="audit-floor-header">
        <div>
          <span class="audit-floor-code">01 // APPROVAL GATE</span>
          <h2>{{ t('governance.approvalGate') }}</h2>
          <p>{{ t('governance.pendingGateHint') }}</p>
        </div>
        <span class="audit-floor-count">{{ pendingHITL.length }}</span>
      </header>
      <div v-if="pendingHITL.length" class="audit-approval-list">
        <article
          v-for="request in pendingHITL"
          :key="request.id"
          class="audit-approval-row"
          :class="{ expanded: expandedHITL === request.id }"
        >
          <span class="gate-robot" aria-hidden="true">
            <i></i><b></b><b></b><em></em>
          </span>
          <div class="audit-approval-main">
            <div class="audit-approval-title">
              <strong>{{ request.toolName }}</strong>
              <span class="audit-pending-stamp">{{ t('governance.pending') }}</span>
              <time>{{ formatTime(request.createdAt) }}</time>
            </div>
            <div class="audit-approval-meta">
              <span>{{ t('governance.requestId') }} · <code>{{ request.id.slice(0, 12) }}</code></span>
              <span>{{ t('governance.conversation') }} · <code>{{ request.conversationId.slice(0, 12) }}</code></span>
              <button type="button" @click="toggleHITL(request)">
                {{ t('governance.arguments') }}
                {{ expandedHITL === request.id ? '−' : '+' }}
              </button>
            </div>
            <pre v-if="expandedHITL === request.id" class="audit-code-block">{{ formatJSON(request.arguments) }}</pre>
          </div>
          <div class="audit-approval-actions">
            <input
              v-model="comments[request.id]"
              :aria-label="t('governance.commentPlaceholder')"
              :placeholder="t('governance.commentPlaceholder')"
            />
            <button class="button compact audit-approve" type="button" @click="decide(request, true)">
              {{ t('governance.approve') }}
            </button>
            <button class="button compact danger" type="button" @click="decide(request, false)">
              {{ t('governance.reject') }}
            </button>
          </div>
        </article>
      </div>
      <div v-else class="audit-empty-state">
        <span class="audit-empty-robot" aria-hidden="true"><i></i><b></b><b></b></span>
        <strong>{{ t('governance.gateIdle') }}</strong>
      </div>
    </section>

    <section v-else-if="activeTab === 'executions'" class="audit-floor-panel">
      <header class="audit-floor-header">
        <div>
          <span class="audit-floor-code">02 // ROBOT RUN LOG</span>
          <h2>{{ t('governance.executionMonitor') }}</h2>
          <p>{{ t('governance.executionsHint') }}</p>
        </div>
        <div class="audit-run-summary">
          <span>{{ t('governance.successRate') }} <strong>{{ executionSuccessRate }}%</strong></span>
          <span class="audit-floor-count">{{ toolExecutions.length }}</span>
        </div>
      </header>
      <div class="audit-toolbar">
        <label class="audit-search-box">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg>
          <input v-model="executionSearch" type="search" :placeholder="t('governance.searchExecutions')" />
        </label>
        <div class="audit-segmented">
          <button type="button" :class="{ active: executionFilter === '' }" @click="executionFilter = ''">{{ t('governance.executionAll') }}</button>
          <button type="button" :class="{ active: executionFilter === 'running' }" @click="executionFilter = 'running'">{{ t('governance.running') }}</button>
          <button type="button" :class="{ active: executionFilter === 'success' }" @click="executionFilter = 'success'">{{ t('governance.success') }}</button>
          <button type="button" :class="{ active: executionFilter === 'failed' }" @click="executionFilter = 'failed'">{{ t('governance.failed') }}</button>
        </div>
      </div>
      <div v-if="filteredExecutions.length" class="audit-execution-list">
        <button
          v-for="execution in filteredExecutions"
          :key="execution.id"
          class="audit-execution-row"
          :class="`tone-${executionTone(execution)}`"
          type="button"
          @click="openExecution(execution)"
        >
          <span class="audit-execution-robot" aria-hidden="true"><i></i><b></b><b></b></span>
          <span class="audit-execution-status"><i></i>{{ executionStatus(execution) }}</span>
          <span class="audit-execution-tool"><strong>{{ execution.toolName }}</strong><small>{{ execution.conversationId ? execution.conversationId.slice(0, 12) : '-' }}</small></span>
          <time>{{ formatTime(execution.startedAt) }}</time>
          <code>{{ duration(execution) }}</code>
          <span class="audit-execution-summary">{{ summarize(execution.error || execution.result, 150) }}</span>
          <span class="audit-trace-link">{{ t('governance.openTrace') }} →</span>
        </button>
      </div>
      <div v-else class="audit-empty-state compact">
        <strong>{{ t('governance.executionsEmpty') }}</strong>
      </div>
    </section>

    <section v-else-if="activeTab === 'audit'" class="audit-floor-panel">
      <header class="audit-floor-header">
        <div>
          <span class="audit-floor-code">03 // COMPLIANCE TRACE</span>
          <h2>{{ t('governance.auditTrace') }}</h2>
          <p>{{ t('governance.auditHint') }}</p>
        </div>
        <div class="audit-run-summary">
          <span>{{ t('governance.successRate') }} <strong>{{ auditSuccessRate }}%</strong></span>
          <span class="audit-floor-count">{{ auditTotal }}</span>
        </div>
      </header>
      <div class="audit-toolbar audit-log-filters">
        <select v-if="isAdmin" v-model="auditScope" :aria-label="t('governance.auditScopeLabel')">
          <option value="self">{{ t('governance.auditScopeSelf') }}</option>
          <option value="all">{{ t('governance.auditScopeAll') }}</option>
        </select>
        <select v-model="resultFilter" :aria-label="t('governance.resultFilter')">
          <option value="">{{ t('governance.filterAll') }}</option>
          <option value="success">{{ t('governance.filterSuccess') }}</option>
          <option value="failure">{{ t('governance.filterFailure') }}</option>
        </select>
        <label class="audit-search-box">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg>
          <input v-model="keyword" type="search" :placeholder="t('governance.searchPlaceholder')" />
        </label>
        <select
          v-model.number="auditPageSize"
          :aria-label="t('governance.pageSizeLabel')"
        >
          <option :value="50">{{ t('governance.pageSize', { size: 50 }) }}</option>
          <option :value="100">{{ t('governance.pageSize', { size: 100 }) }}</option>
          <option :value="500">{{ t('governance.pageSize', { size: 500 }) }}</option>
          <option :value="1000">{{ t('governance.pageSize', { size: 1000 }) }}</option>
        </select>
        <span>{{ t('common.total', { count: auditTotal }) }}</span>
      </div>
      <div v-if="auditLogs.length" class="audit-log-table">
        <div class="audit-log-head">
          <span>{{ t('governance.colTime') }}</span>
          <span>{{ t('governance.colUser') }}</span>
          <span>{{ t('governance.colAction') }}</span>
          <span>{{ t('governance.colResource') }}</span>
          <span>{{ t('governance.colResult') }}</span>
          <span>{{ t('governance.colDetail') }}</span>
        </div>
        <button
          v-for="log in auditLogs"
          :key="log.id"
          type="button"
          class="audit-log-row"
          :class="`tone-${auditTone(log)}`"
          @click="openAudit(log)"
        >
          <time>{{ formatTime(log.createdAt) }}</time>
          <strong>{{ log.username || '-' }}</strong>
          <code>{{ log.action }}</code>
          <code>{{ log.resourceType }}{{ log.resourceId ? ` · ${log.resourceId}` : '' }}</code>
          <span class="audit-result-stamp">{{ log.result === 'success' ? t('governance.success') : t('governance.failed') }}</span>
          <span>{{ summarize(log.detail, 100) }}</span>
        </button>
      </div>
      <div v-else class="audit-empty-state compact"><strong>{{ t('governance.auditEmpty') }}</strong></div>
      <footer v-if="auditLogs.length" class="audit-pagination">
        <span>{{ t('governance.pageInfo', { page: auditPage, totalPages: auditTotalPages }) }}</span>
        <div>
          <button class="button compact" type="button" :disabled="auditPage <= 1" @click="goAuditPage(-1)">{{ t('vulnerability.prev') }}</button>
          <button class="button compact" type="button" :disabled="auditPage >= auditTotalPages" @click="goAuditPage(1)">{{ t('vulnerability.next') }}</button>
        </div>
      </footer>
    </section>

    <section v-else class="audit-floor-panel">
      <header class="audit-floor-header">
        <div>
          <span class="audit-floor-code">04 // MEMORY RECYCLER</span>
          <h2>{{ t('governance.memoryEngine') }}</h2>
          <p>{{ t('governance.memoryHint') }}</p>
        </div>
        <span class="audit-floor-count">{{ contextMetrics.compactions.total }}</span>
      </header>
      <div class="audit-context-metrics">
        <article class="audit-context-stat"><span>COMPACT</span><strong>{{ contextMetrics.compactions.total }}</strong><small>{{ t('governance.contextCompactions') }}</small><i class="tone-cyan"></i></article>
        <article class="audit-context-stat"><span>RATIO</span><strong>{{ formatRatio(contextMetrics.compactions.avgRatio) }}</strong><small>{{ t('governance.contextAvgRatio') }}</small><i class="tone-mint"></i></article>
        <article class="audit-context-stat"><span>LATENCY</span><strong>{{ Math.round(contextMetrics.compactions.avgLatencyMs) }} ms</strong><small>{{ t('governance.contextAvgLatency') }}</small><i class="tone-violet"></i></article>
        <article class="audit-context-stat"><span>WRITE</span><strong>{{ contextMetrics.memoryWrites.total }}</strong><small>{{ t('governance.memoryWrites') }}</small><i class="tone-amber"></i></article>
        <article class="audit-context-stat"><span>INJECT</span><strong>{{ contextMetrics.injections.total }}</strong><small>{{ t('governance.injections') }}</small><i class="tone-coral"></i></article>
      </div>
      <div class="audit-memory-strip">
        <span class="memory-node">ADD <b>{{ contextMetrics.memoryWrites.ADD }}</b></span>
        <i></i>
        <span class="memory-node">UPDATE <b>{{ contextMetrics.memoryWrites.UPDATE }}</b></span>
        <i></i>
        <span class="memory-node">NONE <b>{{ contextMetrics.memoryWrites.NONE }}</b></span>
        <i></i>
        <span class="memory-node">SUPERSEDE <b>{{ contextMetrics.memoryWrites.SUPERSEDE }}</b></span>
      </div>
      <p v-if="contextError" class="context-warning">{{ t('governance.contextUnavailable') }}</p>
      <div v-else-if="contextCompactions.length" class="audit-compaction-list">
        <div class="audit-compaction-head">
          <span>{{ t('governance.colTime') }}</span><span>{{ t('governance.colConversation') }}</span><span>{{ t('governance.colKind') }}</span><span>Token</span><span>{{ t('governance.colRatio') }}</span><span>{{ t('governance.colLatency') }}</span>
        </div>
        <div v-for="item in contextCompactions" :key="item.id" class="audit-compaction-row">
          <time>{{ formatTime(item.createdAt) }}</time>
          <code>{{ item.conversationId.slice(0, 8) }}</code>
          <span class="compaction-kind" :class="item.kind">{{ item.kind }}</span>
          <code>{{ item.tokensBefore }} → {{ item.tokensAfter }}</code>
          <span class="ratio-track"><i :style="{ width: formatRatio(item.tokensBefore > 0 ? item.tokensAfter / item.tokensBefore : 0) }"></i><b>{{ formatRatio(item.tokensBefore > 0 ? item.tokensAfter / item.tokensBefore : 0) }}</b></span>
          <code>{{ item.latencyMs }} ms</code>
        </div>
      </div>
      <div v-else class="audit-empty-state compact"><strong>{{ t('governance.contextEmpty') }}</strong></div>
    </section>

    <Teleport to="body">
      <div v-if="selectedExecution" class="audit-drawer-layer" @click.self="closeExecution">
        <aside class="audit-drawer" role="dialog" aria-modal="true">
          <header class="audit-drawer-head">
            <div>
              <span class="audit-floor-code">ROBOT RUN TRACE</span>
              <h2>{{ t('governance.detailTitle') }}</h2>
            </div>
            <button type="button" :aria-label="t('common.close')" @click="closeExecution">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
            </button>
          </header>
          <div class="audit-drawer-body">
            <dl class="audit-detail-grid">
              <dt>{{ t('governance.colTool') }}</dt><dd>{{ selectedExecution.toolName }}</dd>
              <dt>{{ t('governance.colStatus') }}</dt><dd>{{ executionStatus(selectedExecution) }}</dd>
              <dt>{{ t('governance.colDuration') }}</dt><dd>{{ duration(selectedExecution) }}</dd>
              <dt>{{ t('governance.conversation') }}</dt><dd>{{ selectedExecution.conversationId || '-' }}</dd>
              <dt>{{ t('governance.colTime') }}</dt><dd>{{ formatTime(selectedExecution.startedAt) }}</dd>
            </dl>
            <section class="audit-detail-block"><h3>{{ t('governance.arguments') }}</h3><pre class="audit-code-block">{{ formatJSON(selectedExecution.arguments) }}</pre></section>
            <section v-if="selectedExecution.result" class="audit-detail-block"><h3>{{ t('governance.resultOutput') }}</h3><pre class="audit-code-block">{{ selectedExecution.result }}</pre></section>
            <section v-if="selectedExecution.error" class="audit-detail-block"><h3>{{ t('governance.errorOutput') }}</h3><pre class="audit-code-block error">{{ selectedExecution.error }}</pre></section>
          </div>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="selectedAudit" class="audit-drawer-layer" @click.self="closeAudit">
        <aside class="audit-drawer" role="dialog" aria-modal="true">
          <header class="audit-drawer-head">
            <div>
              <span class="audit-floor-code">COMPLIANCE TRACE</span>
              <h2>{{ t('governance.auditDetailTitle') }}</h2>
            </div>
            <button type="button" :aria-label="t('common.close')" @click="closeAudit">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
            </button>
          </header>
          <div class="audit-drawer-body">
            <dl class="audit-detail-grid">
              <dt>{{ t('governance.colTime') }}</dt><dd>{{ formatTime(selectedAudit.createdAt) }}</dd>
              <dt>{{ t('governance.colUser') }}</dt><dd>{{ selectedAudit.username || '-' }}</dd>
              <dt>{{ t('governance.colAction') }}</dt><dd>{{ selectedAudit.action }}</dd>
              <dt>{{ t('governance.colResource') }}</dt><dd>{{ selectedAudit.resourceType }}{{ selectedAudit.resourceId ? ` · ${selectedAudit.resourceId}` : '' }}</dd>
              <dt>{{ t('governance.colResult') }}</dt><dd><span class="audit-result-stamp" :class="`tone-${auditTone(selectedAudit)}`">{{ selectedAudit.result === 'success' ? t('governance.success') : t('governance.failed') }}</span></dd>
            </dl>
            <section class="audit-detail-block"><h3>{{ t('governance.colDetail') }}</h3><pre class="audit-code-block">{{ selectedAudit.detail || '-' }}</pre></section>
          </div>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.header-actions {
  display: flex;
  gap: 8px;
}

.button.active {
  border-color: var(--accent);
  background: var(--accent-soft);
}

.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
  margin-bottom: 16px;
}

.stat-card {
  position: relative;
  display: grid;
  gap: 4px;
  padding: 16px 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.stat-card::before {
  position: absolute;
  top: -1px;
  left: -1px;
  width: 42px;
  height: 4px;
  content: '';
  background: var(--accent);
  opacity: 1;
}

.stat-card small {
  color: var(--text-muted);
  font-size: 12px;
}

.stat-card strong {
  font-family: var(--mono);
  font-size: 24px;
  font-variant-numeric: tabular-nums;
}

.stat-hint.danger {
  color: var(--danger);
  font-size: 12px;
}

.stat-hint {
  color: var(--text-muted);
  font-size: 11px;
  line-height: 1.5;
}

.context-warning {
  margin: 8px 0 0;
  color: var(--warning);
  font-size: 12px;
}

.panel {
  padding: 18px;
  margin-bottom: 16px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.panel-header h2 {
  margin: 0;
  font-size: 17px;
}

.panel-hint {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 12px;
}

.empty-state {
  margin: 0;
  padding: 18px 4px;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
}

.hitl-list {
  display: grid;
  gap: 12px;
}

.hitl-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 260px;
  gap: 16px;
  padding: 14px;
  border: 1px solid color-mix(in srgb, var(--warning) 45%, var(--border));
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--warning) 8%, var(--surface));
  box-shadow: none;
}

.hitl-title {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 8px;
}

.hitl-side {
  display: grid;
  gap: 8px;
  align-content: start;
}

.hitl-side input {
  width: 100%;
  padding: 8px 10px;
}

.hitl-buttons {
  display: flex;
  gap: 8px;
}

.time,
.time-cell {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 12px;
  white-space: nowrap;
}

.mono {
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 12px;
}

.code-block {
  max-height: 260px;
  margin: 0;
  padding: 10px 12px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.error-block {
  border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  color: var(--danger);
}

.data-list {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid var(--border);
  background: var(--surface);
}

.data-list th,
.data-list td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 13px;
  vertical-align: top;
}

.data-list th {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.summary-cell {
  max-width: min(520px, 38vw);
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}

.state-badge {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid currentColor;
  border-radius: 8px;
  font-family: var(--mono);
  font-size: 11px;
}

.state-success {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.state-failed {
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.state-running {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.audit-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.audit-filters select,
.audit-filters input {
  padding: 6px 10px;
  font-size: 12px;
}

.audit-filters input {
  min-width: 220px;
}

.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 12px;
  color: var(--text-muted);
  font-size: 13px;
}

.pagination-actions {
  display: flex;
  gap: 8px;
}

.detail-drawer {
  position: fixed;
  top: 0;
  right: 0;
  z-index: 20;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  width: min(640px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
}

.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.drawer-header h2 {
  margin: 0;
  font-size: 17px;
}

.text-button.dark {
  color: var(--text-muted);
}

.drawer-body {
  display: grid;
  gap: 14px;
  align-content: start;
  padding: 18px 20px;
  overflow: auto;
}

.detail-list {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: 6px 12px;
  margin: 0;
  font-size: 13px;
}

.detail-list dt {
  color: var(--text-muted);
}

.detail-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.detail-block h3 {
  margin: 0 0 6px;
  font-size: 13px;
}

@media (max-width: 900px) {
  .hitl-card {
    grid-template-columns: 1fr;
  }

  .audit-filters input {
    min-width: 0;
    width: 100%;
  }
}
</style>

<style scoped>
.main-column .page-governance .audit-command-header h1 {
  font-size: 26px;
}

.main-column .page-governance .audit-command-header .eyebrow {
  font-size: 9px;
}

.main-column .page-governance .audit-page-hint {
  font-size: 13px;
  line-height: 1.45;
}

.audit-stat small {
  font-size: 10px;
}

.audit-tabs small {
  font-size: 9px;
}
</style>

<style scoped>
/* Security QA control room */
.main-column .page-governance.audit-control {
  --audit-accent: #f0a43a;
  --audit-cyan: #55c7e8;
  --audit-mint: #34d399;
  --audit-coral: #fb7185;
  --audit-violet: #9d8cff;
  --audit-panel: color-mix(in srgb, var(--surface) 95%, #100d08);
  --audit-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-governance.audit-control .audit-command-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--audit-accent) 24%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--audit-accent) 9%, transparent), transparent 38%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--audit-accent) 5%, transparent) 37px 38px
    ),
    var(--audit-panel) !important;
}

.audit-heading {
  display: flex;
  min-width: 0;
  gap: 13px;
  align-items: center;
}

.audit-heading > div {
  min-width: 0;
}

.audit-inspector {
  position: relative;
  display: block;
  flex: 0 0 46px;
  width: 46px;
  height: 50px;
  color: var(--audit-accent);
}

.audit-inspector-antenna {
  position: absolute;
  top: 0;
  left: 22px;
  width: 2px;
  height: 9px;
  background: currentColor;
}

.audit-inspector-antenna::before {
  position: absolute;
  top: -3px;
  left: -2px;
  width: 5px;
  height: 5px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, currentColor 30%, transparent);
  box-shadow: 0 0 8px color-mix(in srgb, currentColor 50%, transparent);
}

.audit-inspector-face {
  position: absolute;
  top: 8px;
  left: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  width: 42px;
  height: 27px;
  border: 1px solid currentColor;
  border-radius: 7px;
  background: color-mix(in srgb, currentColor 7%, var(--surface));
}

.audit-inspector-face b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
  animation: audit-eye-scan 3.5s ease-in-out infinite;
}

.audit-inspector-face em {
  position: absolute;
  bottom: 4px;
  width: 9px;
  height: 1px;
  background: currentColor;
}

.audit-inspector-body {
  position: absolute;
  bottom: 0;
  left: 8px;
  width: 31px;
  height: 11px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

.main-column .page-governance .audit-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.audit-command-header .header-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
}

.audit-command-header .button {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.audit-command-header .button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.audit-refresh-toggle.active {
  color: var(--audit-mint) !important;
  border-color: color-mix(in srgb, var(--audit-mint) 50%, var(--border)) !important;
  background: color-mix(in srgb, var(--audit-mint) 9%, transparent) !important;
}

.audit-live-led {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--text-muted);
}

.audit-refresh-toggle.active .audit-live-led {
  background: var(--audit-mint);
  box-shadow: 0 0 7px var(--audit-mint);
  animation: audit-live-pulse 2.2s ease-in-out infinite;
}

.audit-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.audit-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(5, minmax(100px, 1fr));
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--audit-line);
  border-radius: 5px;
  background: var(--audit-line);
}

.audit-stat {
  --audit-tone: var(--text-muted);
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 8px;
  min-height: 66px;
  padding: 9px 11px;
  background: var(--audit-panel);
}

.audit-stat::after {
  position: absolute;
  bottom: 0;
  left: 11px;
  width: 28px;
  height: 2px;
  content: '';
  background: var(--audit-tone);
}

.audit-stat > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.audit-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 23px;
  font-weight: 500;
}

.audit-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 9px;
}

.audit-stat.tone-pending {
  --audit-tone: var(--audit-accent);
}

.audit-stat.tone-running {
  --audit-tone: var(--audit-cyan);
}

.audit-stat.tone-failed {
  --audit-tone: var(--audit-coral);
}

.audit-stat.tone-audit {
  --audit-tone: var(--audit-violet);
}

.audit-stat.tone-injection {
  --audit-tone: var(--audit-mint);
}

.audit-status-scan {
  position: absolute;
  right: 12px;
  bottom: 8px;
  width: 42px;
  height: 8px;
  overflow: hidden;
  opacity: 0.45;
}

.audit-status-scan::before {
  position: absolute;
  inset: 0;
  content: '';
  background: repeating-linear-gradient(
    90deg,
    var(--audit-accent) 0 3px,
    transparent 3px 7px
  );
}

.audit-status-scan i {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--audit-mint);
  box-shadow: 0 0 7px var(--audit-mint);
  animation: audit-status-sweep 4s linear infinite;
}

.audit-tabs {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 6px;
  margin-bottom: 10px;
}

.audit-tabs button {
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  min-width: 0;
  min-height: 55px;
  padding: 8px 10px;
  border: 1px solid var(--audit-line);
  border-radius: 4px;
  color: var(--text-secondary);
  background: var(--audit-panel);
  text-align: left;
  cursor: pointer;
}

.audit-tabs button:hover {
  border-color: color-mix(in srgb, var(--audit-accent) 42%, var(--border));
}

.audit-tabs button.active {
  color: var(--text-primary);
  border-color: color-mix(in srgb, var(--audit-accent) 66%, var(--border));
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--audit-accent) 9%, transparent), transparent),
    var(--audit-panel);
  box-shadow: inset 3px 0 0 var(--audit-accent);
}

.audit-tabs svg {
  width: 18px;
  height: 18px;
  fill: none;
  stroke: var(--audit-accent);
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.audit-tabs span {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.audit-tabs strong {
  font-size: 11px;
  font-weight: 600;
}

.audit-tabs small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-tabs b {
  color: var(--audit-accent);
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 500;
}

.audit-floor-panel {
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--audit-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--audit-panel);
}

.audit-floor-header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--audit-accent) 5%, transparent), transparent 44%),
    var(--audit-panel);
}

.audit-floor-code {
  color: var(--audit-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.audit-floor-header h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 600;
}

.audit-floor-header p {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 9px;
}

.audit-floor-count {
  display: grid;
  min-width: 36px;
  height: 36px;
  border: 1px solid color-mix(in srgb, var(--audit-accent) 35%, var(--border));
  border-radius: 50%;
  color: var(--audit-accent);
  background: color-mix(in srgb, var(--audit-accent) 6%, transparent);
  font-family: var(--mono);
  font-size: 14px;
  place-items: center;
}

.audit-run-summary {
  display: flex;
  gap: 12px;
  align-items: center;
}

.audit-run-summary > span:first-child {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.audit-run-summary strong {
  color: var(--audit-mint);
  font-size: 12px;
}

.audit-approval-list {
  display: grid;
  gap: 6px;
  padding: 10px;
}

.audit-approval-row {
  --gate-color: var(--audit-accent);
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr) minmax(210px, 260px);
  gap: 10px;
  align-items: start;
  padding: 9px;
  border: 1px solid color-mix(in srgb, var(--gate-color) 28%, var(--border));
  border-radius: 4px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--gate-color) 7%, transparent), transparent 30%),
    var(--surface);
}

.audit-approval-row.expanded {
  border-color: color-mix(in srgb, var(--gate-color) 58%, var(--border));
}

.gate-robot,
.audit-empty-robot {
  position: relative;
  display: flex;
  width: 38px;
  height: 36px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  border: 1px solid var(--gate-color, var(--text-muted));
  border-radius: 7px;
  color: var(--gate-color, var(--text-muted));
  background: color-mix(in srgb, var(--gate-color, var(--text-muted)) 7%, var(--surface));
}

.gate-robot::before,
.audit-empty-robot::before {
  position: absolute;
  top: -7px;
  left: 17px;
  width: 1px;
  height: 6px;
  content: '';
  background: currentColor;
}

.gate-robot b,
.audit-empty-robot b {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 5px currentColor;
  animation: audit-eye-scan 3s ease-in-out infinite;
}

.gate-robot em,
.audit-empty-robot i {
  position: absolute;
  bottom: -7px;
  width: 24px;
  height: 7px;
  border: 1px solid currentColor;
  border-radius: 2px;
}

.audit-approval-main {
  display: grid;
  min-width: 0;
  gap: 7px;
}

.audit-approval-title {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
}

.audit-approval-title strong {
  color: var(--text-primary);
  font-size: 11px;
}

.audit-approval-title time {
  margin-left: auto;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.audit-pending-stamp {
  padding: 1px 5px;
  border: 1px solid color-mix(in srgb, var(--audit-accent) 48%, var(--border));
  border-radius: 2px;
  color: var(--audit-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.audit-approval-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 12px;
  align-items: center;
  color: var(--text-muted);
  font-size: 8px;
}

.audit-approval-meta code {
  color: var(--text-secondary);
  font-family: var(--mono);
}

.audit-approval-meta button {
  margin-left: auto;
  padding: 2px 5px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--audit-accent);
  background: transparent;
  font-size: 8px;
  cursor: pointer;
}

.audit-approval-actions {
  display: grid;
  grid-template-columns: 1fr auto auto;
  gap: 5px;
  align-items: center;
}

.audit-approval-actions input {
  min-width: 0;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.audit-approve {
  border-color: color-mix(in srgb, var(--audit-mint) 48%, var(--border)) !important;
  color: var(--audit-mint) !important;
  background: color-mix(in srgb, var(--audit-mint) 8%, transparent) !important;
}

.audit-code-block {
  max-height: 240px;
  margin: 0;
  padding: 8px 10px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 9px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.audit-code-block.error {
  border-color: color-mix(in srgb, var(--audit-coral) 45%, var(--border));
  color: var(--audit-coral);
}

.audit-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
  padding: 9px 11px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 52%, transparent);
}

.audit-search-box {
  display: flex;
  flex: 1 1 220px;
  min-width: 170px;
  gap: 6px;
  align-items: center;
  padding: 0 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.audit-search-box svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: var(--text-muted);
  stroke-width: 1.7;
  stroke-linecap: round;
}

.audit-search-box input {
  min-width: 0;
  padding: 7px 0 !important;
  border: 0 !important;
  outline: 0;
  background: transparent !important;
  box-shadow: none !important;
}

.audit-segmented {
  display: inline-flex;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.audit-segmented button {
  min-height: 26px;
  padding: 3px 8px;
  border: 0;
  border-radius: 2px;
  color: var(--text-muted);
  background: transparent;
  font-size: 9px;
  cursor: pointer;
}

.audit-segmented button.active {
  color: var(--text-primary);
  background: color-mix(in srgb, var(--audit-accent) 12%, var(--surface));
  box-shadow: inset 0 -2px 0 var(--audit-accent);
}

.audit-log-filters select {
  min-height: 31px;
  padding: 5px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  font-size: 9px;
}

.audit-log-filters > span {
  margin-left: auto;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.audit-execution-list {
  display: grid;
  gap: 4px;
  padding: 9px;
}

.audit-execution-row {
  --run-color: var(--audit-mint);
  display: grid;
  grid-template-columns: 29px 78px minmax(140px, 0.8fr) 118px 66px minmax(180px, 1.5fr) auto;
  gap: 8px;
  align-items: center;
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-left: 2px solid var(--run-color);
  border-radius: 3px;
  color: inherit;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--run-color) 4%, transparent), transparent 24%),
    var(--surface);
  text-align: left;
  cursor: pointer;
}

.audit-execution-row:hover {
  border-color: color-mix(in srgb, var(--run-color) 48%, var(--border));
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--run-color) 8%, transparent), transparent 28%),
    var(--surface);
}

.audit-execution-row.tone-running {
  --run-color: var(--audit-cyan);
}

.audit-execution-row.tone-failed {
  --run-color: var(--audit-coral);
}

.audit-execution-robot {
  position: relative;
  display: flex;
  width: 25px;
  height: 22px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  border: 1px solid var(--run-color);
  border-radius: 5px;
  color: var(--run-color);
}

.audit-execution-robot::before {
  position: absolute;
  top: -5px;
  left: 11px;
  width: 1px;
  height: 4px;
  content: '';
  background: currentColor;
}

.audit-execution-robot b {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: currentColor;
}

.audit-execution-robot i {
  position: absolute;
  bottom: -5px;
  width: 16px;
  height: 5px;
  border: 1px solid currentColor;
  border-radius: 1px;
}

.audit-execution-status {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--run-color);
  font-family: var(--mono);
  font-size: 8px;
  white-space: nowrap;
}

.audit-execution-status i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
}

.tone-running .audit-execution-status i {
  animation: audit-live-pulse 1.8s ease-in-out infinite;
}

.audit-execution-tool {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.audit-execution-tool strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-execution-tool small,
.audit-execution-row > code,
.audit-execution-row > time {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-execution-summary {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-trace-link {
  color: var(--run-color);
  font-family: var(--mono);
  font-size: 8px;
  white-space: nowrap;
}

.audit-log-table,
.audit-compaction-list {
  min-width: 760px;
}

.audit-log-head,
.audit-log-row,
.audit-compaction-head,
.audit-compaction-row {
  display: grid;
  align-items: center;
}

.audit-log-head,
.audit-log-row {
  grid-template-columns: 128px 90px minmax(110px, 0.7fr) minmax(160px, 1fr) 70px minmax(180px, 1.2fr);
}

.audit-log-head,
.audit-compaction-head {
  min-height: 31px;
  padding: 5px 10px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  background: color-mix(in srgb, var(--field-bg) 78%, var(--audit-accent));
  font-family: var(--mono);
  font-size: 8px;
}

.audit-log-row {
  width: 100%;
  min-height: 38px;
  padding: 6px 10px;
  border: 0;
  border-bottom: 1px solid var(--border);
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.audit-log-row:hover {
  background: color-mix(in srgb, var(--audit-accent) 5%, transparent);
}

.audit-log-row time,
.audit-log-row code,
.audit-log-row > span:last-child {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-log-row > strong {
  color: var(--text-secondary);
  font-size: 9px;
}

.audit-result-stamp {
  display: inline-flex;
  width: fit-content;
  min-height: 18px;
  align-items: center;
  padding: 1px 6px;
  border: 1px solid currentColor;
  border-radius: 2px;
  font-family: var(--mono);
  font-size: 8px;
}

.tone-success .audit-result-stamp,
.audit-result-stamp.tone-success {
  color: var(--audit-mint);
  background: color-mix(in srgb, var(--audit-mint) 7%, transparent);
}

.tone-failed .audit-result-stamp,
.audit-result-stamp.tone-failed {
  color: var(--audit-coral);
  background: color-mix(in srgb, var(--audit-coral) 7%, transparent);
}

.audit-pagination {
  display: flex;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 9px 11px;
  border-top: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 9px;
}

.audit-pagination > div {
  display: flex;
  gap: 6px;
}

.audit-context-metrics {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 1px;
  margin: 10px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--border);
}

.audit-context-stat {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 7px;
  min-height: 64px;
  padding: 9px 10px;
  background: var(--surface);
}

.audit-context-stat > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
}

.audit-context-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 18px;
  font-weight: 500;
}

.audit-context-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 8px;
}

.audit-context-stat i {
  position: absolute;
  bottom: 0;
  left: 10px;
  width: 24px;
  height: 2px;
  background: var(--audit-cyan);
}

.audit-context-stat i.tone-mint {
  background: var(--audit-mint);
}

.audit-context-stat i.tone-violet {
  background: var(--audit-violet);
}

.audit-context-stat i.tone-amber {
  background: var(--audit-accent);
}

.audit-context-stat i.tone-coral {
  background: var(--audit-coral);
}

.audit-memory-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  align-items: center;
  margin: 0 10px 10px;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.memory-node {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.memory-node b {
  margin-left: 3px;
  color: var(--text-secondary);
}

.audit-memory-strip > i {
  width: 18px;
  height: 1px;
  background: color-mix(in srgb, var(--audit-violet) 42%, var(--border));
}

.audit-compaction-list {
  margin: 0 10px 10px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
}

.audit-compaction-head,
.audit-compaction-row {
  grid-template-columns: 130px 80px 64px 120px minmax(110px, 1fr) 70px;
}

.audit-compaction-row {
  min-height: 37px;
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 8px;
}

.audit-compaction-row time,
.audit-compaction-row code {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.compaction-kind {
  width: fit-content;
  padding: 1px 5px;
  border: 1px solid color-mix(in srgb, var(--audit-cyan) 42%, var(--border));
  border-radius: 2px;
  color: var(--audit-cyan);
  font-family: var(--mono);
}

.compaction-kind.major {
  border-color: color-mix(in srgb, var(--audit-accent) 45%, var(--border));
  color: var(--audit-accent);
}

.ratio-track {
  position: relative;
  display: flex;
  height: 14px;
  align-items: center;
  padding: 0 4px;
  overflow: hidden;
  border-radius: 2px;
  background: var(--field-bg);
}

.ratio-track i {
  position: absolute;
  inset: 0 auto 0 0;
  background: color-mix(in srgb, var(--audit-mint) 18%, transparent);
}

.ratio-track b {
  position: relative;
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 8px;
}

.audit-empty-state {
  display: grid;
  min-height: 170px;
  gap: 12px;
  place-items: center;
  align-content: center;
  color: var(--text-muted);
  font-size: 10px;
}

.audit-empty-state.compact {
  min-height: 90px;
}

.audit-empty-robot {
  --gate-color: var(--text-muted);
}

.audit-drawer-layer {
  position: fixed;
  inset: 0;
  z-index: 90;
  display: flex;
  justify-content: flex-end;
  background: rgba(6, 7, 5, 0.6);
  backdrop-filter: blur(3px);
}

.audit-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  width: min(610px, 100%);
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--audit-accent) 28%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--audit-accent) 4%, transparent), transparent 170px),
    var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.36);
  animation: audit-drawer-in 0.22s ease-out both;
}

.audit-drawer-head {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface-soft) 76%, transparent);
}

.audit-drawer-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 16px;
}

.audit-drawer-head > button {
  display: grid;
  width: 31px;
  height: 31px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
  place-items: center;
}

.audit-drawer-head > button:hover {
  border-color: color-mix(in srgb, var(--audit-coral) 48%, var(--border));
  color: var(--audit-coral);
}

.audit-drawer-head svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
}

.audit-drawer-body {
  display: grid;
  gap: 11px;
  align-content: start;
  padding: 14px;
  overflow: auto;
}

.audit-detail-grid {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  margin: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
}

.audit-detail-grid dt,
.audit-detail-grid dd {
  min-width: 0;
  margin: 0;
  padding: 7px 9px;
  border-bottom: 1px solid var(--border);
  font-size: 9px;
}

.audit-detail-grid dt {
  color: var(--text-muted);
  background: var(--field-bg);
}

.audit-detail-grid dd {
  overflow-wrap: anywhere;
  color: var(--text-secondary);
  font-family: var(--mono);
}

.audit-detail-block h3 {
  margin: 0 0 6px;
  color: var(--text-secondary);
  font-size: 10px;
}

.context-warning {
  margin: 0 10px 10px;
  padding: 8px 9px;
  border-left: 2px solid var(--audit-accent);
  color: var(--audit-accent);
  background: color-mix(in srgb, var(--audit-accent) 6%, transparent);
  font-size: 9px;
}

@keyframes audit-eye-scan {
  0%,
  100% {
    opacity: 0.55;
  }
  48% {
    opacity: 1;
  }
  52% {
    opacity: 0.35;
  }
}

@keyframes audit-live-pulse {
  0%,
  100% {
    opacity: 0.5;
  }
  50% {
    opacity: 1;
  }
}

@keyframes audit-status-sweep {
  from {
    left: 0;
  }
  to {
    left: 100%;
  }
}

@keyframes audit-drawer-in {
  from {
    opacity: 0;
    transform: translateX(24px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

@media (max-width: 1180px) {
  .audit-tabs {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .audit-execution-row {
    grid-template-columns: 29px 76px minmax(130px, 1fr) 112px 62px minmax(150px, 1fr);
  }

  .audit-trace-link {
    display: none;
  }

  .audit-approval-row {
    grid-template-columns: 42px minmax(0, 1fr);
  }

  .audit-approval-actions {
    grid-column: 2;
  }

  .audit-context-metrics {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .main-column .page-governance.audit-control {
    overflow-x: hidden;
  }

  .audit-command-header {
    align-items: stretch;
  }

  .audit-heading {
    align-items: flex-start;
  }

  .audit-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .audit-status-rail .audit-stat:last-of-type {
    grid-column: span 2;
  }

  .audit-tabs {
    grid-template-columns: 1fr;
  }

  .audit-tabs button {
    min-width: 0;
    overflow: hidden;
  }

  .audit-floor-header {
    align-items: flex-start;
  }

  .audit-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .audit-toolbar > *,
  .audit-search-box,
  .audit-log-filters select {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .audit-segmented {
    max-width: 100%;
    overflow-x: auto;
  }

  .audit-approval-row {
    grid-template-columns: 36px minmax(0, 1fr);
  }

  .audit-approval-actions {
    grid-column: 1 / -1;
    grid-template-columns: 1fr auto auto;
  }

  .audit-approval-title time {
    flex-basis: 100%;
    margin-left: 0;
  }

  .audit-execution-row {
    grid-template-columns: 26px 72px minmax(0, 1fr) auto;
  }

  .audit-execution-row > time,
  .audit-execution-row > code,
  .audit-execution-summary {
    display: none;
  }

  .audit-log-table,
  .audit-compaction-list {
    overflow-x: auto;
  }

  .audit-context-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .audit-context-stat:last-child {
    grid-column: span 2;
  }

  .audit-pagination {
    align-items: flex-start;
    flex-direction: column;
  }

  .audit-detail-grid {
    grid-template-columns: 92px minmax(0, 1fr);
  }

  .audit-drawer {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .audit-inspector-face b,
  .gate-robot b,
  .audit-empty-robot b,
  .audit-refresh-toggle.active .audit-live-led,
  .tone-running .audit-execution-status i,
  .audit-status-scan i {
    animation: none;
  }

  .audit-drawer {
    animation: none;
  }
}
</style>

<style scoped>
/* Audit & Monitoring in the Vulnerability Management visual system */
.main-column .page-governance.audit-control .audit-command-header {
  min-height: 78px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-governance .audit-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-governance .audit-command-header .button {
  min-height: 30px;
  padding: 5px 9px;
  border-radius: 3px;
  font-size: 10px;
}

.audit-status-rail {
  display: grid;
  grid-template-columns: repeat(5, minmax(110px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  padding: 0;
  border: 0;
  background: transparent;
}

.audit-stat {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 4px;
  align-content: center;
  min-height: 72px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.audit-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: var(--accent);
  font-size: 12px;
}

.audit-stat-icon {
  width: 16px;
  height: 16px;
  flex: 0 0 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
  opacity: 0.82;
}

.audit-stat strong {
  color: var(--accent);
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.audit-stat::after {
  display: none;
}

.audit-stat.tone-pending {
  border-left-color: var(--warning);
}

.audit-stat.tone-pending small,
.audit-stat.tone-pending strong {
  color: var(--warning);
}

.audit-stat.tone-running {
  border-left-color: #55c7e8;
}

.audit-stat.tone-running small,
.audit-stat.tone-running strong {
  color: #55c7e8;
}

.audit-stat.tone-failed {
  border-left-color: var(--danger);
}

.audit-stat.tone-failed small,
.audit-stat.tone-failed strong {
  color: var(--danger);
}

.audit-stat.tone-audit {
  border-left-color: var(--accent);
}

.audit-stat.tone-audit small,
.audit-stat.tone-audit strong {
  color: var(--accent);
}

.audit-stat.tone-injection {
  border-left-color: var(--success);
}

.audit-stat.tone-injection small,
.audit-stat.tone-injection strong {
  color: var(--success);
}

.audit-stat.tone-context {
  border-left-color: var(--success);
}

.audit-status-scan {
  display: none;
}

.audit-tabs {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}

.audit-tabs button {
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr) auto;
  min-height: 44px;
  width: 100%;
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: var(--surface);
}

.audit-tabs button.active {
  border-left-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 6%, var(--surface));
}

.audit-tabs button small {
  display: none;
}

.audit-floor-panel {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.audit-empty-state {
  min-height: 120px;
  padding: 22px 14px;
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.audit-approval-list,
.audit-execution-list,
.audit-log-table {
  border: 1px solid var(--line);
  background: var(--surface);
}

.audit-approval-row,
.audit-execution-row,
.audit-log-row {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
}

.audit-approval-row:hover,
.audit-execution-row:hover,
.audit-log-row:hover {
  background: color-mix(in srgb, var(--accent) 4%, transparent);
}

.audit-approval-row:last-child,
.audit-execution-row:last-child,
.audit-log-row:last-child {
  border-bottom: 0;
}

.audit-toolbar {
  padding: 8px 10px;
  background: var(--surface-soft);
}

.audit-search-box {
  height: 34px;
  border-radius: var(--radius);
  background: var(--field-bg);
}

.audit-search-box input {
  height: 32px;
  padding: 0;
  border: 0;
  background: transparent;
}

.audit-segmented {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}

.audit-floor-header,
.audit-toolbar,
.panel-header {
  border-bottom: 1px solid var(--border);
  background: var(--surface-soft);
}

.panel,
.audit-floor-panel,
.audit-context-metrics,
.audit-compaction-list {
  border-color: var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.audit-execution-row,
.audit-compaction-row,
.hitl-card {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
}

.audit-execution-row:hover,
.audit-compaction-row:hover {
  background: color-mix(in srgb, var(--accent) 4%, transparent);
}

.audit-drawer-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.audit-drawer {
  width: min(720px, 100%);
  border-left-color: color-mix(in srgb, var(--accent) 32%, var(--border));
  background: var(--surface);
}

.audit-drawer-head,
.audit-drawer-foot {
  background: var(--surface-soft);
}

@media (max-width: 1100px) {
  .audit-status-rail {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .audit-tabs {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .audit-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .audit-tabs {
    grid-template-columns: minmax(0, 1fr);
  }

  .audit-drawer {
    width: 100%;
  }
}
</style>
