<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost } from '../api/client'
import DataPagination from '../components/DataPagination.vue'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()
const canWrite = computed(() => auth.hasPermission('asset:write'))
const canDelete = computed(() => auth.hasPermission('asset:delete'))

interface Project {
  id: string
  name: string
}

interface IntelCapabilities {
  enabled: boolean
  fofaConfigured: boolean
  hunterConfigured: boolean
}

interface IntelResult {
  source: string
  url: string
  domain: string
  ip: string
  port: number
  title: string
  protocol: string
  server: string
  org: string
  location: string
  updatedAt: string
  components: string[]
  sources: string[]
}

interface IntelSearchSummary {
  id: string
  projectId: string
  provider: string
  query: string
  page: number
  pageSize: number
  startTime: string
  resultCount: number
  createdAt: string
}

interface IntelSearchDetail extends IntelSearchSummary {
  results: IntelResult[]
  providerErrors: string[]
  persisted?: boolean
  persistWarning?: string
}

interface ImportSummary {
  created: number
  existing: number
  skippedInvalid: number
  failed: number
}

const projects = ref<Project[]>([])
const capabilities = reactive<IntelCapabilities>({
  enabled: false,
  fofaConfigured: false,
  hunterConfigured: false,
})
const histories = ref<IntelSearchSummary[]>([])
const selected = ref<IntelSearchDetail | null>(null)
const loadingHistory = ref(false)
const loadingDetail = ref(false)
const searching = ref(false)
const importing = ref(false)
const deletingID = ref('')
const queryFocused = ref(false)
const error = ref('')
const notice = ref('')
const warning = ref('')

const form = reactive({
  provider: 'all',
  query: '',
  projectId: '',
  page: 1,
  pageSize: 20,
  startTime: '',
})

const historyPagination = reactive({
  page: 1,
  pageSize: 10,
  total: 0,
  totalPages: 1,
})

const resultPagination = reactive({
  page: 1,
  pageSize: 20,
  total: 0,
  totalPages: 1,
})

const providers = computed(() => [
  { value: 'all', label: t('intel.providerAll') },
  { value: 'fofa', label: 'FOFA' },
  { value: 'hunter', label: 'Hunter' },
])

const queryEnabled = computed(() => {
  if (!capabilities.enabled) {
    return false
  }
  if (form.provider === 'fofa') {
    return capabilities.fofaConfigured
  }
  if (form.provider === 'hunter') {
    return capabilities.hunterConfigured
  }
  return capabilities.fofaConfigured || capabilities.hunterConfigured
})

const selectedProjectID = computed(() => selected.value?.projectId || form.projectId)
const currentResultCount = computed(() => selected.value?.resultCount ?? 0)
const queryExpanded = computed(() => queryFocused.value)
const pagedResults = computed(() => {
  const results = selected.value?.results ?? []
  const start = (resultPagination.page - 1) * resultPagination.pageSize
  return results.slice(start, start + resultPagination.pageSize)
})

async function loadProjects() {
  const loaded: Project[] = []
  let cursor = ''
  try {
    do {
      const query = new URLSearchParams({ limit: '100' })
      if (cursor) {
        query.set('before', cursor)
      }
      const response = await apiGet<{
        items: Project[]
        hasMore: boolean
        nextCursor: string
      }>(`/projects?${query.toString()}`)
      loaded.push(...(response.items ?? []))
      cursor = response.nextCursor ?? ''
      if (!response.hasMore || !cursor) {
        break
      }
    } while (true)
    projects.value = loaded
  } catch {
    projects.value = []
  }
}

async function loadCapabilities() {
  capabilities.enabled = false
  capabilities.fofaConfigured = false
  capabilities.hunterConfigured = false
  try {
    const response = await apiGet<IntelCapabilities>('/intel/capabilities')
    capabilities.enabled = response.enabled
    capabilities.fofaConfigured = response.fofaConfigured
    capabilities.hunterConfigured = response.hunterConfigured
  } catch {
    capabilities.enabled = false
  }
}

async function loadHistory(resetPage = false) {
  if (resetPage) {
    historyPagination.page = 1
  }
  loadingHistory.value = true
  try {
    const query = new URLSearchParams({
      limit: String(historyPagination.pageSize),
      offset: String((historyPagination.page - 1) * historyPagination.pageSize),
    })
    if (form.projectId) {
      query.set('projectId', form.projectId)
    }
    const response = await apiGet<{
      items: IntelSearchSummary[]
      total: number
    }>(`/intel/searches?${query.toString()}`)
    histories.value = response.items ?? []
    historyPagination.total = response.total ?? 0
    historyPagination.totalPages = Math.max(
      1,
      Math.ceil(historyPagination.total / historyPagination.pageSize),
    )
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('intel.historyLoadFailed')
  } finally {
    loadingHistory.value = false
  }
}

async function loadDetail(id: string) {
  if (!id || loadingDetail.value) {
    return
  }
  loadingDetail.value = true
  error.value = ''
  try {
    selected.value = await apiGet<IntelSearchDetail>(
      `/intel/searches/${encodeURIComponent(id)}`,
    )
    resetResultPagination()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('intel.detailLoadFailed')
  } finally {
    loadingDetail.value = false
  }
}

async function runSearch() {
  if (!canWrite.value || searching.value) {
    return
  }
  const queryText = form.query.trim()
  if (!queryText) {
    error.value = t('intel.queryRequired')
    return
  }
  if (!queryEnabled.value) {
    error.value = t('intel.providerNotConfigured')
    return
  }
  searching.value = true
  error.value = ''
  notice.value = ''
  warning.value = ''
  try {
    const response = await apiPost<IntelSearchDetail>('/intel/searches', {
      provider: form.provider,
      query: queryText,
      projectId: form.projectId,
      page: Number(form.page),
      page_size: Number(form.pageSize),
      start_time: form.startTime,
    })
    selected.value = response
    resetResultPagination()
    if (response.persisted === false) {
      warning.value = response.persistWarning || t('intel.persistWarning')
    } else {
      notice.value = t('intel.searchSaved', { count: response.resultCount })
    }
    historyPagination.page = 1
    await loadHistory()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('intel.searchFailed')
  } finally {
    searching.value = false
  }
}

async function importAssets() {
  if (!canWrite.value || importing.value || !selected.value) {
    return
  }
  const projectID = selectedProjectID.value
  if (!projectID) {
    error.value = t('intel.projectRequired')
    return
  }
  importing.value = true
  error.value = ''
  notice.value = ''
  warning.value = ''
  try {
    const response = await apiPost<ImportSummary>(
      `/intel/searches/${encodeURIComponent(selected.value.id)}/import`,
      { projectId: projectID },
    )
    notice.value = t('intel.imported', {
      created: response.created,
      existing: response.existing,
      skipped: response.skippedInvalid,
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('intel.importFailed')
  } finally {
    importing.value = false
  }
}

async function deleteHistory(item: IntelSearchSummary) {
  if (!canDelete.value || deletingID.value) {
    return
  }
  if (!window.confirm(t('intel.deleteConfirm'))) {
    return
  }
  deletingID.value = item.id
  error.value = ''
  notice.value = ''
  warning.value = ''
  try {
    await apiDelete(`/intel/searches/${encodeURIComponent(item.id)}`)
    if (selected.value?.id === item.id) {
      selected.value = null
    }
    await loadHistory()
    notice.value = t('intel.deleted')
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('intel.deleteFailed')
  } finally {
    deletingID.value = ''
  }
}

function selectHistory(item: IntelSearchSummary) {
  notice.value = ''
  void loadDetail(item.id)
}

function providerLabel(value: string) {
  if (value === 'fofa') {
    return 'FOFA'
  }
  if (value === 'hunter') {
    return 'Hunter'
  }
  return t('intel.providerAll')
}

function resultTarget(item: IntelResult) {
  if (item.url) {
    return item.url
  }
  const host = item.domain || item.ip
  if (!host) {
    return '-'
  }
  if (!item.port) {
    return host
  }
  const normalized = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
  return `${normalized}:${item.port}`
}

function resultSources(item: IntelResult) {
  return (item.sources?.length ? item.sources : [item.source])
    .filter(Boolean)
    .map((source) => source.toUpperCase())
    .join(' + ')
}

function formatTime(value: string) {
  if (!value) {
    return '-'
  }
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function projectName(projectID: string) {
  if (!projectID) {
    return t('intel.unlinkedProject')
  }
  return projects.value.find((item) => item.id === projectID)?.name ?? projectID
}

function changeHistoryPage(page: number) {
  historyPagination.page = page
  void loadHistory()
}

function resetResultPagination() {
  resultPagination.page = 1
  syncResultPagination()
}

function syncResultPagination() {
  resultPagination.total = selected.value?.results.length ?? 0
  resultPagination.totalPages = Math.max(
    1,
    Math.ceil(resultPagination.total / resultPagination.pageSize),
  )
  if (resultPagination.page > resultPagination.totalPages) {
    resultPagination.page = resultPagination.totalPages
  }
}

function changeResultPage(page: number) {
  resultPagination.page = page
  syncResultPagination()
}

function changeResultPageSize(pageSize: number) {
  resultPagination.pageSize = pageSize
  resultPagination.page = 1
  syncResultPagination()
}

function applyProjectFilter() {
  selected.value = null
  void loadHistory(true)
}

onMounted(async () => {
  await Promise.all([loadProjects(), loadCapabilities(), loadHistory()])
})
</script>

<template>
  <section class="page factory-page page-assets intel-collection-page">
    <header class="page-header intel-collection-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="pink" />
        <div>
          <p class="eyebrow">ASSET INTELLIGENCE // COLLECTION CONSOLE</p>
          <h1>{{ t('intel.title') }}</h1>
          <p class="intel-page-hint">{{ t('intel.subtitle') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button
          class="button"
          type="button"
          :disabled="loadingHistory"
          @click="Promise.all([loadCapabilities(), loadHistory()])"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
          {{ t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>
    <div v-if="warning" class="alert warn">{{ warning }}</div>
    <div v-if="!capabilities.enabled" class="alert warn">
      {{ t('intel.disabledHint') }}
    </div>
    <div
      v-else-if="!capabilities.fofaConfigured && !capabilities.hunterConfigured"
      class="alert warn"
    >
      {{ t('intel.noProviderConfigured') }}
    </div>

    <section class="intel-stat-rail">
      <article class="intel-stat-card tone-log">
        <span class="intel-stat-icon">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" />
          </svg>
        </span>
        <div>
          <small>{{ t('intel.totalQueries') }}</small>
          <strong>{{ historyPagination.total }}</strong>
          <em>{{ t('intel.savedQueries') }}</em>
        </div>
      </article>
      <article class="intel-stat-card tone-result">
        <span class="intel-stat-icon">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="11" cy="11" r="6" />
            <path d="m16 16 4 4M8 11h6M11 8v6" />
          </svg>
        </span>
        <div>
          <small>{{ t('intel.currentResults') }}</small>
          <strong>{{ currentResultCount }}</strong>
          <em>{{ t('intel.currentResultsHint') }}</em>
        </div>
      </article>
      <article class="intel-stat-card" :class="capabilities.fofaConfigured ? 'tone-online' : 'tone-offline'">
        <span class="intel-stat-icon">F</span>
        <div>
          <small>FOFA</small>
          <strong>{{ capabilities.fofaConfigured ? t('intel.configured') : t('intel.notConfigured') }}</strong>
          <em>{{ t('intel.providerCredential') }}</em>
        </div>
      </article>
      <article class="intel-stat-card" :class="capabilities.hunterConfigured ? 'tone-online' : 'tone-offline'">
        <span class="intel-stat-icon">H</span>
        <div>
          <small>Hunter</small>
          <strong>{{ capabilities.hunterConfigured ? t('intel.configured') : t('intel.notConfigured') }}</strong>
          <em>{{ t('intel.providerCredential') }}</em>
        </div>
      </article>
    </section>

    <section class="intel-command-console">
      <header class="intel-console-head">
        <div>
          <span>RUN CONFIGURATION</span>
          <strong>{{ t('intel.commandConsole') }}</strong>
        </div>
        <div class="intel-provider-switch" role="group" :aria-label="t('intel.provider')">
          <button
            v-for="provider in providers"
            :key="provider.value"
            type="button"
            :class="{ active: form.provider === provider.value }"
            @click="form.provider = provider.value"
          >
            {{ provider.label }}
          </button>
        </div>
      </header>
      <div class="intel-fofa-query-wrap">
        <div class="intel-fofa-query-box" :class="{ expanded: queryExpanded }">
          <textarea
            v-model="form.query"
            class="intel-fofa-query-input"
            rows="1"
            spellcheck="false"
            :placeholder="t('intel.queryPlaceholder')"
            @focus="queryFocused = true"
            @blur="queryFocused = false"
            @keydown.ctrl.enter.prevent="runSearch"
            @keydown.meta.enter.prevent="runSearch"
          ></textarea>
          <div class="intel-fofa-query-suffix">
            <span class="intel-fofa-sensor-state" :class="{ ready: queryEnabled }">
              <i></i>
              {{ queryEnabled ? t('intel.sensorReady') : t('intel.sensorBlocked') }}
            </span>
            <button
              class="intel-fofa-search-button"
              type="button"
              :title="searching ? t('intel.searching') : t('intel.search')"
              :aria-label="searching ? t('intel.searching') : t('intel.search')"
              :disabled="!canWrite || searching || !queryEnabled"
              @mousedown.prevent
              @click="runSearch"
            >
              <svg v-if="!searching" viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="11" cy="11" r="6" />
                <path d="m16 16 4 4" />
              </svg>
              <span v-else class="intel-search-spinner"></span>
            </button>
          </div>
        </div>
        <div class="intel-fofa-options">
          <label>
            <span>{{ t('asset.project') }}</span>
            <select v-model="form.projectId" @change="applyProjectFilter">
              <option value="">{{ t('intel.unlinkedProject') }}</option>
              <option v-for="project in projects" :key="project.id" :value="project.id">
                {{ project.name }}
              </option>
            </select>
          </label>
          <label>
            <span>{{ t('intel.page') }}</span>
            <input v-model.number="form.page" type="number" min="1" max="100" />
          </label>
          <label>
            <span>{{ t('intel.pageSize') }}</span>
            <input v-model.number="form.pageSize" type="number" min="1" max="100" />
          </label>
          <label>
            <span>{{ t('intel.startTime') }}</span>
            <input v-model="form.startTime" type="date" />
          </label>
        </div>
      </div>
    </section>

    <section class="intel-history-console">
      <header class="intel-section-head">
        <div>
          <span>EXECUTION HISTORY</span>
          <strong>{{ t('intel.history') }}</strong>
        </div>
        <em>{{ t('intel.historyCount', { count: historyPagination.total }) }}</em>
      </header>
      <div v-if="loadingHistory && !histories.length" class="intel-panel-state compact">
        {{ t('common.loading') }}
      </div>
      <div v-else-if="!histories.length" class="intel-panel-state compact">
        {{ t('intel.historyEmpty') }}
      </div>
      <div v-else class="intel-history-tape">
        <article
          v-for="item in histories"
          :key="item.id"
          :class="{ active: selected?.id === item.id }"
          class="intel-history-card"
        >
          <button
            class="intel-history-select"
            type="button"
            @click="selectHistory(item)"
          >
            <span class="intel-history-source">{{ providerLabel(item.provider) }}</span>
            <strong>{{ item.query }}</strong>
            <div>
              <small>{{ t('intel.resultCount', { count: item.resultCount }) }}</small>
              <em>{{ formatTime(item.createdAt) }}</em>
            </div>
            <span class="intel-history-project">{{ projectName(item.projectId) }}</span>
          </button>
          <button
            v-if="canDelete"
            class="intel-history-delete"
            type="button"
            :title="t('intel.delete')"
            :aria-label="t('intel.delete')"
            :disabled="!!deletingID"
            @click="deleteHistory(item)"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" />
            </svg>
          </button>
        </article>
      </div>
      <DataPagination
        v-if="historyPagination.total > historyPagination.pageSize"
        :total="historyPagination.total"
        :page="historyPagination.page"
        :page-size="historyPagination.pageSize"
        :total-pages="historyPagination.totalPages"
        :disabled="loadingHistory"
        @page-change="changeHistoryPage"
      />
    </section>

    <section class="intel-results-console">
      <header class="intel-section-head result-head">
        <div>
          <span>COLLECTION RESULTSET</span>
          <strong>{{ selected ? selected.query : t('intel.results') }}</strong>
          <small v-if="selected">
            {{ providerLabel(selected.provider) }}
            · {{ projectName(selected.projectId) }}
            · {{ formatTime(selected.createdAt) }}
          </small>
        </div>
        <button
          v-if="selected && selected.results.length"
          class="button compact intel-import-button"
          type="button"
          :disabled="!canWrite || importing || !selectedProjectID"
          @click="importAssets"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />
          </svg>
          {{ importing ? t('intel.importing') : t('intel.importAssets') }}
        </button>
      </header>
      <div v-if="loadingDetail" class="intel-panel-state">
        <span class="intel-scan-state"><i></i><i></i><i></i></span>
        {{ t('common.loading') }}
      </div>
      <div v-else-if="!selected" class="intel-empty-state">
        <span class="intel-empty-radar">
          <i></i>
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="8" />
            <circle cx="12" cy="12" r="3" />
            <path d="M12 4v2M20 12h-2" />
          </svg>
        </span>
        <strong>{{ t('intel.selectHistory') }}</strong>
        <small>{{ t('intel.emptyHint') }}</small>
      </div>
      <div v-else class="intel-result-content">
        <div v-if="selected.providerErrors.length" class="intel-provider-errors">
          <span v-for="item in selected.providerErrors" :key="item">{{ item }}</span>
        </div>
        <div class="intel-result-table-wrap">
          <table class="intel-result-table">
            <thead>
              <tr>
                <th>{{ t('intel.source') }}</th>
                <th>{{ t('intel.target') }}</th>
                <th>{{ t('intel.titleColumn') }}</th>
                <th>{{ t('intel.fingerprint') }}</th>
                <th>{{ t('intel.organization') }}</th>
                <th>{{ t('common.updatedAt') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(item, index) in pagedResults"
                :key="`${resultTarget(item)}-${resultPagination.page}-${index}`"
              >
                <td><span class="intel-source-badge">{{ resultSources(item) }}</span></td>
                <td>
                  <div class="intel-target-cell">
                    <code :title="resultTarget(item)">{{ resultTarget(item) }}</code>
                    <small>{{ item.protocol || item.location || '-' }}</small>
                  </div>
                </td>
                <td :title="item.title">{{ item.title || '-' }}</td>
                <td :title="item.components?.join(', ')">{{ item.components?.join(', ') || item.server || '-' }}</td>
                <td :title="item.org || item.location">{{ item.org || item.location || '-' }}</td>
                <td>{{ item.updatedAt || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <DataPagination
          v-if="selected && resultPagination.total > 0"
          :total="resultPagination.total"
          :page="resultPagination.page"
          :page-size="resultPagination.pageSize"
          :total-pages="resultPagination.totalPages"
          @page-change="changeResultPage"
          @page-size-change="changeResultPageSize"
        />
      </div>
    </section>
  </section>
</template>

<style scoped>
.intel-collection-page {
  --intel-cyan: #55c7e8;
  --intel-pink: #f472b6;
  --intel-green: #34d399;
  --intel-amber: #f0a43a;
  --intel-red: #fb7185;
  display: grid;
  gap: 10px;
}

.intel-page-hint {
  max-width: 760px;
  margin: 5px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.intel-collection-header svg,
.intel-result-table svg,
.intel-fofa-search-button svg,
.intel-import-button svg {
  width: 16px;
  height: 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.intel-stat-rail {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.intel-stat-card {
  position: relative;
  display: grid;
  min-width: 0;
  min-height: 82px;
  grid-template-columns: 34px minmax(0, 1fr);
  gap: 10px;
  align-items: center;
  overflow: hidden;
  padding: 11px 12px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
}

.intel-stat-card::before {
  position: absolute;
  top: 0;
  right: 0;
  left: 0;
  height: 2px;
  content: "";
  background: var(--intel-card-tone, var(--intel-cyan));
}

.intel-stat-card::after {
  position: absolute;
  right: 10px;
  bottom: 6px;
  width: 34px;
  height: 2px;
  content: "";
  background: repeating-linear-gradient(
    90deg,
    color-mix(in srgb, var(--intel-card-tone, var(--intel-cyan)) 60%, transparent) 0 5px,
    transparent 5px 9px
  );
}

.intel-stat-card.tone-log {
  --intel-card-tone: var(--intel-cyan);
}

.intel-stat-card.tone-result {
  --intel-card-tone: var(--intel-pink);
}

.intel-stat-card.tone-online {
  --intel-card-tone: var(--intel-green);
}

.intel-stat-card.tone-offline {
  --intel-card-tone: var(--intel-red);
}

.intel-stat-card > div {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.intel-stat-card small,
.intel-stat-card em {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  font-style: normal;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-stat-card small {
  font-family: var(--mono);
  letter-spacing: 0.04em;
}

.intel-stat-card strong {
  overflow: hidden;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 20px;
  font-weight: 500;
  line-height: 1.1;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-stat-card.tone-online strong {
  color: var(--intel-green);
  font-size: 13px;
}

.intel-stat-card.tone-offline strong {
  color: var(--intel-red);
  font-size: 13px;
}

.intel-stat-icon {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--intel-card-tone, var(--intel-cyan)) 32%, var(--border));
  border-radius: 4px;
  color: var(--intel-card-tone, var(--intel-cyan));
  background: color-mix(in srgb, var(--intel-card-tone, var(--intel-cyan)) 8%, var(--field-bg));
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 800;
}

.intel-stat-icon svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.intel-command-console,
.intel-history-console,
.intel-results-console {
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 5px;
  background: var(--surface);
}

.intel-command-console {
  position: relative;
}

.intel-command-console::before {
  position: absolute;
  top: 0;
  bottom: 0;
  left: 0;
  width: 2px;
  content: "";
  background: var(--intel-cyan);
}

.intel-console-head,
.intel-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 72%, transparent);
}

.intel-console-head > div:first-child,
.intel-section-head > div {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.intel-console-head span,
.intel-section-head span {
  color: var(--intel-cyan);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.06em;
}

.intel-console-head strong,
.intel-section-head strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-provider-switch {
  display: inline-flex;
  flex: 0 0 auto;
  padding: 3px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--field-bg);
}

.intel-provider-switch button {
  min-width: 80px;
  min-height: 28px;
  padding: 5px 11px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-muted);
  background: transparent;
  font-family: var(--mono);
  font-size: 9px;
}

.intel-provider-switch button.active {
  border-color: color-mix(in srgb, var(--intel-cyan) 38%, var(--border));
  color: var(--intel-cyan);
  background: color-mix(in srgb, var(--intel-cyan) 10%, var(--surface));
  box-shadow: inset 0 -2px 0 color-mix(in srgb, var(--intel-cyan) 65%, transparent);
}

.intel-fofa-query-wrap {
  display: grid;
  min-width: 0;
  gap: 9px;
  padding: 12px;
}

.intel-fofa-query-box {
  position: relative;
  min-width: 0;
  min-height: 48px;
  overflow: hidden;
  border: 1px solid transparent;
  border-radius: 8px;
  background:
    linear-gradient(var(--field-bg), var(--field-bg)) padding-box,
    linear-gradient(
        96deg,
        color-mix(in srgb, var(--intel-cyan) 60%, #4674dd),
        color-mix(in srgb, var(--intel-cyan) 52%, transparent)
      )
      border-box;
  transition:
    min-height 0.18s ease,
    box-shadow 0.18s ease;
}

.intel-fofa-query-box.expanded {
  min-height: 132px;
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--intel-cyan) 10%, transparent);
}

.intel-fofa-query-input {
  width: 100%;
  height: 48px;
  padding: 11px 185px 11px 15px;
  overflow: hidden;
  border: 0;
  outline: 0;
  color: var(--text-primary);
  background: transparent;
  font-family: var(--mono);
  font-size: 14px;
  line-height: 1.65;
  resize: none;
  white-space: nowrap;
}

.intel-fofa-query-input::placeholder {
  color: color-mix(in srgb, var(--text-muted) 82%, transparent);
}

.intel-fofa-query-box.expanded .intel-fofa-query-input {
  height: 132px;
  padding: 12px 15px 44px;
  overflow: auto;
  white-space: pre-wrap;
}

.intel-fofa-query-suffix {
  position: absolute;
  top: 50%;
  right: 10px;
  display: flex;
  align-items: center;
  gap: 9px;
  transform: translateY(-50%);
}

.intel-fofa-query-box.expanded .intel-fofa-query-suffix {
  top: auto;
  bottom: 8px;
  transform: none;
}

.intel-fofa-sensor-state {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  white-space: nowrap;
}

.intel-fofa-sensor-state i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--intel-red);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--intel-red) 16%, transparent);
}

.intel-fofa-sensor-state.ready i {
  background: var(--intel-green);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--intel-green) 16%, transparent);
}

.intel-fofa-search-button {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 auto;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--intel-cyan) 48%, var(--border));
  border-radius: 50%;
  color: #102025;
  background: var(--intel-cyan);
}

.intel-fofa-search-button:hover:not(:disabled) {
  background: color-mix(in srgb, white 18%, var(--intel-cyan));
}

.intel-fofa-search-button:disabled {
  border-color: var(--border);
  color: var(--text-muted);
  background: var(--field-bg);
  opacity: 0.6;
}

.intel-fofa-search-button svg {
  width: 18px;
  height: 18px;
}

.intel-search-spinner {
  width: 13px;
  height: 13px;
  border: 2px solid rgba(16, 32, 37, 0.25);
  border-top-color: #102025;
  border-radius: 50%;
  animation: intel-search-spin 0.8s linear infinite;
}

.intel-fofa-options {
  display: grid;
  grid-template-columns: minmax(190px, 1.45fr) repeat(3, minmax(105px, 0.55fr));
  gap: 8px;
}

.intel-fofa-options label {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.intel-fofa-options label > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.intel-fofa-options input,
.intel-fofa-options select {
  width: 100%;
  min-height: 32px;
  padding: 5px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-primary);
  background: var(--field-bg);
  font-size: 10px;
}

.intel-section-head em {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  font-style: normal;
}

.intel-history-console {
  display: grid;
  gap: 0;
}

.intel-history-tape {
  display: grid;
  grid-auto-columns: minmax(235px, 330px);
  grid-auto-flow: column;
  gap: 7px;
  overflow-x: auto;
  padding: 9px;
  scrollbar-width: thin;
}

.intel-history-card {
  position: relative;
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  border-left: 2px solid color-mix(in srgb, var(--intel-pink) 45%, var(--border));
  border-radius: 4px;
  background: var(--field-bg);
}

.intel-history-select {
  display: grid;
  width: 100%;
  min-width: 0;
  gap: 5px;
  padding: 9px 34px 9px 10px;
  border: 0;
  color: var(--text-secondary);
  background: transparent;
  text-align: left;
}

.intel-history-card:hover,
.intel-history-card.active {
  border-color: color-mix(in srgb, var(--intel-pink) 42%, var(--border));
  border-left-color: var(--intel-pink);
  background: color-mix(in srgb, var(--intel-pink) 8%, var(--field-bg));
}

.intel-history-card.active {
  box-shadow: inset 3px 0 0 color-mix(in srgb, var(--intel-pink) 55%, transparent);
}

.intel-history-delete {
  position: absolute;
  top: 6px;
  right: 6px;
  display: grid;
  width: 24px;
  height: 24px;
  place-items: center;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-muted);
  background: transparent;
}

.intel-history-delete:hover:not(:disabled) {
  border-color: color-mix(in srgb, var(--intel-red) 35%, var(--border));
  color: var(--intel-red);
  background: color-mix(in srgb, var(--intel-red) 9%, transparent);
}

.intel-history-delete:disabled {
  opacity: 0.45;
}

.intel-history-delete svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.intel-history-tape strong,
.intel-history-tape small,
.intel-history-tape em,
.intel-history-project {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-history-tape strong {
  padding-right: 20px;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 10px;
}

.intel-history-select > div {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.intel-history-tape small,
.intel-history-tape em,
.intel-history-project {
  color: var(--text-muted);
  font-size: 8px;
  font-style: normal;
}

.intel-history-source,
.intel-source-badge {
  width: fit-content;
  padding: 2px 5px;
  border: 1px solid color-mix(in srgb, var(--intel-pink) 34%, var(--border));
  border-radius: 3px;
  color: var(--intel-pink);
  background: color-mix(in srgb, var(--intel-pink) 7%, transparent);
  font-family: var(--mono);
  font-size: 8px;
}

.intel-history-project {
  color: color-mix(in srgb, var(--text-muted) 76%, transparent);
}

.intel-results-console {
  display: grid;
  min-height: 340px;
  align-content: start;
}

.result-head {
  align-items: flex-start;
}

.result-head > div {
  flex: 1;
}

.result-head small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-import-button {
  flex: 0 0 auto;
}

.intel-panel-state {
  display: grid;
  min-height: 220px;
  place-items: center;
  color: var(--text-muted);
  font-size: 10px;
}

.intel-panel-state.compact {
  min-height: 70px;
}

.intel-scan-state {
  display: inline-flex;
  gap: 4px;
}

.intel-scan-state i {
  width: 5px;
  height: 14px;
  background: var(--intel-cyan);
  animation: intel-scan 1.1s ease-in-out infinite;
}

.intel-scan-state i:nth-child(2) {
  animation-delay: 0.15s;
}

.intel-scan-state i:nth-child(3) {
  animation-delay: 0.3s;
}

.intel-empty-state {
  display: grid;
  min-height: 260px;
  place-items: center;
  align-content: center;
  gap: 8px;
  padding: 24px;
  text-align: center;
}

.intel-empty-state strong {
  color: var(--text-primary);
  font-size: 13px;
}

.intel-empty-state small {
  max-width: 440px;
  color: var(--text-muted);
  font-size: 9px;
  line-height: 1.55;
}

.intel-empty-radar {
  position: relative;
  display: grid;
  width: 54px;
  height: 54px;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--intel-cyan) 28%, var(--border));
  border-radius: 50%;
  color: var(--intel-cyan);
  background: color-mix(in srgb, var(--intel-cyan) 5%, var(--field-bg));
}

.intel-empty-radar i {
  position: absolute;
  inset: 7px;
  border-top: 1px solid var(--intel-cyan);
  border-radius: 50%;
  animation: intel-radar 3.2s linear infinite;
}

.intel-empty-radar svg {
  width: 24px;
  height: 24px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.4;
}

.intel-result-content {
  display: grid;
  min-width: 0;
}

.intel-provider-errors {
  display: grid;
  gap: 4px;
  margin: 8px;
  padding: 7px 9px;
  border-left: 2px solid var(--intel-amber);
  color: var(--intel-amber);
  background: color-mix(in srgb, var(--intel-amber) 8%, var(--field-bg));
  font-size: 9px;
}

.intel-result-table-wrap {
  min-width: 0;
  overflow: auto;
}

.intel-result-table {
  width: 100%;
  min-width: 980px;
  border-spacing: 0;
  border-collapse: separate;
}

.intel-result-table th,
.intel-result-table td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
}

.intel-result-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  color: var(--text-muted);
  background: color-mix(in srgb, var(--field-bg) 88%, var(--intel-cyan));
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
}

.intel-result-table tbody tr:hover td {
  background: color-mix(in srgb, var(--intel-cyan) 5%, transparent);
}

.intel-result-table td {
  max-width: 250px;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intel-target-cell {
  display: grid;
  gap: 2px;
}

.intel-target-cell code {
  overflow: hidden;
  color: var(--intel-cyan);
  font-family: var(--mono);
  font-size: 10px;
  text-overflow: ellipsis;
}

.intel-target-cell small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

@keyframes intel-scan {
  0%,
  100% {
    opacity: 0.28;
    transform: scaleY(0.5);
  }
  50% {
    opacity: 1;
    transform: scaleY(1);
  }
}

@keyframes intel-radar {
  to {
    transform: rotate(360deg);
  }
}

@keyframes intel-search-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 860px) {
  .intel-stat-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .intel-fofa-options {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 620px) {
  .intel-stat-rail,
  .intel-fofa-options {
    grid-template-columns: minmax(0, 1fr);
  }

  .intel-console-head,
  .intel-section-head {
    align-items: stretch;
    flex-direction: column;
  }

  .intel-provider-switch {
    display: grid;
    width: 100%;
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .intel-provider-switch button {
    min-width: 0;
  }

  .intel-history-tape {
    grid-auto-columns: minmax(220px, 84vw);
  }

  .intel-fofa-query-input {
    padding-right: 52px;
    font-size: 12px;
  }

  .intel-fofa-query-box.expanded .intel-fofa-query-input {
    padding-right: 15px;
  }

  .intel-fofa-sensor-state {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .intel-scan-state i,
  .intel-empty-radar i {
    animation: none;
  }
}
</style>
