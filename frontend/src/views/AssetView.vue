<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()

interface Asset {
  id: string
  projectId: string
  ownerUserId?: string
  name: string
  kind: string
  value: string
  status: string
  criticality: string
  riskScore: number
  createdAt: string
  updatedAt: string
}

interface Project {
  id: string
  name: string
}

interface AssetDraft {
  id: string
  projectId: string
  name: string
  kind: string
  value: string
  status: string
  criticality: string
  riskScore: number
  createdAt?: string
  updatedAt?: string
}

const STATUS_OPTIONS = [
  { value: 'unknown', label: t('assetStatus.unknown') },
  { value: 'active', label: t('assetStatus.active') },
  { value: 'inactive', label: t('assetStatus.inactive') },
  { value: 'retired', label: t('assetStatus.retired') },
]

const CRITICALITY_OPTIONS = [
  { value: 'critical', label: t('assetCriticality.critical') },
  { value: 'high', label: t('assetCriticality.high') },
  { value: 'medium', label: t('assetCriticality.medium') },
  { value: 'low', label: t('assetCriticality.low') },
  { value: 'info', label: t('assetCriticality.info') },
]

const KNOWN_KINDS = ['domain', 'ip', 'url', 'port', 'host']

const assets = ref<Asset[]>([])
const projects = ref<Project[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')
const draft = ref<AssetDraft | null>(null)
const editingId = ref('')
const deleteTarget = ref<Asset | null>(null)
const deleting = ref(false)
const copiedId = ref('')
let copyTimer: number | undefined

const filters = reactive({
  search: '',
  projectId: '',
  kind: '',
  status: '',
})

const pagination = reactive({
  page: 1,
  pageSize: 20,
  total: 0,
  totalPages: 1,
})

const canWrite = computed(() => auth.hasPermission('asset:write'))
const canDelete = computed(() => auth.hasPermission('asset:delete'))
const activeCount = computed(() => assets.value.filter((asset) => asset.status === 'active').length)
const highRiskCount = computed(
  () =>
    assets.value.filter(
      (asset) => asset.criticality === 'critical' || asset.criticality === 'high',
    ).length,
)
const unlinkedCount = computed(() => assets.value.filter((asset) => !asset.projectId).length)
const averageRisk = computed(() => {
  if (!assets.value.length) {
    return 0
  }
  return Math.round(
    assets.value.reduce((sum, asset) => sum + asset.riskScore, 0) / assets.value.length,
  )
})

function statusLabel(value: string) {
  return STATUS_OPTIONS.find((option) => option.value === value)?.label ?? value
}

function criticalityLabel(value: string) {
  return CRITICALITY_OPTIONS.find((option) => option.value === value)?.label ?? value
}

function kindLabel(value: string) {
  const key = `assetKind.${value}`
  const label = t(key)
  return label === key ? value : label
}

function projectName(projectId: string) {
  if (!projectId) {
    return t('asset.unlinked')
  }
  return projects.value.find((project) => project.id === projectId)?.name ?? projectId
}

function kindTone(kind: string) {
  switch (kind) {
    case 'domain':
      return 'cyan'
    case 'ip':
      return 'violet'
    case 'url':
      return 'mint'
    case 'port':
      return 'coral'
    case 'host':
      return 'blue'
    default:
      return 'muted'
  }
}

function riskTone(score: number) {
  if (score >= 85) {
    return 'critical'
  }
  if (score >= 65) {
    return 'high'
  }
  if (score >= 40) {
    return 'medium'
  }
  if (score > 0) {
    return 'low'
  }
  return 'info'
}

function selectKind(kind: string) {
  filters.kind = kind
  void load(true)
}

function formatTime(value: string) {
  if (!value) {
    return '-'
  }
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

async function load(resetPage = false) {
  if (resetPage) {
    pagination.page = 1
  }
  loading.value = true
  error.value = ''
  try {
    const query = new URLSearchParams({
      limit: String(pagination.pageSize),
      offset: String((pagination.page - 1) * pagination.pageSize),
    })
    if (filters.search.trim()) {
      query.set('search', filters.search.trim())
    }
    if (filters.projectId) {
      query.set('projectId', filters.projectId)
    }
    if (filters.kind) {
      query.set('kind', filters.kind)
    }
    if (filters.status) {
      query.set('status', filters.status)
    }
    const response = await apiGet<{ items: Asset[]; total: number }>(
      `/assets?${query.toString()}`,
    )
    const totalPages = Math.max(1, Math.ceil((response.total ?? 0) / pagination.pageSize))
    if (pagination.page > totalPages) {
      pagination.page = totalPages
      return await load()
    }
    assets.value = response.items ?? []
    pagination.total = response.total ?? 0
    pagination.totalPages = totalPages
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('asset.loadFailed')
  } finally {
    loading.value = false
  }
}

async function loadProjects() {
  try {
    const loaded: Project[] = []
    let cursor = ''
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

async function run(action: () => Promise<void>, successText = '') {
  error.value = ''
  notice.value = ''
  try {
    await action()
    if (successText) {
      notice.value = successText
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  }
}

function resetFilters() {
  filters.search = ''
  filters.projectId = ''
  filters.kind = ''
  filters.status = ''
  void load(true)
}

function openCreate() {
  editingId.value = ''
  draft.value = {
    id: '',
    projectId: filters.projectId,
    name: '',
    kind: 'domain',
    value: '',
    status: 'unknown',
    criticality: 'medium',
    riskScore: 0,
  }
}

function openEdit(asset: Asset) {
  editingId.value = asset.id
  draft.value = {
    id: asset.id,
    projectId: asset.projectId,
    name: asset.name,
    kind: asset.kind,
    value: asset.value,
    status: asset.status,
    criticality: asset.criticality,
    riskScore: asset.riskScore,
  }
}

function closeDraft() {
  draft.value = null
  editingId.value = ''
}

function saveDraft() {
  const current = draft.value
  if (!current) {
    return
  }
  const name = current.name.trim()
  const kind = current.kind.trim().toLowerCase()
  const value = current.value.trim()
  if (!name || !value) {
    error.value = t('asset.nameValueRequired')
    return
  }
  if (!KNOWN_KINDS.includes(kind)) {
    error.value = t('asset.kindRequired')
    return
  }
  const riskScore = Number(current.riskScore)
  if (!Number.isFinite(riskScore) || riskScore < 0 || riskScore > 100) {
    error.value = t('asset.riskRange')
    return
  }
  const isEdit = editingId.value !== ''
  void run(async () => {
    const payload = {
      projectId: current.projectId,
      name,
      kind,
      value,
      status: current.status || 'unknown',
      criticality: current.criticality || 'medium',
      riskScore,
    }
    if (isEdit) {
      await apiPut(`/assets/${editingId.value}`, payload)
    } else {
      await apiPost('/assets', payload)
    }
    closeDraft()
    await load(!isEdit)
  }, isEdit ? t('asset.updated') : t('asset.created'))
}

async function copyAssetValue(asset: Asset) {
  let copied = false
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(asset.value)
      copied = true
    }
  } catch {
    copied = false
  }
  if (!copied) {
    const textarea = document.createElement('textarea')
    textarea.value = asset.value
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    copied = document.execCommand('copy')
    textarea.remove()
  }
  if (copied) {
    copiedId.value = asset.id
    if (copyTimer) {
      window.clearTimeout(copyTimer)
    }
    copyTimer = window.setTimeout(() => {
      copiedId.value = ''
    }, 1800)
    notice.value = t('asset.copied')
  } else {
    error.value = t('asset.copyFailed')
  }
}

function requestDelete(asset: Asset) {
  if (canDelete.value) {
    deleteTarget.value = asset
  }
}

function closeDeleteDialog() {
  if (!deleting.value) {
    deleteTarget.value = null
  }
}

async function confirmDelete() {
  const asset = deleteTarget.value
  if (!asset || !canDelete.value || deleting.value) {
    return
  }
  deleting.value = true
  error.value = ''
  notice.value = ''
  try {
    await apiDelete(`/assets/${asset.id}`)
    deleteTarget.value = null
    notice.value = t('asset.deleted')
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
    deleteTarget.value = null
  } finally {
    deleting.value = false
  }
}

function applyFilters() {
  void load(true)
}

function goPage(offset: number) {
  const next = pagination.page + offset
  if (next < 1 || next > pagination.totalPages) {
    return
  }
  pagination.page = next
  void load()
}

onMounted(() => {
  void Promise.all([load(), loadProjects()])
})

onUnmounted(() => {
  if (copyTimer) {
    window.clearTimeout(copyTimer)
  }
})
</script>

<template>
  <section class="page asset-page factory-page page-assets asset-recon">
    <header class="page-header asset-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="coral" />
        <div>
          <p class="eyebrow">ASSET MANAGEMENT</p>
          <h1>{{ t('nav.assets') }}</h1>
          <p class="asset-page-hint">{{ t('asset.reconHint') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load()">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
          {{ t('common.refresh') }}
        </button>
        <button v-if="canWrite" class="button asset-primary" type="button" @click="openCreate">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          {{ t('asset.create') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error asset-alert">{{ error }}</div>
    <div v-if="notice" class="alert ok asset-alert">{{ notice }}</div>

    <div class="asset-stat-row">
      <article class="asset-stat-card">
        <small>
          <svg class="asset-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m4 8 8-4 8 4-8 4-8-4Z" />
            <path d="m4 12 8 4 8-4M4 16l8 4 8-4" />
          </svg>
          {{ t('nav.assets') }}
        </small>
        <strong>{{ pagination.total }}</strong>
      </article>
      <article class="asset-stat-card tone-active">
        <small>
          <svg class="asset-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="5" width="13" height="9" rx="2" />
            <path d="M7 9h.01M11 9h5" />
            <path d="M14 19a5 5 0 0 0 5-5" />
            <path d="m17 16 2-2 2 2" />
          </svg>
          {{ t('asset.activeAssets') }}
        </small>
        <strong>{{ activeCount }}</strong>
      </article>
      <article class="asset-stat-card tone-risk">
        <small>
          <svg class="asset-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m12 3 7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z" />
            <path d="M12 8v4M12 16h.01" />
          </svg>
          {{ t('asset.highRiskAssets') }}
        </small>
        <strong>{{ highRiskCount }}</strong>
      </article>
      <article class="asset-stat-card tone-unlinked">
        <small>
          <svg class="asset-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M10 13a4 4 0 0 0 5.66 0l2-2a4 4 0 0 0-5.66-5.66l-1 1" />
            <path d="M14 11a4 4 0 0 0-5.66 0l-2 2a4 4 0 0 0 5.66 5.66l1-1" />
            <path d="m4 4 16 16" />
          </svg>
          {{ t('asset.unlinkedAssets') }}
        </small>
        <strong>{{ unlinkedCount }}</strong>
      </article>
      <article class="asset-stat-card tone-average">
        <small>
          <svg class="asset-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 18a8 8 0 1 1 16 0" />
            <path d="m12 18 4-5" />
            <path d="M7 18h10" />
          </svg>
          {{ t('asset.averageRisk') }}
        </small>
        <strong>{{ averageRisk }}</strong>
      </article>
    </div>

    <section class="asset-filter-console">
      <div class="asset-filter-main">
        <label class="asset-search-box">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg>
          <input v-model="filters.search" type="search" :placeholder="t('asset.searchPlaceholder')" @keyup.enter="applyFilters" />
        </label>
        <select
          v-model="filters.projectId"
          :aria-label="t('asset.project')"
          @change="applyFilters"
        >
          <option value="">{{ t('asset.allProjects') }}</option>
          <option v-for="project in projects" :key="project.id" :value="project.id">{{ project.name }}</option>
        </select>
        <select v-model="filters.status" :aria-label="t('common.status')" @change="applyFilters">
          <option value="">{{ t('asset.allStatus') }}</option>
          <option v-for="option in STATUS_OPTIONS" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select>
        <select v-model="filters.kind" :aria-label="t('asset.allKinds')" @change="applyFilters">
          <option value="">{{ t('asset.allKinds') }}</option>
          <option v-for="kind in KNOWN_KINDS" :key="kind" :value="kind">{{ kindLabel(kind) }}</option>
        </select>
        <button class="button" type="button" @click="applyFilters">{{ t('common.query') }}</button>
        <button class="button compact" type="button" @click="resetFilters">{{ t('common.reset') }}</button>
      </div>
      <div class="asset-kind-track">
        <button type="button" :class="{ active: filters.kind === '' }" @click="selectKind('')">
          <span class="asset-kind-glyph tone-all"><i></i></span>
          <b>{{ t('asset.allKinds') }}</b>
          <small>{{ pagination.total }}</small>
        </button>
        <button v-for="kind in KNOWN_KINDS" :key="kind" type="button" :class="{ active: filters.kind === kind }" @click="selectKind(kind)">
          <span class="asset-kind-glyph" :class="`tone-${kindTone(kind)}`">
            <svg v-if="kind === 'domain'" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" /></svg>
            <svg v-else-if="kind === 'ip'" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M7 9h.01M7 15h.01M11 9h6M11 12h6M11 15h4" /></svg>
            <svg v-else-if="kind === 'url'" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2" /></svg>
            <svg v-else-if="kind === 'port'" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" /><path d="M12 4v8l5 3" /></svg>
            <svg v-else-if="kind === 'host'" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></svg>
            <svg v-else viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" /><path d="M9 12h6" /></svg>
          </span>
          <b>{{ kindLabel(kind) }}</b>
        </button>
      </div>
    </section>

    <section class="asset-table-section">
      <div v-if="loading && !assets.length" class="asset-loading"><i></i><i></i><i></i><span>{{ t('common.loading') }}</span></div>
      <div v-else-if="!assets.length" class="asset-empty"><span class="asset-empty-robot" aria-hidden="true"><i></i><b></b><b></b></span><strong>{{ t('asset.empty') }}</strong></div>
      <div v-else class="asset-table-wrap">
        <table class="asset-table">
          <thead>
            <tr>
              <th>{{ t('project.assetName') }}</th>
              <th>{{ t('project.assetKind') }}</th>
              <th>{{ t('project.assetValue') }}</th>
              <th>{{ t('asset.project') }}</th>
              <th>{{ t('common.status') }}</th>
              <th>{{ t('project.assetCriticality') }}</th>
              <th>{{ t('project.assetRisk') }}</th>
              <th>{{ t('common.updatedAt') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="asset in assets" :key="asset.id" :class="`risk-${riskTone(asset.riskScore)}`">
              <td>
                <button class="asset-name-cell" type="button" :disabled="!canWrite" @click="openEdit(asset)">
                  <span class="asset-kind-glyph compact" :class="`tone-${kindTone(asset.kind)}`">
                    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" /><path d="M8 12h8M12 8v8" /></svg>
                  </span>
                  <span><strong>{{ asset.name }}</strong><small>{{ asset.id.slice(0, 10) }}</small></span>
                </button>
              </td>
              <td><span class="asset-kind-badge" :class="`tone-${kindTone(asset.kind)}`">{{ kindLabel(asset.kind) }}</span></td>
              <td>
                <div class="asset-value-cell">
                  <code :title="asset.value">{{ asset.value }}</code>
                  <button type="button" :title="t('asset.copyValue')" @click="copyAssetValue(asset)">
                    <svg v-if="copiedId !== asset.id" viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2" /><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" /></svg>
                    <svg v-else viewBox="0 0 24 24"><path d="m5 12 4 4L19 6" /></svg>
                  </button>
                </div>
              </td>
              <td><span class="asset-project-badge">{{ projectName(asset.projectId) }}</span></td>
              <td><span class="asset-state" :class="`tone-${asset.status}`"><i></i>{{ statusLabel(asset.status) }}</span></td>
              <td><span class="asset-criticality" :class="`tone-${asset.criticality}`">{{ criticalityLabel(asset.criticality) }}</span></td>
              <td>
                <div class="asset-risk" :class="`tone-${riskTone(asset.riskScore)}`">
                  <strong>{{ asset.riskScore }}</strong>
                  <span><i :style="{ width: `${Math.max(0, Math.min(100, asset.riskScore))}%` }"></i></span>
                </div>
              </td>
              <td class="asset-time">{{ formatTime(asset.updatedAt) }}</td>
              <td>
                <div class="asset-row-actions">
                  <button v-if="canWrite" class="button compact" type="button" @click="openEdit(asset)">
                    {{ t('common.edit') }}
                  </button>
                  <button v-if="canDelete" class="button compact danger" type="button" @click="requestDelete(asset)">
                    {{ t('common.delete') }}
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <footer class="asset-pagination">
        <span>{{ t('asset.pagination', { total: pagination.total, page: pagination.page, totalPages: pagination.totalPages }) }}</span>
        <div>
          <button class="button compact" type="button" :disabled="pagination.page <= 1" @click="goPage(-1)">{{ t('asset.prev') }}</button>
          <button class="button compact" type="button" :disabled="pagination.page >= pagination.totalPages" @click="goPage(1)">{{ t('asset.next') }}</button>
        </div>
      </footer>
    </section>

    <Teleport to="body">
      <div v-if="draft" class="asset-drawer-layer" @click.self="closeDraft">
        <aside class="asset-drawer" role="dialog" aria-modal="true">
          <header class="asset-drawer-head">
            <div><span class="asset-code">ASSET REGISTRY</span><h2>{{ editingId ? t('asset.edit') : t('asset.create') }}</h2></div>
            <button type="button" @click="closeDraft"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></svg></button>
          </header>
          <div class="asset-drawer-body">
            <section class="asset-form-section">
              <span>01</span>
              <div>
                <h3>{{ t('project.assetName') }}</h3>
                <label><b>{{ t('project.assetName') }}</b><input v-model="draft.name" :placeholder="t('asset.namePlaceholder')" /></label>
                <div class="drawer-grid">
                  <label>
                    <b>{{ t('project.assetKind') }}</b>
                    <select v-model="draft.kind" :aria-label="t('project.assetKind')">
                      <option v-for="kind in KNOWN_KINDS" :key="kind" :value="kind">{{ kindLabel(kind) }}</option>
                      <option v-if="draft.kind && !KNOWN_KINDS.includes(draft.kind)" :value="draft.kind" disabled>
                        {{ kindLabel(draft.kind) }} · {{ t('asset.legacyKind') }}
                      </option>
                    </select>
                  </label>
                  <label><b>{{ t('asset.project') }}</b><select v-model="draft.projectId"><option value="">{{ t('asset.unlinked') }}</option><option v-for="project in projects" :key="project.id" :value="project.id">{{ project.name }}</option></select></label>
                </div>
                <label><b>{{ t('project.assetValue') }}</b><input v-model="draft.value" :placeholder="t('asset.valuePlaceholder')" /></label>
              </div>
            </section>
            <section class="asset-form-section">
              <span>02</span>
              <div>
                <h3>{{ t('project.assetRisk') }}</h3>
                <div class="drawer-grid">
                  <label><b>{{ t('common.status') }}</b><select v-model="draft.status"><option v-for="option in STATUS_OPTIONS" :key="option.value" :value="option.value">{{ option.label }}</option></select></label>
                  <label><b>{{ t('project.assetCriticality') }}</b><select v-model="draft.criticality"><option v-for="option in CRITICALITY_OPTIONS" :key="option.value" :value="option.value">{{ option.label }}</option></select></label>
                </div>
                <label class="asset-risk-input">
                  <b>{{ t('project.assetRisk') }}</b>
                  <div>
                    <input v-model.number="draft.riskScore" type="range" min="0" max="100" />
                    <input v-model.number="draft.riskScore" type="number" min="0" max="100" />
                  </div>
                </label>
              </div>
            </section>
          </div>
          <footer class="asset-drawer-foot">
            <button class="button compact" type="button" @click="closeDraft">{{ t('common.cancel') }}</button>
            <button class="button asset-primary" type="button" @click="saveDraft">{{ t('common.save') }}</button>
          </footer>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="deleteTarget" class="asset-dialog-layer" @click.self="closeDeleteDialog">
        <aside class="asset-dialog" role="dialog" aria-modal="true">
          <header><span class="asset-warning" aria-hidden="true">!</span><div><span class="asset-code">ASSET REMOVAL</span><h2>{{ t('asset.deleteTitle') }}</h2></div></header>
          <p>{{ t('asset.deleteHint', { name: deleteTarget.name }) }}</p>
          <div class="asset-dialog-value"><span>{{ kindLabel(deleteTarget.kind) }}</span><code>{{ deleteTarget.value }}</code></div>
          <footer>
            <button class="button compact" type="button" :disabled="deleting" @click="closeDeleteDialog">{{ t('common.cancel') }}</button>
            <button class="button compact danger" type="button" :disabled="deleting" @click="confirmDelete">{{ deleting ? t('common.loading') : t('asset.deletePermanently') }}</button>
          </footer>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.asset-counter {
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 12px;
}

.asset-filter-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  padding: 10px;
  border: 1px solid var(--line);
  background: var(--surface);
  box-shadow: none;
}

.asset-filter-bar input,
.asset-filter-bar select {
  padding: 9px 10px;
}

.asset-filter-bar input {
  flex: 2 1 240px;
}

.asset-filter-bar select {
  flex: 1 1 150px;
}

.asset-filter-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

.asset-table-wrap {
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.asset-table {
  width: 100%;
  min-width: 1040px;
  border-collapse: collapse;
}

.asset-table th,
.asset-table td {
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 13px;
  vertical-align: middle;
}

.asset-table th {
  color: var(--text-secondary);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.asset-table tbody tr:last-child td {
  border-bottom: 0;
}

.asset-table tbody tr:hover {
  background: var(--surface-soft);
}

.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
  color: var(--text-muted);
  font-size: 13px;
}

.pagination-actions {
  display: flex;
  gap: 8px;
}

.kind-badge,
.status-badge,
.criticality-badge {
  display: inline-block;
  padding: 3px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--field-bg);
  font-size: 12px;
  white-space: nowrap;
}

.status-badge.tone-active {
  border-color: var(--success);
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.status-badge.tone-inactive,
.status-badge.tone-retired {
  color: var(--text-muted);
}

.criticality-badge.tone-critical {
  border-color: var(--danger);
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.criticality-badge.tone-high {
  border-color: #ffab00;
  color: #ffab00;
  background: color-mix(in srgb, #ffab00 10%, var(--surface));
}

.criticality-badge.tone-medium {
  border-color: var(--warning);
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.criticality-badge.tone-low {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-soft);
}

.link-button {
  padding: 0;
  border: 0;
  color: var(--accent);
  background: transparent;
  font-weight: 700;
  text-align: left;
  cursor: pointer;
}

.cell-value,
.cell-time {
  max-width: 220px;
  overflow: hidden;
  color: var(--text-secondary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.risk-cell {
  display: grid;
  grid-template-columns: 28px 54px;
  align-items: center;
  gap: 7px;
}

.risk-cell strong {
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 12px;
  text-align: right;
}

.risk-track {
  display: block;
  height: 5px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.risk-track i {
  display: block;
  height: 100%;
  border-radius: var(--radius);
  background: var(--accent);
}

.row-actions {
  display: flex;
  gap: 6px;
  white-space: nowrap;
}

.empty-cell {
  padding: 30px 12px;
  color: var(--text-muted);
  text-align: center;
}

.editor-drawer {
  position: fixed;
  top: 0;
  right: 0;
  z-index: 20;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(560px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
}

.drawer-header,
.drawer-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.drawer-footer {
  justify-content: flex-end;
  border-top: 1px solid var(--line);
  border-bottom: 0;
}

.drawer-header h2 {
  margin: 0;
  font-size: 17px;
}

.drawer-body {
  display: grid;
  gap: 12px;
  align-content: start;
  padding: 18px 20px;
  overflow: auto;
}

.drawer-body label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.drawer-body input,
.drawer-body select {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-weight: 400;
}

.drawer-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

@media (max-width: 760px) {
  .header-actions {
    align-items: flex-end;
    flex-direction: column;
  }

  .asset-filter-bar {
    flex-direction: column;
    align-items: stretch;
  }

  .asset-filter-actions {
    margin-left: 0;
  }

  .asset-filter-actions .button {
    flex: 1;
  }

  .asset-counter {
    align-self: flex-start;
  }
}
</style>

<style scoped>
/* Asset Management in the Vulnerability Management visual system */
.main-column .page-assets.asset-recon {
  --asset-accent: #fb7185;
  --asset-accent-soft: color-mix(in srgb, #fb7185 10%, transparent);
  --asset-panel: var(--surface);
  --asset-line: var(--line);
}

.main-column .page-assets.asset-recon .asset-header {
  min-height: 78px;
  margin-bottom: 12px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-assets.asset-recon .asset-header::before {
  display: block;
  width: 68px;
  height: 2px;
  background: var(--asset-accent);
}

.main-column .page-assets.asset-recon .asset-header::after {
  display: none;
}

.main-column .page-assets .asset-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-assets .asset-header .button {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  min-height: 30px;
  padding: 5px 9px;
  border-color: var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  background: transparent;
  font-size: 10px;
}

.main-column .page-assets .asset-header .button svg {
  display: none;
}

.main-column .page-assets .asset-header .asset-primary {
  border-color: color-mix(in srgb, var(--asset-accent) 58%, var(--border)) !important;
  color: var(--asset-accent) !important;
  background: var(--asset-accent-soft) !important;
}

.asset-stat-row {
  display: grid;
  grid-template-columns: repeat(5, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}

.asset-stat-card {
  --stat-tone: var(--asset-accent);
  display: grid;
  gap: 4px;
  min-height: 72px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--stat-tone);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.asset-stat-card.tone-active {
  --stat-tone: var(--success);
}

.asset-stat-card.tone-risk {
  --stat-tone: var(--danger);
}

.asset-stat-card.tone-unlinked {
  --stat-tone: #9d8cff;
}

.asset-stat-card.tone-average {
  --stat-tone: var(--warning);
}

.asset-stat-card small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: var(--stat-tone);
  font-size: 12px;
}

.asset-stat-icon {
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

.asset-stat-card strong {
  color: var(--stat-tone);
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.asset-filter-console {
  margin-bottom: 12px;
  padding: 10px;
  border: 1px solid var(--line);
  background: var(--surface);
  box-shadow: none;
}

.asset-filter-main {
  display: grid;
  grid-template-columns: minmax(220px, 2fr) repeat(3, minmax(120px, 1fr)) auto auto;
  gap: 8px;
  align-items: center;
}

.asset-filter-main .asset-search-box {
  display: flex;
  min-width: 0;
  height: 34px;
  gap: 6px;
  align-items: center;
  padding: 0 8px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.asset-filter-main .asset-search-box input {
  width: 100%;
  min-width: 0;
  height: 32px;
  padding: 0;
  border: 0 !important;
  background: transparent !important;
}

.asset-filter-main select {
  width: 100%;
  height: 34px;
  padding: 7px 9px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.asset-filter-main .button {
  min-height: 34px;
  padding: 6px 10px;
}

.asset-filter-console .asset-kind-track {
  display: flex;
  gap: 6px;
  margin-top: 8px;
  padding: 8px 0 0;
  overflow-x: auto;
  border: 0;
  border-top: 1px solid var(--border);
  background: transparent;
}

.asset-filter-console .asset-kind-track button {
  min-height: 34px;
  padding: 4px 8px;
  border-color: var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
  font-size: 10px;
}

.asset-filter-console .asset-kind-track button.active {
  border-color: color-mix(in srgb, var(--asset-accent) 55%, var(--border));
  color: var(--asset-accent);
  background: var(--asset-accent-soft);
}

.asset-table-section {
  min-width: 0;
}

.asset-table-section .asset-table-wrap {
  overflow-x: auto;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.asset-table-section .asset-table {
  width: 100%;
  min-width: 1110px;
  border: 1px solid var(--line);
  border-collapse: collapse;
  background: var(--surface);
  box-shadow: none;
}

.asset-table-section .asset-table th,
.asset-table-section .asset-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  text-align: left;
  vertical-align: middle;
}

.asset-table-section .asset-table th {
  color: var(--text-secondary);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.asset-table-section .asset-table tbody tr,
.asset-table-section .asset-table tbody tr.risk-critical,
.asset-table-section .asset-table tbody tr.risk-high {
  border-left: 0;
  background: transparent;
}

.asset-table-section .asset-table tbody tr:hover {
  background: color-mix(in srgb, var(--asset-accent) 4%, transparent);
}

.asset-table-section .asset-table tbody tr:hover td {
  background: transparent;
}

.asset-table-section .asset-name-cell strong {
  font-size: 12px;
}

.asset-table-section .asset-name-cell small,
.asset-table-section .asset-value-cell code,
.asset-table-section .asset-time,
.asset-table-section .asset-project-badge,
.asset-table-section .asset-kind-badge,
.asset-table-section .asset-criticality,
.asset-table-section .asset-state {
  font-size: 10px;
}

.asset-table-section .asset-row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.asset-table-section .asset-row-actions .button {
  display: inline-flex;
  width: auto;
  height: auto;
  min-height: 26px;
  padding: 4px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  background: transparent;
  font-size: 9px;
}

.asset-table-section .asset-row-actions .button:hover {
  border-color: var(--asset-accent);
  color: var(--asset-accent);
}

.asset-table-section .asset-row-actions .button.danger:hover {
  border-color: var(--danger);
  color: var(--danger);
}

.asset-table-section .asset-pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
  padding: 0;
  border: 0;
  color: var(--text-muted);
  font-size: 13px;
}

.asset-table-section .asset-empty,
.asset-table-section .asset-loading {
  min-height: 180px;
  border: 1px solid var(--line);
  background: var(--surface);
}

.asset-drawer-layer,
.asset-dialog-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.asset-drawer {
  width: min(720px, 100%);
  border-left-color: color-mix(in srgb, var(--asset-accent) 34%, var(--border));
  background: var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.4);
}

.asset-drawer-head {
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.asset-drawer-head h2 {
  font-size: 16px;
}

.asset-drawer-body {
  align-content: start;
  gap: 12px;
  padding: 16px;
}

.asset-form-section {
  grid-template-columns: 24px minmax(0, 1fr);
  gap: 10px;
  padding: 0 0 12px;
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
}

.asset-form-section:last-child {
  border-bottom: 0;
}

.asset-form-section h3 {
  font-size: 12px;
}

.asset-form-section label {
  gap: 6px;
  color: var(--text-secondary);
  font-size: 12px;
}

.asset-form-section input,
.asset-form-section select {
  padding: 9px 10px;
  border-color: var(--border-strong);
}

.asset-drawer-foot {
  padding: 12px 16px;
  border-top: 1px solid var(--line);
  background: var(--surface-soft);
}

.asset-dialog {
  border-radius: 4px;
  background: var(--surface);
}

@media (max-width: 1100px) {
  .asset-filter-main {
    grid-template-columns: minmax(200px, 2fr) repeat(3, minmax(110px, 1fr));
  }

  .asset-filter-main .button {
    width: 100%;
  }
}

@media (max-width: 760px) {
  .main-column .page-assets.asset-recon .asset-header {
    padding: 13px;
  }

  .asset-stat-row {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
  }

  .asset-stat-card {
    min-height: 66px;
    padding: 10px 12px;
  }

  .asset-filter-console {
    padding: 9px;
  }

  .asset-filter-main {
    grid-template-columns: 1fr;
  }

  .asset-filter-main .asset-search-box,
  .asset-filter-main select,
  .asset-filter-main .button {
    width: 100%;
  }

  .asset-filter-console .asset-kind-track {
    padding-top: 7px;
  }

  .asset-table-section .asset-table {
    min-width: 0;
    border: 0;
    background: transparent;
  }

  .asset-table-section .asset-table tr {
    border: 1px solid var(--line) !important;
    border-left: 2px solid var(--asset-accent) !important;
    background: var(--surface);
  }

  .asset-table-section .asset-table td {
    font-size: 10px;
  }

  .asset-table-section .asset-row-actions .button {
    flex: 1;
    justify-content: center;
  }

  .asset-table-section .asset-pagination {
    align-items: flex-start;
    flex-direction: column;
    gap: 8px;
  }

  .asset-drawer {
    width: 100%;
  }
}
</style>

<style scoped>
/* Asset reconnaissance registry */
.main-column .page-assets.asset-recon {
  --asset-accent: #55c7e8;
  --asset-mint: #34d399;
  --asset-amber: #f0a43a;
  --asset-violet: #9d8cff;
  --asset-coral: #fb7185;
  --asset-blue: #60a5fa;
  --asset-panel: color-mix(in srgb, var(--surface) 95%, #071012);
  --asset-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-assets.asset-recon .asset-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--asset-accent) 24%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--asset-accent) 9%, transparent), transparent 38%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--asset-accent) 5%, transparent) 37px 38px
    ),
    var(--asset-panel) !important;
}

.main-column .page-assets .asset-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 12px;
}

.asset-header .header-actions {
  gap: 7px;
}

.asset-header .button {
  display: inline-flex;
  gap: 5px;
  align-items: center;
}

.asset-header .button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
}

.asset-primary {
  border-color: color-mix(in srgb, var(--asset-accent) 66%, var(--border)) !important;
  color: #061214 !important;
  background: var(--asset-accent) !important;
}

.asset-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.asset-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(5, minmax(100px, 1fr));
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--asset-line);
  border-radius: 5px;
  background: var(--asset-line);
}

.asset-stat {
  --asset-tone: var(--asset-accent);
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 7px;
  min-height: 64px;
  padding: 9px 11px;
  background: var(--asset-panel);
}

.asset-stat::after {
  position: absolute;
  bottom: 0;
  left: 11px;
  width: 27px;
  height: 2px;
  content: '';
  background: var(--asset-tone);
}

.asset-stat.tone-active {
  --asset-tone: var(--asset-mint);
}

.asset-stat.tone-risk {
  --asset-tone: var(--asset-coral);
}

.asset-stat.tone-unlinked {
  --asset-tone: var(--asset-violet);
}

.asset-stat.tone-average {
  --asset-tone: var(--asset-amber);
}

.asset-stat > span,
.asset-code {
  color: var(--asset-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.1em;
}

.asset-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 500;
}

.asset-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 9px;
}

.asset-scan {
  position: absolute;
  right: 12px;
  bottom: 8px;
  width: 42px;
  height: 8px;
  overflow: hidden;
  opacity: 0.42;
}

.asset-scan::before {
  position: absolute;
  inset: 0;
  content: '';
  background: repeating-linear-gradient(
    90deg,
    var(--asset-accent) 0 3px,
    transparent 3px 7px
  );
}

.asset-scan i {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--asset-mint);
  box-shadow: 0 0 7px var(--asset-mint);
  animation: asset-scan-line 4s linear infinite;
}

.asset-filter-card,
.asset-inventory {
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--asset-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--asset-panel);
}

.asset-filter-card {
  margin-bottom: 10px;
}

.asset-filter-head,
.asset-inventory-head {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}

.asset-filter-head h2,
.asset-inventory-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 13px;
}

.asset-filter-actions {
  display: flex;
  gap: 6px;
}

.asset-kind-track {
  display: flex;
  gap: 5px;
  padding: 8px 10px;
  overflow-x: auto;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 45%, transparent);
}

.asset-kind-track button {
  display: grid;
  grid-template-columns: 28px auto auto;
  gap: 5px;
  align-items: center;
  flex: 0 0 auto;
  min-height: 34px;
  padding: 3px 7px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  background: var(--surface);
  font-size: 9px;
  cursor: pointer;
}

.asset-kind-track button.active {
  border-color: color-mix(in srgb, var(--asset-accent) 52%, var(--border));
  color: var(--text-primary);
  background: color-mix(in srgb, var(--asset-accent) 8%, var(--surface));
}

.asset-kind-track button b {
  font-weight: 500;
  white-space: nowrap;
}

.asset-kind-track button small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
}

.asset-kind-glyph {
  --kind-tone: var(--asset-accent);
  display: grid;
  width: 27px;
  height: 27px;
  border: 1px solid color-mix(in srgb, var(--kind-tone) 45%, var(--border));
  border-radius: 4px;
  color: var(--kind-tone);
  background: color-mix(in srgb, var(--kind-tone) 7%, var(--surface));
  place-items: center;
}

.asset-kind-glyph.tone-violet {
  --kind-tone: var(--asset-violet);
}

.asset-kind-glyph.tone-mint {
  --kind-tone: var(--asset-mint);
}

.asset-kind-glyph.tone-amber {
  --kind-tone: var(--asset-amber);
}

.asset-kind-glyph.tone-coral {
  --kind-tone: var(--asset-coral);
}

.asset-kind-glyph.tone-blue {
  --kind-tone: var(--asset-blue);
}

.asset-kind-glyph.tone-muted {
  --kind-tone: var(--text-muted);
}

.asset-kind-glyph.tone-all {
  --kind-tone: var(--asset-accent);
}

.asset-kind-glyph.tone-all i {
  width: 10px;
  height: 10px;
  border: 1px solid currentColor;
  border-radius: 2px;
  box-shadow:
    5px 0 0 -3px currentColor,
    0 5px 0 -3px currentColor;
}

.asset-kind-glyph svg {
  width: 15px;
  height: 15px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.asset-kind-glyph.compact {
  flex: 0 0 31px;
  width: 31px;
  height: 31px;
}

.asset-filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
  margin: 0;
  padding: 8px 10px;
  border: 0;
  background: transparent;
}

.asset-search-box {
  display: flex;
  flex: 2 1 240px;
  min-width: 180px;
  gap: 6px;
  align-items: center;
  padding: 0 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.asset-search-box svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: var(--text-muted);
  stroke-width: 1.7;
}

.asset-search-box input {
  min-width: 0;
  padding: 7px 0 !important;
  border: 0 !important;
  outline: 0;
  background: transparent !important;
}

.asset-filter-bar select {
  flex: 1 1 140px;
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  font-size: 9px;
}

.asset-inventory-head > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.asset-table-wrap {
  overflow-x: auto;
}

.asset-table {
  min-width: 1110px;
  border-collapse: separate;
  border-spacing: 0;
}

.asset-table th {
  padding: 7px 8px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  background: color-mix(in srgb, var(--field-bg) 78%, var(--asset-accent));
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
  text-align: left;
  white-space: nowrap;
}

.asset-table td {
  padding: 7px 8px;
  border-bottom: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 9px;
  vertical-align: middle;
}

.asset-table tbody tr {
  border-left: 2px solid transparent;
}

.asset-table tbody tr.risk-critical {
  border-left-color: var(--asset-coral);
  background: color-mix(in srgb, var(--asset-coral) 3%, transparent);
}

.asset-table tbody tr.risk-high {
  border-left-color: var(--asset-amber);
}

.asset-table tbody tr:hover {
  background: color-mix(in srgb, var(--asset-accent) 5%, transparent);
}

.asset-name-cell {
  display: flex;
  min-width: 0;
  gap: 7px;
  align-items: center;
  padding: 0;
  border: 0;
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.asset-name-cell:disabled {
  cursor: default;
}

.asset-name-cell > span:last-child {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.asset-name-cell strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.asset-name-cell small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
}

.asset-kind-badge,
.asset-project-badge,
.asset-criticality {
  display: inline-flex;
  width: fit-content;
  min-height: 18px;
  align-items: center;
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  white-space: nowrap;
}

.asset-kind-badge.tone-cyan {
  border-color: color-mix(in srgb, var(--asset-accent) 42%, var(--border));
  color: var(--asset-accent);
}

.asset-kind-badge.tone-violet {
  border-color: color-mix(in srgb, var(--asset-violet) 42%, var(--border));
  color: var(--asset-violet);
}

.asset-kind-badge.tone-mint {
  border-color: color-mix(in srgb, var(--asset-mint) 42%, var(--border));
  color: var(--asset-mint);
}

.asset-kind-badge.tone-amber {
  border-color: color-mix(in srgb, var(--asset-amber) 42%, var(--border));
  color: var(--asset-amber);
}

.asset-kind-badge.tone-coral {
  border-color: color-mix(in srgb, var(--asset-coral) 42%, var(--border));
  color: var(--asset-coral);
}

.asset-kind-badge.tone-blue {
  border-color: color-mix(in srgb, var(--asset-blue) 42%, var(--border));
  color: var(--asset-blue);
}

.asset-value-cell {
  display: flex;
  min-width: 0;
  gap: 4px;
  align-items: center;
}

.asset-value-cell code {
  display: block;
  max-width: 240px;
  overflow: hidden;
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.asset-value-cell button,
.asset-row-actions button,
.asset-drawer-head > button {
  display: grid;
  flex: 0 0 24px;
  width: 24px;
  height: 24px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
  place-items: center;
}

.asset-value-cell button:hover,
.asset-row-actions button:hover {
  border-color: color-mix(in srgb, var(--asset-accent) 40%, var(--border));
  color: var(--asset-accent);
}

.asset-value-cell svg,
.asset-row-actions svg,
.asset-drawer-head svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.asset-project-badge {
  max-width: 140px;
  overflow: hidden;
  color: var(--asset-blue);
  text-overflow: ellipsis;
}

.asset-state {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--asset-mint);
  font-family: var(--mono);
  font-size: 8px;
}

.asset-state i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 5px currentColor;
}

.asset-state.tone-inactive,
.asset-state.tone-retired,
.asset-state.tone-unknown {
  color: var(--text-muted);
}

.asset-criticality.tone-critical {
  border-color: color-mix(in srgb, var(--asset-coral) 55%, var(--border));
  color: #ff8ca0;
  background: color-mix(in srgb, var(--asset-coral) 7%, transparent);
}

.asset-criticality.tone-high {
  border-color: color-mix(in srgb, var(--asset-amber) 52%, var(--border));
  color: var(--asset-amber);
}

.asset-criticality.tone-medium {
  border-color: color-mix(in srgb, #facc15 48%, var(--border));
  color: #facc15;
}

.asset-criticality.tone-low {
  border-color: color-mix(in srgb, var(--asset-mint) 45%, var(--border));
  color: var(--asset-mint);
}

.asset-criticality.tone-info {
  color: var(--text-muted);
}

.asset-risk {
  --risk-tone: var(--asset-accent);
  display: grid;
  grid-template-columns: 25px 58px;
  gap: 6px;
  align-items: center;
}

.asset-risk.tone-critical {
  --risk-tone: var(--asset-coral);
}

.asset-risk.tone-high {
  --risk-tone: var(--asset-amber);
}

.asset-risk.tone-medium {
  --risk-tone: #facc15;
}

.asset-risk.tone-low {
  --risk-tone: var(--asset-mint);
}

.asset-risk.tone-info {
  --risk-tone: var(--text-muted);
}

.asset-risk strong {
  color: var(--risk-tone);
  font-family: var(--mono);
  font-size: 9px;
  text-align: right;
}

.asset-risk > span {
  display: block;
  height: 4px;
  overflow: hidden;
  border-radius: 2px;
  background: var(--border);
}

.asset-risk i {
  display: block;
  height: 100%;
  background: var(--risk-tone);
}

.asset-time {
  color: var(--text-muted) !important;
  font-family: var(--mono);
  font-size: 8px !important;
  white-space: nowrap;
}

.asset-row-actions {
  display: flex;
  gap: 2px;
}

.asset-row-actions button.danger:hover {
  border-color: color-mix(in srgb, var(--asset-coral) 45%, var(--border));
  color: var(--asset-coral);
}

.asset-pagination {
  display: flex;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  border-top: 1px solid var(--border);
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.asset-pagination > div {
  display: flex;
  gap: 6px;
}

.asset-loading,
.asset-empty {
  display: grid;
  min-height: 180px;
  gap: 10px;
  place-items: center;
  align-content: center;
  color: var(--text-muted);
  font-size: 10px;
}

.asset-loading {
  grid-template-columns: repeat(3, 26px);
}

.asset-loading i {
  width: 23px;
  height: 3px;
  background: var(--asset-accent);
  animation: asset-load 1.4s ease-in-out infinite;
}

.asset-loading i:nth-child(2) {
  animation-delay: 0.18s;
}

.asset-loading i:nth-child(3) {
  animation-delay: 0.36s;
}

.asset-loading span {
  grid-column: 1 / -1;
}

.asset-empty-robot {
  position: relative;
  display: block;
  width: 38px;
  height: 34px;
  border: 1px solid var(--text-muted);
  border-radius: 7px;
  opacity: 0.55;
}

.asset-empty-robot::before {
  position: absolute;
  top: -8px;
  left: 17px;
  width: 1px;
  height: 7px;
  content: '';
  background: var(--text-muted);
}

.asset-empty-robot b {
  position: absolute;
  top: 12px;
  width: 5px;
  height: 1px;
  background: var(--text-muted);
}

.asset-empty-robot b:first-of-type {
  left: 9px;
}

.asset-empty-robot b:nth-of-type(2) {
  right: 9px;
}

.asset-empty-robot i {
  position: absolute;
  bottom: 7px;
  left: 12px;
  width: 12px;
  height: 1px;
  background: var(--text-muted);
}

.asset-drawer-layer,
.asset-dialog-layer {
  --asset-accent: #55c7e8;
  --asset-mint: #34d399;
  --asset-amber: #f0a43a;
  --asset-violet: #9d8cff;
  --asset-coral: #fb7185;
  --asset-blue: #60a5fa;
  position: fixed;
  inset: 0;
  z-index: 90;
  display: flex;
  justify-content: flex-end;
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.asset-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(580px, 100%);
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--asset-accent) 30%, var(--border));
  background-color: var(--surface);
  background-image:
    linear-gradient(180deg, color-mix(in srgb, var(--asset-accent) 4%, transparent), transparent 170px),
    linear-gradient(var(--surface), var(--surface));
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.36);
  animation: asset-drawer-in 0.22s ease-out both;
}

.asset-drawer-head {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface-soft) 76%, transparent);
}

.asset-drawer-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 16px;
}

.asset-drawer-head > button {
  border-color: var(--border);
}

.asset-drawer-head > button:hover {
  color: var(--asset-coral);
  border-color: color-mix(in srgb, var(--asset-coral) 45%, var(--border));
}

.asset-drawer-body {
  display: grid;
  gap: 9px;
  align-content: start;
  padding: 14px;
  overflow: auto;
}

.asset-form-section {
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr);
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--field-bg);
}

.asset-form-section > span {
  color: var(--asset-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.asset-form-section > div {
  display: grid;
  gap: 8px;
}

.asset-form-section h3 {
  margin: 0;
  color: var(--text-primary);
  font-size: 10px;
}

.asset-form-section label {
  display: grid;
  gap: 4px;
  color: var(--text-muted);
  font-size: 8px;
}

.asset-form-section label b {
  color: var(--text-muted);
  font-weight: 500;
}

.asset-form-section input,
.asset-form-section select {
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--surface);
}

.drawer-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px;
}

.asset-risk-input > div {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 72px;
  gap: 8px;
  align-items: center;
}

.asset-risk-input input[type='range'] {
  accent-color: var(--asset-accent);
}

.asset-drawer-foot {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  padding: 10px 14px;
  border-top: 1px solid var(--border);
}

.asset-dialog-layer {
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.asset-dialog {
  width: min(420px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--asset-coral) 42%, var(--border));
  border-radius: 5px;
  background: var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
}

.asset-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
}

.asset-dialog h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 15px;
}

.asset-warning {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--asset-coral);
  border-radius: 50%;
  color: var(--asset-coral);
  font-family: var(--mono);
  font-size: 16px;
  place-items: center;
}

.asset-dialog > p {
  margin: 12px 0;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.5;
}

.asset-dialog-value {
  display: flex;
  gap: 7px;
  align-items: center;
  padding: 7px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.asset-dialog-value span {
  color: var(--asset-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.asset-dialog-value code {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.asset-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  margin-top: 14px;
}

@keyframes asset-scan-line {
  from {
    left: 0;
  }
  to {
    left: 100%;
  }
}

@keyframes asset-load {
  0%,
  100% {
    opacity: 0.25;
    transform: scaleX(0.7);
  }
  50% {
    opacity: 1;
    transform: scaleX(1);
  }
}

@keyframes asset-drawer-in {
  from {
    opacity: 0;
    transform: translateX(24px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

@media (max-width: 980px) {
  .asset-status-rail {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .main-column .page-assets.asset-recon {
    overflow-x: hidden;
  }

  .asset-header {
    align-items: stretch;
  }

  .asset-header .header-actions {
    width: 100%;
    flex-direction: row;
    align-items: stretch;
  }

  .asset-header .header-actions .button {
    flex: 1;
    justify-content: center;
  }

  .asset-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .asset-status-rail .asset-stat:last-of-type {
    grid-column: span 2;
  }

  .asset-filter-head {
    align-items: stretch;
    flex-direction: column;
  }

  .asset-filter-actions .button {
    flex: 1;
  }

  .asset-filter-bar {
    align-items: stretch;
    flex-direction: column;
  }

  .asset-filter-bar > *,
  .asset-search-box {
    width: 100%;
    min-width: 0;
  }

  .asset-search-box {
    flex: 0 0 auto;
    min-height: 34px;
  }

  .asset-filter-bar select {
    height: 34px;
    flex: 0 0 34px;
  }

  .main-column .page-assets.asset-recon .asset-table {
    min-width: 0;
  }

  .asset-table thead {
    display: none;
  }

  .asset-table,
  .asset-table tbody,
  .asset-table tr,
  .asset-table td {
    display: block;
    width: 100%;
  }

  .asset-table tr {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    grid-template-areas:
      'name name actions'
      'kind status criticality'
      'value value value'
      'project project risk';
    gap: 5px;
    padding: 9px;
    border-bottom: 1px solid var(--border);
    border-left-width: 2px;
  }

  .asset-table td {
    padding: 0;
    border: 0;
  }

  .asset-table td:first-child {
    grid-area: name;
  }

  .asset-table td:nth-child(2) {
    grid-area: kind;
    display: flex;
    align-items: center;
  }

  .asset-table td:nth-child(3) {
    grid-area: value;
  }

  .asset-table td:nth-child(4) {
    grid-area: project;
    display: flex;
    align-items: center;
  }

  .asset-table td:nth-child(5) {
    grid-area: status;
    display: flex;
    align-items: center;
  }

  .asset-table td:nth-child(6) {
    grid-area: criticality;
    display: flex;
    align-items: center;
    justify-content: flex-end;
  }

  .asset-table td:nth-child(7) {
    grid-area: risk;
    display: flex;
    align-items: center;
    justify-content: flex-end;
  }

  .asset-table td:nth-child(8) {
    display: none;
  }

  .asset-table td:last-child {
    grid-area: actions;
    display: flex;
    justify-self: end;
  }

  .asset-value-cell code {
    max-width: calc(100vw - 110px);
  }

  .asset-pagination {
    align-items: flex-start;
    flex-direction: column;
  }

  .asset-drawer {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .asset-scan i,
  .asset-loading i,
  .asset-drawer {
    animation: none;
  }
}

/* Vulnerability-style final overrides after the legacy asset skin. */
.main-column .page-assets.asset-recon .asset-header {
  background: var(--surface) !important;
  background-image: none !important;
  box-shadow: none !important;
}

.main-column .page-assets.asset-recon .asset-header::after {
  display: none !important;
}

.main-column .page-assets .asset-header .asset-primary {
  border-color: color-mix(in srgb, var(--asset-accent) 58%, var(--border)) !important;
  color: var(--asset-accent) !important;
  background: var(--asset-accent-soft) !important;
}

.asset-table-section .asset-row-actions .button {
  display: inline-flex !important;
  width: auto !important;
  height: auto !important;
  flex: 0 0 auto !important;
  align-items: center !important;
  justify-content: center !important;
  white-space: nowrap !important;
}

.asset-drawer {
  width: min(720px, 100%) !important;
  background: var(--surface) !important;
  background-image: none !important;
  border-left-color: color-mix(in srgb, var(--asset-accent) 34%, var(--border)) !important;
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.4) !important;
}

.asset-drawer-head {
  padding: 14px 16px !important;
  border-bottom: 1px solid var(--line) !important;
  background: var(--surface-soft) !important;
}

.asset-drawer-head h2 {
  font-size: 16px !important;
}

.asset-drawer-body {
  gap: 12px !important;
  align-content: start !important;
  padding: 16px !important;
}

.asset-form-section {
  grid-template-columns: 24px minmax(0, 1fr) !important;
  gap: 10px !important;
  padding: 0 0 12px !important;
  border: 0 !important;
  border-bottom: 1px solid var(--border) !important;
  border-radius: 0 !important;
  background: transparent !important;
}

.asset-form-section:last-child {
  border-bottom: 0 !important;
}

.asset-form-section h3 {
  font-size: 12px !important;
}

.asset-form-section label {
  gap: 6px !important;
  color: var(--text-secondary) !important;
  font-size: 12px !important;
}

.asset-form-section input,
.asset-form-section select {
  padding: 9px 10px !important;
  border-color: var(--border-strong) !important;
}

.asset-drawer-foot {
  padding: 12px 16px !important;
  border-top: 1px solid var(--line) !important;
  background: var(--surface-soft) !important;
}

@media (max-width: 760px) {
  .asset-table-section .asset-row-actions .button {
    flex: 1 1 auto !important;
    min-width: 72px !important;
  }

  .asset-drawer {
    width: 100% !important;
  }
}
</style>
