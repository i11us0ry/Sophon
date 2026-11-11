<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

import { apiDelete, apiGet, apiPost, apiPut, apiUrl } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'

const { t } = useI18n()

interface ProjectCounts {
  facts: number
  attackSteps: number
  assets: number
  conversations: number
  vulnerabilities: number
  promptTokens: number
  completionTokens: number
  totalTokens: number
  tokenUsageEstimated: boolean
}

interface Project {
  id: string
  name: string
  description: string
  goals: string
  scope: string
  status: string
  counts?: ProjectCounts
  createdAt: string
  updatedAt: string
}

interface ProjectPage {
  items: Project[]
  hasMore: boolean
  nextCursor?: string
}

interface ProjectBatchResult {
  created: number
  duplicate: number
  invalid: number
  failed: number
}

interface ProjectBatchStartResult {
  created: number
  started: number
  queued: number
  skipped: number
  failed: number
  maxConcurrency: number
}

interface AgentRoleOption {
  id: string
  name: string
  enabled: boolean
}

const router = useRouter()
const projects = ref<Project[]>([])
const selected = ref<string[]>([])
const loading = ref(false)
const loadingMore = ref(false)
const hasMore = ref(false)
const nextCursor = ref('')
const error = ref('')
const notice = ref('')
const createDraft = reactive({
  name: '',
  description: '',
  goals: '',
  scope: '',
  status: 'active',
})
const showCreate = ref(false)
const showBatchCreate = ref(false)
const showBatchStart = ref(false)
const batchCreating = ref(false)
const batchStarting = ref(false)
const editingId = ref('')
const searchText = ref('')
const statusFilter = ref('')
const riskFilter = ref(false)
const batchDraft = reactive({
  assets: '',
})
const batchStartInstruction = ref('')
const batchStartRoleId = ref('')
const agentRoles = ref<AgentRoleOption[]>([])
const rolesLoading = ref(false)
const deleteTarget = ref<Project | null>(null)
const deleteBatch = ref(false)
const deleting = ref(false)

const PROJECT_STATUSES = ['planning', 'active', 'paused', 'done', 'archived'] as const
const PROJECT_BATCH_MAX_ASSETS = 500
const compactTokenFormatter = new Intl.NumberFormat('zh-CN', {
  notation: 'compact',
  maximumFractionDigits: 1,
})
const exactTokenFormatter = new Intl.NumberFormat('zh-CN')

function statusLabel(status: string) {
  return t(`projectStatus.${status}`)
}

function projectInitial(value: string) {
  const first = Array.from(value.trim())[0] ?? 'P'
  return first.toUpperCase()
}

const filteredProjects = computed(() => {
  const keyword = searchText.value.trim().toLowerCase()
  return projects.value.filter((project) => {
    if (riskFilter.value && (project.counts?.vulnerabilities ?? 0) === 0) {
      return false
    }
    if (statusFilter.value && project.status !== statusFilter.value) {
      return false
    }
    if (!keyword) {
      return true
    }
    return `${project.name} ${project.description}`.toLowerCase().includes(keyword)
  })
})

const statusCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const project of projects.value) {
    counts[project.status] = (counts[project.status] ?? 0) + 1
  }
  return counts
})

const projectStats = computed(() => ({
  total: projects.value.length,
  active: statusCounts.value.active ?? 0,
  paused: statusCounts.value.paused ?? 0,
  done: statusCounts.value.done ?? 0,
  risk: projects.value.filter((project) => (project.counts?.vulnerabilities ?? 0) > 0).length,
}))

const batchAssetCount = computed(
  () => batchDraft.assets.split(/\r?\n/).filter((line) => line.trim()).length,
)

function formatTime(value: string) {
  if (!value) {
    return '-'
  }
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function formatTokenCount(value: number) {
  return compactTokenFormatter.format(value || 0)
}

function formatExactTokenCount(value: number) {
  return exactTokenFormatter.format(value || 0)
}

function projectTokenTitle(project: Project) {
  const counts = project.counts
  const parts = [
    `${t('project.tokenPrompt')} ${formatExactTokenCount(counts?.promptTokens ?? 0)}`,
    `${t('project.tokenCompletion')} ${formatExactTokenCount(counts?.completionTokens ?? 0)}`,
    `${t('project.tokenUsage')} ${formatExactTokenCount(counts?.totalTokens ?? 0)}`,
  ]
  if (counts?.tokenUsageEstimated) {
    parts.push(t('project.tokenEstimated'))
  }
  return parts.join(' · ')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<ProjectPage>('/projects?limit=100')
    projects.value = response.items ?? []
    hasMore.value = Boolean(response.hasMore)
    nextCursor.value = response.nextCursor || ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readProjectsFailed')
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  if (!hasMore.value || !nextCursor.value || loadingMore.value) {
    return
  }
  loadingMore.value = true
  error.value = ''
  try {
    const response = await apiGet<ProjectPage>(
      `/projects?limit=100&before=${encodeURIComponent(nextCursor.value)}`,
    )
    const existing = new Set(projects.value.map((item) => item.id))
    projects.value.push(...response.items.filter((item) => !existing.has(item.id)))
    hasMore.value = Boolean(response.hasMore)
    nextCursor.value = response.nextCursor || ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readProjectsFailed')
  } finally {
    loadingMore.value = false
  }
}

async function loadAgentRoles() {
  rolesLoading.value = true
  try {
    const response = await apiGet<{ items: AgentRoleOption[] }>('/agent-roles?enabled=true')
    agentRoles.value = (response.items ?? []).filter((role) => role.enabled)
    if (!agentRoles.value.some((role) => role.id === batchStartRoleId.value)) {
      batchStartRoleId.value = agentRoles.value[0]?.id ?? ''
    }
  } catch {
    agentRoles.value = []
    batchStartRoleId.value = ''
  } finally {
    rolesLoading.value = false
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

function resetCreateDraft() {
  createDraft.name = ''
  createDraft.description = ''
  createDraft.goals = ''
  createDraft.scope = ''
  createDraft.status = 'active'
}

function openCreate() {
  showBatchCreate.value = false
  showBatchStart.value = false
  editingId.value = ''
  resetCreateDraft()
  showCreate.value = true
}

function openEdit(project: Project) {
  showBatchCreate.value = false
  showBatchStart.value = false
  editingId.value = project.id
  createDraft.name = project.name
  createDraft.description = project.description
  createDraft.goals = project.goals
  createDraft.scope = project.scope
  createDraft.status = project.status || 'active'
  showCreate.value = true
}

function openBatchCreate() {
  showCreate.value = false
  showBatchStart.value = false
  editingId.value = ''
  batchDraft.assets = ''
  error.value = ''
  notice.value = ''
  showBatchCreate.value = true
}

function openBatchStart() {
  if (!selected.value.length) {
    return
  }
  showCreate.value = false
  showBatchCreate.value = false
  error.value = ''
  notice.value = ''
  batchStartInstruction.value = t('project.batchStartDefaultInstruction')
  if (!agentRoles.value.some((role) => role.id === batchStartRoleId.value)) {
    batchStartRoleId.value = agentRoles.value[0]?.id ?? ''
  }
  showBatchStart.value = true
}

function exportProject(project: Project) {
  window.open(apiUrl(`/projects/${project.id}/export?format=docx`), '_blank')
}

function closeCreate() {
  showCreate.value = false
  editingId.value = ''
}

function closeBatchCreate() {
  if (batchCreating.value) {
    return
  }
  showBatchCreate.value = false
  batchDraft.assets = ''
}

function closeBatchStart() {
  if (batchStarting.value) {
    return
  }
  showBatchStart.value = false
  batchStartInstruction.value = ''
}

function createProject() {
  if (!createDraft.name.trim()) {
    error.value = '项目名称不能为空'
    return
  }
  const isEdit = editingId.value !== ''
  const targetId = editingId.value
  void run(async () => {
    const payload = {
      name: createDraft.name.trim(),
      description: createDraft.description.trim(),
      goals: createDraft.goals.trim(),
      scope: createDraft.scope.trim(),
      status: createDraft.status,
    }
    if (isEdit) {
      await apiPut(`/projects/${targetId}`, payload)
    } else {
      await apiPost('/projects', payload)
    }
    showCreate.value = false
    editingId.value = ''
    resetCreateDraft()
    await load()
  }, isEdit ? t('project.updated') : t('project.created'))
}

async function createProjectsBatch() {
  if (!batchDraft.assets.trim()) {
    error.value = t('project.batchAssetsRequired')
    return
  }
  if (batchAssetCount.value > PROJECT_BATCH_MAX_ASSETS) {
    error.value = t('project.batchLimit', { count: PROJECT_BATCH_MAX_ASSETS })
    return
  }

  batchCreating.value = true
  error.value = ''
  notice.value = ''
  try {
    const result = await apiPost<ProjectBatchResult>('/projects/batch', {
      assets: batchDraft.assets,
    })
    showBatchCreate.value = false
    batchDraft.assets = ''
    await load()
    notice.value = t('project.batchCreated', {
      created: result.created,
      duplicate: result.duplicate,
      invalid: result.invalid,
      failed: result.failed,
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  } finally {
    batchCreating.value = false
  }
}

async function startSelectedProjects() {
  if (!selected.value.length || batchStarting.value) {
    return
  }
  if (!batchStartRoleId.value) {
    error.value = t('project.batchStartRoleRequired')
    return
  }
  batchStarting.value = true
  error.value = ''
  notice.value = ''
  try {
    const result = await apiPost<ProjectBatchStartResult>('/projects/batch-start', {
      projectIds: [...selected.value],
      instruction: batchStartInstruction.value.trim(),
      roleId: batchStartRoleId.value,
    })
    showBatchStart.value = false
    selected.value = []
    await load()
    notice.value = t('project.batchStarted', {
      started: result.started,
      queued: result.queued,
      skipped: result.skipped,
      failed: result.failed,
      maxConcurrency: result.maxConcurrency,
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  } finally {
    batchStarting.value = false
  }
}

function openProject(project: Project) {
  void router.push({ name: 'project-detail', params: { id: project.id } })
}

function selectStatus(status: string) {
  statusFilter.value = status
  riskFilter.value = false
}

function selectRiskProjects() {
  statusFilter.value = ''
  riskFilter.value = true
}

function resetProjectFilters() {
  searchText.value = ''
  statusFilter.value = ''
  riskFilter.value = false
}

function toggleSelect(projectId: string) {
  if (selected.value.includes(projectId)) {
    selected.value = selected.value.filter((item) => item !== projectId)
    return
  }
  selected.value = [...selected.value, projectId]
}

const allSelected = computed(
  () =>
    filteredProjects.value.length > 0 &&
    selected.value.length === filteredProjects.value.length,
)

function toggleAll() {
  selected.value = allSelected.value ? [] : filteredProjects.value.map((item) => item.id)
}

function requestDelete(project: Project) {
  deleteTarget.value = project
  deleteBatch.value = false
}

function requestDeleteSelected() {
  if (!selected.value.length || deleting.value) {
    return
  }
  deleteTarget.value = null
  deleteBatch.value = true
}

function closeDeleteDialog() {
  if (deleting.value) {
    return
  }
  deleteTarget.value = null
  deleteBatch.value = false
}

async function confirmDelete() {
  if (deleting.value) {
    return
  }
  const batch = deleteBatch.value
  const ids = batch ? [...selected.value] : deleteTarget.value ? [deleteTarget.value.id] : []
  if (!ids.length) {
    closeDeleteDialog()
    return
  }
  deleting.value = true
  error.value = ''
  notice.value = ''
  try {
    if (batch) {
      const result = await apiPost<{ deleted: number }>('/projects/batch-delete', { ids })
      notice.value = t('project.deletedCount', { count: result.deleted })
    } else {
      await apiDelete(`/projects/${ids[0]}`)
      notice.value = t('project.deleted')
    }
    selected.value = []
    deleteTarget.value = null
    deleteBatch.value = false
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  } finally {
    deleting.value = false
  }
}

onMounted(() => {
  void load()
  void loadAgentRoles()
})
</script>

<template>
  <section class="page factory-page page-projects">
    <header class="page-header project-control-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="amber" />
        <div>
          <p class="eyebrow">PROJECT CONTROL // MISSION REGISTRY</p>
          <h1>{{ t('nav.projects') }}</h1>
          <p class="project-page-hint">{{ t('project.controlHint') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="button project-header-button" type="button" @click="openBatchCreate">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 7h16M4 12h16M4 17h10M18 15v6M15 18h6" />
          </svg>
          {{ t('project.batchCreate') }}
        </button>
        <button class="button project-header-button project-primary" type="button" @click="openCreate">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          {{ t('project.create') }}
        </button>
        <button class="button project-header-button" type="button" :disabled="loading" @click="load">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
          {{ t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error project-alert">{{ error }}</div>
    <div v-if="notice" class="alert ok project-alert">{{ notice }}</div>

    <section class="project-status-rail">
      <button
        type="button"
        class="project-stat tone-all"
        :class="{ active: !statusFilter && !riskFilter }"
        @click="resetProjectFilters"
      >
        <small>
          <svg class="project-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="18" height="6" rx="2" />
            <rect x="3" y="14" width="18" height="6" rx="2" />
            <path d="M7 7h.01M7 17h.01" />
          </svg>
          {{ t('project.allProjects') }}
        </small>
        <strong>{{ projectStats.total }}</strong>
      </button>
      <button
        type="button"
        class="project-stat tone-active"
        :class="{ active: statusFilter === 'active' }"
        @click="selectStatus('active')"
      >
        <small>
          <svg class="project-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M8 5v14l11-7z" />
          </svg>
          {{ t('project.activeProjects') }}
        </small>
        <strong>{{ projectStats.active }}</strong>
      </button>
      <button
        type="button"
        class="project-stat tone-paused"
        :class="{ active: statusFilter === 'paused' }"
        @click="selectStatus('paused')"
      >
        <small>
          <svg class="project-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="7" y="5" width="3" height="14" rx="1" />
            <rect x="14" y="5" width="3" height="14" rx="1" />
          </svg>
          {{ t('project.pausedProjects') }}
        </small>
        <strong>{{ projectStats.paused }}</strong>
      </button>
      <button
        type="button"
        class="project-stat tone-done"
        :class="{ active: statusFilter === 'done' }"
        @click="selectStatus('done')"
      >
        <small>
          <svg class="project-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" />
            <path d="m8 12 3 3 5-6" />
          </svg>
          {{ t('project.doneProjects') }}
        </small>
        <strong>{{ projectStats.done }}</strong>
      </button>
      <button
        type="button"
        class="project-stat tone-risk"
        :class="{ active: riskFilter }"
        @click="selectRiskProjects"
      >
        <small>
          <svg class="project-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m12 3 7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z" />
            <path d="M12 8v4M12 16h.01" />
          </svg>
          {{ t('project.riskProjects') }}
        </small>
        <strong>{{ projectStats.risk }}</strong>
      </button>
      <div class="project-scan" aria-hidden="true"><i></i></div>
    </section>

    <section class="project-filter-console">
      <div class="project-filters">
        <input
          v-model="searchText"
          class="project-search"
          type="search"
          :aria-label="t('project.searchPlaceholder')"
          :placeholder="t('project.searchPlaceholder')"
        />
        <select
          v-model="statusFilter"
          class="project-status-filter"
          :aria-label="t('project.statusLabel')"
          @change="riskFilter = false"
        >
        <option value="">{{ t('project.statusAll') }}</option>
        <option v-for="status in PROJECT_STATUSES" :key="status" :value="status">
          {{ statusLabel(status) }}
        </option>
      </select>
      <span class="project-filter-stats">
        {{ t('project.filterStats', {
          total: projects.length,
          shown: filteredProjects.length,
          active: statusCounts.active ?? 0,
        }) }}
      </span>
        <button class="button compact" type="button" @click="resetProjectFilters">
          {{ t('common.reset') }}
        </button>
      </div>
    </section>

    <div class="list-toolbar">
      <label class="select-all">
        <input
          type="checkbox"
          :checked="allSelected"
          :disabled="!projects.length"
          @change="toggleAll"
        />
        <span>{{ t('common.selectAll') }}</span>
      </label>
      <span v-if="selected.length" class="selected-count">
        {{ t('common.selected', { count: selected.length }) }}
      </span>
      <button
        class="button compact"
        type="button"
        :disabled="!selected.length || batchStarting"
        @click="openBatchStart"
      >
        {{ t('project.batchStart') }}
      </button>
      <button
        class="button compact danger"
        type="button"
        :disabled="!selected.length"
        @click="requestDeleteSelected"
      >
        {{ t('common.batchDelete') }}
      </button>
    </div>

    <section class="project-inventory">
      <div class="project-grid">
      <article
        v-for="project in filteredProjects"
        :key="project.id"
        class="project-card"
        :class="`project-status-${project.status}`"
      >
        <div class="project-main">
          <div class="project-summary">
            <div class="project-mark" aria-hidden="true">
              <span>{{ projectInitial(project.name) }}</span>
              <i></i>
            </div>
            <div class="project-copy">
              <div class="project-head">
                <input
                  type="checkbox"
                  :aria-label="project.name"
                  :checked="selected.includes(project.id)"
                  @change="toggleSelect(project.id)"
                />
                <button class="project-name" type="button" @click="openProject(project)">
                  {{ project.name }}
                </button>
                <span class="status-badge" :class="`status-${project.status}`">
                  {{ statusLabel(project.status) }}
                </span>
              </div>
              <span class="project-record-id">
                {{ t('project.projectCode') }} // {{ project.id.slice(0, 8).toUpperCase() }}
              </span>
              <p class="project-description">
                {{ project.description || t('role.noDescription') }}
              </p>
            </div>
          </div>
          <div class="project-meta-line">
            <span>
              <small>{{ t('project.facts') }}</small>
              <strong>{{ project.counts?.facts ?? 0 }}</strong>
            </span>
            <span>
              <small>{{ t('project.attackSteps') }}</small>
              <strong>{{ project.counts?.attackSteps ?? 0 }}</strong>
            </span>
            <span>
              <small>{{ t('project.assets') }}</small>
              <strong>{{ project.counts?.assets ?? 0 }}</strong>
            </span>
            <span>
              <small>{{ t('nav.chat') }}</small>
              <strong>{{ project.counts?.conversations ?? 0 }}</strong>
            </span>
            <span class="project-meta-token" :title="projectTokenTitle(project)">
              <small>{{ t('project.tokenUsage') }}</small>
              <strong>{{ formatTokenCount(project.counts?.totalTokens ?? 0) }}</strong>
            </span>
            <span
              class="project-meta-risk"
              :class="{ alert: (project.counts?.vulnerabilities ?? 0) > 0 }"
            >
              <small>{{ t('project.vulnerabilities') }}</small>
              <strong>{{ project.counts?.vulnerabilities ?? 0 }}</strong>
            </span>
          </div>
        </div>
        <div class="project-side">
          <small class="project-updated">
            {{ t('project.updatedAt', { time: formatTime(project.updatedAt) }) }}
          </small>
          <div class="project-actions">
            <button class="project-action-open" type="button" @click="openProject(project)">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
              <span>{{ t('project.enter') }}</span>
            </button>
            <button
              class="project-action-quiet"
              type="button"
              :title="t('project.export')"
              :aria-label="t('project.export')"
              @click="exportProject(project)"
            >
              {{ t('project.export') }}
            </button>
            <button
              class="project-action-quiet"
              type="button"
              :title="t('common.edit')"
              :aria-label="t('common.edit')"
              @click="openEdit(project)"
            >
              {{ t('common.edit') }}
            </button>
            <button
              class="project-action-quiet danger"
              type="button"
              :title="t('common.delete')"
              :aria-label="t('common.delete')"
              @click="requestDelete(project)"
            >
              {{ t('common.delete') }}
            </button>
          </div>
        </div>
      </article>

      <p v-if="!projects.length && !loading" class="empty-projects">{{ t('project.empty') }}</p>
      <p v-else-if="!filteredProjects.length && !loading" class="empty-projects">
        {{ t('project.searchEmpty') }}
      </p>
      </div>
      <button
        v-if="hasMore"
        class="button load-more-projects"
        type="button"
        :disabled="loadingMore"
        @click="loadMore"
      >
        {{ loadingMore ? t('common.loading') : t('common.loadMore') }}
      </button>
    </section>

    <div v-if="showCreate" class="modal-mask" @click="closeCreate"></div>
    <form v-if="showCreate" class="project-modal" @submit.prevent="createProject">
      <header class="modal-header">
        <h2>{{ editingId ? t('project.editTitle') : t('project.create') }}</h2>
        <button class="modal-close" type="button" @click="closeCreate">×</button>
      </header>
      <div class="modal-body">
        <label class="field">
          <span>{{ t('project.nameLabel') }}</span>
          <input v-model="createDraft.name" :placeholder="t('project.namePlaceholder')" />
        </label>
        <label class="field">
          <span>{{ t('project.descriptionLabel') }}</span>
          <input
            v-model="createDraft.description"
            :placeholder="t('project.descriptionPlaceholder')"
          />
        </label>
        <label class="field">
          <span>{{ t('project.goalsLabel') }}</span>
          <textarea
            v-model="createDraft.goals"
            rows="3"
            :placeholder="t('project.goalsPlaceholder')"
          ></textarea>
        </label>
        <label class="field">
          <span>{{ t('project.scopeLabel') }}</span>
          <textarea
            v-model="createDraft.scope"
            rows="3"
            :placeholder="t('project.scopePlaceholder')"
          ></textarea>
        </label>
        <label class="field">
          <span>{{ t('project.statusLabel') }}</span>
          <select v-model="createDraft.status">
            <option v-for="status in PROJECT_STATUSES" :key="status" :value="status">
              {{ statusLabel(status) }}
            </option>
          </select>
        </label>
      </div>
      <footer class="modal-footer">
        <button class="button" type="submit">
          {{ editingId ? t('common.save') : t('project.create') }}
        </button>
        <button class="button" type="button" @click="closeCreate">{{ t('common.cancel') }}</button>
      </footer>
    </form>

    <div v-if="showBatchCreate" class="modal-mask" @click="closeBatchCreate"></div>
    <form
      v-if="showBatchCreate"
      class="project-modal batch-project-modal"
      @submit.prevent="createProjectsBatch"
    >
      <header class="modal-header">
        <h2>{{ t('project.batchTitle') }}</h2>
        <button
          class="modal-close"
          type="button"
          :disabled="batchCreating"
          @click="closeBatchCreate"
        >
          ×
        </button>
      </header>
      <div class="modal-body">
        <label class="field">
          <span class="field-heading">
            <span>{{ t('project.batchAssetsLabel') }}</span>
            <small>{{ batchAssetCount }} / {{ PROJECT_BATCH_MAX_ASSETS }}</small>
          </span>
          <textarea
            v-model="batchDraft.assets"
            class="batch-assets-input"
            rows="14"
            :placeholder="t('project.batchAssetsPlaceholder')"
          ></textarea>
        </label>
        <p class="batch-hint">{{ t('project.batchHint') }}</p>
      </div>
      <footer class="modal-footer">
        <button class="button" type="submit" :disabled="batchCreating">
          {{ batchCreating ? t('common.loading') : t('project.batchCreateSubmit') }}
        </button>
        <button class="button" type="button" :disabled="batchCreating" @click="closeBatchCreate">
          {{ t('common.cancel') }}
        </button>
      </footer>
    </form>

    <div v-if="showBatchStart" class="modal-mask" @click="closeBatchStart"></div>
    <form
      v-if="showBatchStart"
      class="project-modal batch-start-modal"
      @submit.prevent="startSelectedProjects"
    >
      <header class="modal-header">
        <h2>{{ t('project.batchStartTitle') }}</h2>
        <button
          class="modal-close"
          type="button"
          :disabled="batchStarting"
          @click="closeBatchStart"
        >
          ×
        </button>
      </header>
      <div class="modal-body">
        <p class="batch-start-summary">
          {{ t('project.batchStartSelected', { count: selected.length }) }}
        </p>
        <label class="field">
          <span>{{ t('project.batchStartInstructionLabel') }}</span>
          <textarea
            v-model="batchStartInstruction"
            class="batch-start-instruction"
            rows="8"
          ></textarea>
        </label>
        <label class="field">
          <span>{{ t('project.batchStartRoleLabel') }}</span>
          <select
            v-model="batchStartRoleId"
            class="batch-start-role"
            :disabled="batchStarting || rolesLoading || !agentRoles.length"
            required
          >
            <option value="" disabled>
              {{ rolesLoading ? t('common.loading') : t('project.batchStartRolePlaceholder') }}
            </option>
            <option v-for="role in agentRoles" :key="role.id" :value="role.id">
              {{ role.name }}
            </option>
          </select>
        </label>
        <p v-if="!rolesLoading && !agentRoles.length" class="batch-hint">
          {{ t('project.batchStartNoRoles') }}
        </p>
        <p class="batch-hint">{{ t('project.batchStartHint') }}</p>
      </div>
      <footer class="modal-footer">
        <button
          class="button"
          type="submit"
          :disabled="batchStarting || rolesLoading || !batchStartRoleId"
        >
          {{ batchStarting ? t('common.loading') : t('project.batchStartSubmit') }}
        </button>
        <button class="button" type="button" :disabled="batchStarting" @click="closeBatchStart">
          {{ t('common.cancel') }}
        </button>
      </footer>
    </form>

    <div
      v-if="deleteTarget || deleteBatch"
      class="project-dialog-layer"
      @click.self="closeDeleteDialog"
    >
      <section class="project-dialog" role="dialog" aria-modal="true">
        <header>
          <span class="project-warning" aria-hidden="true">!</span>
          <div>
            <span class="project-code">PROJECT REMOVAL</span>
            <h2>
              {{
                deleteBatch
                  ? t('project.removeBatchTitle')
                  : t('project.removeTitle')
              }}
            </h2>
          </div>
        </header>
        <p>
          {{
            deleteBatch
              ? t('project.confirmBatchDelete', { count: selected.length })
              : t('project.confirmDeleteCascade', { name: deleteTarget?.name ?? '' })
          }}
        </p>
        <div v-if="deleteTarget && !deleteBatch" class="project-dialog-record">
          <span>{{ statusLabel(deleteTarget.status) }}</span>
          <code>{{ deleteTarget.name }}</code>
        </div>
        <footer>
          <button class="button compact" type="button" :disabled="deleting" @click="closeDeleteDialog">
            {{ t('common.cancel') }}
          </button>
          <button class="button compact danger" type="button" :disabled="deleting" @click="confirmDelete">
            {{ deleting ? t('common.loading') : t('project.deletePermanently') }}
          </button>
        </footer>
      </section>
    </div>
  </section>
</template>

<style scoped>
.alert.ok {
  color: var(--success);
  background: rgba(52, 211, 153, 0.14);
}

.header-actions {
  display: flex;
  gap: 8px;
}

.project-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 14px;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--surface);
  box-shadow: none;
}

.project-search {
  flex: 1 1 260px;
  min-width: 180px;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: inherit;
  font: inherit;
}

.project-status-filter {
  min-width: 138px;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: inherit;
  font: inherit;
}

.project-filter-stats {
  padding: 4px 8px;
  border: 1px solid color-mix(in srgb, var(--accent) 14%, var(--border));
  border-radius: 3px;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 5%, transparent);
  font-family: var(--mono);
  font-size: 10px;
  line-height: 1.5;
}

.status-badge {
  flex-shrink: 0;
  margin-left: auto;
  padding: 3px 7px;
  border: 1px solid currentColor;
  border-radius: 999px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
}

.status-planning {
  color: var(--accent);
  background: var(--accent-soft);
}

.status-active {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 12%, var(--surface));
}

.status-paused {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 12%, var(--surface));
}

.status-done {
  color: var(--accent);
  background: var(--accent-soft);
}

.status-archived {
  color: var(--text-muted);
  background: var(--surface-soft);
}

.modal-mask {
  position: fixed;
  inset: 0;
  z-index: 40;
  background: rgb(5 10 15 / 0.58);
}

.project-modal {
  position: fixed;
  top: 50%;
  left: 50%;
  z-index: 41;
  display: flex;
  flex-direction: column;
  width: min(560px, 92vw);
  max-height: 88vh;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
  transform: translate(-50%, -50%);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.modal-header h2 {
  margin: 0;
  font-size: 16px;
}

.modal-close {
  padding: 0 6px;
  border: none;
  background: none;
  color: var(--text-muted);
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
}

.modal-body {
  display: grid;
  gap: 12px;
  padding: 16px;
  overflow-y: auto;
}

.modal-body .field {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.field-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.field-heading small {
  color: var(--text-muted);
  font-weight: 400;
}

.modal-body input,
.modal-body textarea,
.modal-body select {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: inherit;
  font: inherit;
  font-weight: 400;
}

.modal-body textarea {
  resize: vertical;
}

.batch-project-modal {
  width: min(680px, 94vw);
}

.batch-start-modal {
  width: min(720px, 94vw);
}

.batch-start-summary {
  margin: 0;
  padding: 10px 12px;
  border: 1px solid var(--accent-line);
  border-radius: var(--radius);
  color: var(--accent);
  background: var(--accent-soft);
  font-size: 13px;
  font-weight: 600;
}

.batch-start-instruction {
  min-height: 180px;
  line-height: 1.6;
}

.batch-assets-input {
  min-height: 280px;
  font-family: var(--font-mono, monospace);
  line-height: 1.55;
}

.batch-hint {
  margin: -2px 0 0;
  color: var(--text-muted);
  font-size: 12px;
  line-height: 1.6;
}

.modal-footer {
  display: flex;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--line);
  background: var(--surface-soft);
}

.list-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  padding: 6px 0 !important;
  border-width: 1px 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
}

.select-all {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted);
  font-size: 12px;
}

.selected-count {
  color: var(--accent);
  font-size: 12px;
}

.project-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 10px;
}

.load-more-projects {
  width: 100%;
  margin-top: 12px;
}

.project-card {
  --project-tone: var(--accent);
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 230px;
  gap: 16px;
  align-items: center;
  min-height: 0;
  padding: 13px 15px;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--surface);
  box-shadow: none;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.project-card::before {
  display: none;
}

.project-card:hover {
  border-color: color-mix(in srgb, var(--project-tone) 40%, var(--line)) !important;
  transform: translateY(-1px);
}

.project-status-planning {
  --project-tone: var(--accent);
}

.project-status-active {
  --project-tone: var(--success);
}

.project-status-paused {
  --project-tone: var(--warning);
}

.project-status-done {
  --project-tone: var(--accent-solid);
}

.project-status-archived {
  --project-tone: var(--text-muted);
}

.project-main {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.project-summary {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr);
  gap: 11px;
  align-items: center;
  min-width: 0;
}

.project-mark {
  position: relative;
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  color: var(--project-tone);
  border: 1px solid color-mix(in srgb, var(--project-tone) 34%, var(--line));
  border-radius: 4px;
  background: color-mix(in srgb, var(--project-tone) 5%, transparent);
  font-family: var(--mono);
  font-size: 14px;
  line-height: 1;
}

.project-mark i {
  position: absolute;
  top: -3px;
  right: -3px;
  width: 7px;
  height: 7px;
  border: 2px solid var(--surface);
  border-radius: 50%;
  background: currentColor;
}

.project-copy {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.project-head {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.project-side {
  display: grid;
  gap: 7px;
  align-self: center;
  justify-items: end;
  min-width: 0;
  padding-left: 15px;
  border-left: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
}

.project-updated {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  white-space: nowrap;
}

.project-actions {
  display: flex;
  gap: 5px;
  flex-wrap: wrap;
  justify-content: flex-end;
  align-items: center;
}

.project-action-open,
.project-action-quiet {
  min-height: 28px;
  border-radius: 3px;
  font-size: 11px;
  line-height: 1.2;
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    color 0.15s ease,
    background 0.15s ease;
}

.project-action-open {
  padding: 5px 10px;
  border: 1px solid color-mix(in srgb, var(--project-tone) 42%, var(--border));
  color: var(--project-tone);
  background: color-mix(in srgb, var(--project-tone) 7%, transparent);
}

.project-action-open:hover {
  border-color: var(--project-tone);
  background: color-mix(in srgb, var(--project-tone) 12%, transparent);
}

.project-action-quiet {
  padding: 5px 7px;
  border: 1px solid transparent;
  color: var(--text-muted);
  background: transparent;
}

.project-action-quiet:hover {
  border-color: var(--border);
  color: var(--text-primary);
  background: var(--surface-soft);
}

.project-action-quiet.danger:hover {
  border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 8%, transparent);
}

.project-action-open:focus-visible,
.project-action-quiet:focus-visible {
  outline: 2px solid var(--project-tone);
  outline-offset: 1px;
}

.project-name {
  flex: 1 1 auto;
  min-width: 0;
  padding: 0;
  border: 0;
  color: var(--text-primary);
  background: transparent;
  font-size: 15px;
  font-weight: 600;
  line-height: 1.35;
  text-align: left;
  overflow-wrap: anywhere;
  cursor: pointer;
}

.project-name:hover {
  color: var(--project-tone);
}

.project-card small {
  color: var(--text-muted);
  font-size: 12px;
}

.project-description {
  display: -webkit-box;
  margin: 0;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.5;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.project-meta-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  min-width: 0;
}

.project-meta-line span {
  display: inline-flex;
  gap: 5px;
  align-items: baseline;
  min-width: 0;
  padding: 0 9px;
  border-left: 1px solid color-mix(in srgb, var(--line) 58%, transparent);
}

.project-meta-line span:first-child {
  padding-left: 0;
  border-left: 0;
}

.project-meta-line small {
  color: var(--text-muted);
  font-size: 10px;
  white-space: nowrap;
}

.project-meta-line strong {
  color: var(--text-primary);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}

.project-meta-risk.alert strong {
  color: var(--danger);
}

.project-meta-risk.alert small {
  color: color-mix(in srgb, var(--danger) 74%, var(--text-muted));
}

.project-meta-token strong {
  color: var(--accent);
}

.empty-projects {
  margin: 0;
  padding: 28px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  color: var(--text-muted);
  text-align: center;
}

@media (max-width: 1180px) {
  .project-grid {
    grid-template-columns: 1fr;
  }

  .project-card {
    grid-template-columns: minmax(0, 1fr) minmax(230px, auto);
  }
}

@media (max-width: 760px) {
  .project-filters {
    align-items: stretch;
  }

  .project-search,
  .project-status-filter {
    flex: 1 1 100%;
    width: 100%;
  }

  .project-filter-stats {
    width: fit-content;
  }

  .project-grid {
    grid-template-columns: 1fr;
  }

  .project-card {
    grid-template-columns: 1fr;
    gap: 12px;
    padding: 13px 14px;
  }

  .project-summary {
    grid-template-columns: 34px minmax(0, 1fr);
    gap: 9px;
  }

  .project-mark {
    width: 34px;
    height: 34px;
    font-size: 12px;
  }

  .project-head {
    flex-wrap: wrap;
  }

  .status-badge {
    margin-left: auto;
  }

  .project-side {
    justify-items: stretch;
    padding-top: 10px;
    padding-left: 0;
    border-top: 1px solid color-mix(in srgb, var(--line) 64%, transparent);
    border-left: 0;
  }

  .project-updated {
    white-space: normal;
  }

  .project-actions {
    justify-content: stretch;
  }

  .project-action-open {
    flex: 1 1 100%;
    width: 100%;
  }

  .project-action-quiet {
    flex: 1 1 calc(33.333% - 4px);
    min-width: 0;
  }

  .project-meta-line {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 5px 0;
  }

  .project-meta-line span {
    padding: 0 8px;
  }

  .project-meta-line span:nth-child(2n + 1) {
    padding-left: 0;
    border-left: 0;
  }

  .project-meta-line span:nth-child(5),
  .project-meta-line span:nth-child(6) {
    padding-top: 5px;
    border-top: 1px solid color-mix(in srgb, var(--line) 64%, transparent);
  }

  .project-meta-line span:nth-child(5) {
    padding-left: 0;
    border-left: 0;
  }
}
</style>

<style scoped>
/* Project mission registry */
.main-column .page-projects {
  --project-accent: #f0a43a;
  --project-mint: #34d399;
  --project-amber: #f0a43a;
  --project-coral: #fb7185;
  --project-violet: #9d8cff;
  --project-panel: color-mix(in srgb, var(--surface) 95%, #100d08);
  --project-line: color-mix(in srgb, var(--border-strong) 58%, transparent);
}

.main-column .page-projects .project-control-header {
  min-height: 78px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--project-accent) 30%, var(--border)) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-projects .project-control-header::after {
  display: none;
}

.project-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 12px;
}

.project-header-button {
  display: inline-flex;
  gap: 5px;
  align-items: center;
}

.project-header-button svg,
.project-action-quiet svg,
.project-action-open svg {
  display: none;
}

.project-primary {
  border-color: color-mix(in srgb, var(--project-accent) 66%, var(--border)) !important;
  color: var(--project-accent) !important;
  background: color-mix(in srgb, var(--project-accent) 10%, transparent) !important;
}

.project-primary:hover:not(:disabled) {
  color: var(--project-accent) !important;
  background: color-mix(in srgb, var(--project-accent) 16%, transparent) !important;
}

.project-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.project-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  overflow: visible;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.project-stat {
  --stat-tone: var(--project-accent);
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 4px;
  align-content: center;
  min-height: 72px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--stat-tone);
  border-radius: var(--radius);
  color: var(--stat-tone);
  background: var(--surface);
  text-align: left;
  cursor: pointer;
}

.project-stat::after {
  display: none;
}

.project-stat::before {
  position: absolute;
  top: 0;
  bottom: 0;
  left: 0;
  width: 2px;
  content: '';
  background: transparent;
}

.project-stat.active {
  border-color: color-mix(in srgb, var(--stat-tone) 45%, var(--border));
  background: color-mix(in srgb, var(--stat-tone) 6%, var(--surface));
}

.project-stat.active::before {
  background: var(--stat-tone);
}

.project-stat.tone-active {
  --stat-tone: var(--project-mint);
}

.project-stat.tone-paused {
  --stat-tone: var(--project-amber);
}

.project-stat.tone-done {
  --stat-tone: var(--project-violet);
}

.project-stat.tone-risk {
  --stat-tone: var(--project-coral);
}

.project-code {
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.1em;
}

.project-stat strong {
  color: var(--stat-tone);
  font-family: var(--mono);
  font-size: 20px;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
}

.project-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: var(--stat-tone);
  font-size: 12px;
}

.project-stat-icon {
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

.project-scan {
  display: none;
}

.project-scan::before {
  position: absolute;
  inset: 0;
  content: '';
  background: repeating-linear-gradient(
    90deg,
    var(--project-accent) 0 3px,
    transparent 3px 7px
  );
}

.project-scan i {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--project-mint);
  box-shadow: 0 0 7px var(--project-mint);
  animation: project-scan-line 4s linear infinite;
}

.project-filter-console {
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--project-accent) 20%, var(--border));
  border-radius: 4px;
  background: var(--surface);
  margin-bottom: 10px;
}

.project-filter-head,
.project-inventory-head {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}

.project-filter-head h2,
.project-inventory-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 13px;
}

.project-filter-head .button {
  margin-left: auto;
}

.project-filter-console .project-filters {
  display: grid;
  grid-template-columns: minmax(200px, 2fr) minmax(140px, 1fr) auto auto;
  gap: 8px;
  align-items: center;
  margin: 0;
  padding: 8px 10px;
  border: 0;
  background: transparent;
}

.project-filter-console .project-search,
.project-filter-console .project-status-filter {
  height: 34px;
  padding: 7px 9px;
  background: var(--field-bg);
  font-size: 10px;
}

.project-filter-console .project-filters .button {
  min-height: 34px;
  padding: 6px 10px;
}

.project-filter-console .project-filter-stats {
  color: var(--project-accent);
  border-color: color-mix(in srgb, var(--project-accent) 28%, var(--border));
  background: color-mix(in srgb, var(--project-accent) 7%, transparent);
}

.project-inventory {
  overflow: visible;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.main-column .page-projects .list-toolbar {
  margin: 0 0 10px;
  padding: 7px 10px !important;
  border: 1px solid var(--project-line) !important;
  border-radius: 4px !important;
  background: color-mix(in srgb, var(--field-bg) 50%, transparent) !important;
}

.main-column .page-projects .list-toolbar .button {
  margin-left: 0;
}

.project-inventory-head > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.project-inventory .project-grid {
  gap: 1px;
  padding: 1px;
  overflow: hidden;
  border: 1px solid var(--project-line);
  border-radius: 4px;
  background: var(--project-line);
}

.project-inventory .project-card {
  grid-template-columns: minmax(0, 1fr) 250px;
  gap: 14px;
  min-height: 96px;
  padding: 10px 12px;
  border: 0;
  border-left: 2px solid var(--project-tone);
  border-radius: 0;
  background: var(--project-panel);
}

.project-inventory .project-card:hover {
  border-color: var(--project-tone);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--project-tone) 7%, transparent), transparent 45%),
    var(--project-panel);
  transform: none;
}

.project-inventory .project-summary {
  grid-template-columns: 42px minmax(0, 1fr);
  gap: 12px;
}

.project-inventory .project-mark {
  width: 42px;
  height: 42px;
  border-radius: 5px;
  color: var(--project-tone);
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--project-tone) 12%, transparent), transparent),
    color-mix(in srgb, var(--project-tone) 3%, var(--surface));
  font-size: 15px;
}

.project-inventory .project-mark::before {
  position: absolute;
  top: -5px;
  left: 19px;
  width: 1px;
  height: 5px;
  content: '';
  background: currentColor;
}

.project-inventory .project-mark::after {
  position: absolute;
  top: -7px;
  left: 17px;
  width: 5px;
  height: 3px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 2px;
}

.project-inventory .project-mark i {
  top: 5px;
  right: 5px;
  width: 4px;
  height: 4px;
  border: 0;
  box-shadow: 0 0 6px currentColor;
}

.project-inventory .project-copy {
  gap: 4px;
}

.project-inventory .project-name {
  font-size: 14px;
  font-weight: 600;
}

.project-record-id {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
  letter-spacing: 0.05em;
}

.project-inventory .status-badge {
  padding: 2px 6px;
  border-radius: 2px;
  font-size: 8px;
}

.project-inventory .project-description {
  color: var(--text-muted);
  font-size: 10px;
  -webkit-line-clamp: 1;
}

.project-inventory .project-meta-line {
  gap: 2px 0;
  padding-left: 54px;
}

.project-inventory .project-meta-line span {
  gap: 4px;
  padding: 0 8px;
}

.project-inventory .project-meta-line small {
  font-size: 8px;
}

.project-inventory .project-meta-line strong {
  font-family: var(--mono);
  font-size: 10px;
}

.project-inventory .project-side {
  gap: 8px;
  padding-left: 12px;
  border-left-color: var(--project-line);
}

.project-inventory .project-updated {
  font-size: 7px;
}

.project-inventory .project-actions {
  gap: 4px;
  flex-wrap: nowrap;
}

.project-inventory .project-action-open {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  min-height: 26px;
  padding: 4px 8px;
  font-size: 9px;
}

.project-inventory .project-action-quiet {
  display: inline-flex;
  width: auto;
  height: 27px;
  min-width: 0;
  align-items: center;
  justify-content: center;
  padding: 4px 7px;
  border-color: var(--border);
  white-space: nowrap;
}

.project-inventory .empty-projects {
  grid-column: 1 / -1;
  margin: 0;
  border: 0;
  border-radius: 0;
  background: var(--project-panel);
}

.main-column .page-projects .load-more-projects {
  width: 100%;
  margin: 0;
  border-width: 1px 0 0;
  border-radius: 0;
}

.main-column .page-projects .modal-mask {
  z-index: 70;
  background: rgba(4, 9, 10, 0.66);
  backdrop-filter: blur(3px);
}

.main-column .page-projects .project-modal {
  top: 0;
  right: 0;
  bottom: 0;
  left: auto;
  z-index: 71;
  width: min(600px, 100%);
  max-height: none;
  height: 100%;
  border-width: 0 0 0 1px;
  border-color: color-mix(in srgb, var(--project-accent) 34%, var(--border));
  border-radius: 0;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--project-accent) 5%, transparent), transparent 180px),
    var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.38);
  transform: none;
  animation: project-drawer-in 0.22s ease-out both;
}

.main-column .page-projects .batch-project-modal,
.main-column .page-projects .batch-start-modal {
  width: min(720px, 100%);
}

.main-column .page-projects .modal-header {
  min-height: 58px;
  padding: 13px 15px;
  background:
    repeating-linear-gradient(
      90deg,
      transparent 0 27px,
      color-mix(in srgb, var(--project-accent) 4%, transparent) 27px 28px
    ),
    var(--surface-soft);
}

.main-column .page-projects .modal-header h2 {
  font-size: 15px;
}

.main-column .page-projects .modal-body {
  flex: 1;
  gap: 10px;
  align-content: start;
  padding: 14px;
  overflow: auto;
}

.main-column .page-projects .modal-body .field {
  gap: 4px;
  font-size: 9px;
}

.main-column .page-projects .modal-body input,
.main-column .page-projects .modal-body textarea,
.main-column .page-projects .modal-body select {
  padding: 8px 9px;
  font-size: 10px;
}

.main-column .page-projects .modal-footer {
  justify-content: flex-end;
  padding: 10px 14px;
}

.project-dialog-layer {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: grid;
  padding: 20px;
  background: rgba(4, 9, 10, 0.68);
  backdrop-filter: blur(3px);
  place-items: center;
}

.project-dialog {
  width: min(430px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--project-coral) 44%, var(--border));
  border-radius: 5px;
  background: var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.44);
}

.project-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
}

.project-dialog h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 15px;
}

.project-warning {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--project-coral);
  border-radius: 50%;
  color: var(--project-coral);
  font-family: var(--mono);
  font-size: 16px;
  place-items: center;
}

.project-dialog > p {
  margin: 12px 0;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.55;
}

.project-dialog-record {
  display: flex;
  gap: 7px;
  align-items: center;
  padding: 7px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.project-dialog-record span {
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.project-dialog-record code {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.project-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  margin-top: 14px;
}

@keyframes project-scan-line {
  from {
    left: 0;
  }
  to {
    left: 100%;
  }
}

@keyframes project-drawer-in {
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
  .project-status-rail {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .project-inventory .project-card {
    grid-template-columns: minmax(0, 1fr) 220px;
  }
}

@media (max-width: 760px) {
  .project-control-header {
    align-items: stretch;
  }

  .project-control-header .header-actions {
    width: 100%;
    flex-wrap: wrap;
  }

  .project-header-button {
    flex: 1;
    justify-content: center;
  }

  .project-header-button:first-child {
    flex-basis: 100%;
  }

  .project-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .project-status-rail .project-stat:last-of-type {
    grid-column: span 2;
  }

  .project-filter-head {
    align-items: stretch;
  }

  .project-filter-head .button {
    width: 100%;
  }

  .project-filter-console .project-filters {
    align-items: stretch;
    grid-template-columns: minmax(0, 1fr);
  }

  .project-filter-console .project-search,
  .project-filter-console .project-status-filter {
    flex: 0 0 34px;
    width: 100%;
  }

  .project-filter-console .project-filter-stats {
    width: fit-content;
  }

  .list-toolbar {
    flex-wrap: wrap;
  }

  .list-toolbar .button {
    flex: 1;
  }

  .project-inventory .project-card {
    grid-template-columns: 1fr;
    min-height: 0;
    padding: 11px;
  }

  .project-inventory .project-summary {
    grid-template-columns: 36px minmax(0, 1fr);
  }

  .project-inventory .project-mark {
    width: 36px;
    height: 36px;
  }

  .project-inventory .project-mark::before {
    left: 16px;
  }

  .project-inventory .project-mark::after {
    left: 14px;
  }

  .project-inventory .project-head {
    flex-wrap: wrap;
  }

  .project-inventory .project-side {
    justify-items: stretch;
    padding-top: 8px;
    padding-left: 0;
    border-top: 1px solid var(--project-line);
    border-left: 0;
  }

  .project-inventory .project-actions {
    flex-wrap: wrap;
  }

  .project-inventory .project-action-open {
    flex: 1;
  }

  .project-inventory .project-action-quiet {
    flex: 0 0 29px;
    width: 29px;
    height: 29px;
  }

  .project-inventory .project-meta-line {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    padding-left: 0;
  }

  .main-column .page-projects .project-modal {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .project-scan i,
  .main-column .page-projects .project-modal {
    animation: none;
  }
}
</style>
