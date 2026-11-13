<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../i18n'

interface ZhiziNode {
  id: string
  name: string
  host: string
  port: number
  username: string
  authType: 'key' | 'password'
  hostKeyFingerprint: string
  workRoot: string
  maxSlots: number
  activeSlots: number
  enabled: boolean
  lastTestAt: string
  lastTestError: string
  initStatus: 'never' | 'queued' | 'running' | 'succeeded' | 'failed'
  initMessage: string
  initStartedAt: string
  initFinishedAt: string
  createdAt: string
  updatedAt: string
}

interface HostKeyProbe {
  host: string
  port: number
  algorithm: string
  fingerprint: string
}

interface ZhiziAvailability {
  enabledNodes: number
  totalSlots: number
  activeSlots: number
  available: number
}

interface ZhiziListResponse {
  items: ZhiziNode[]
  availability: ZhiziAvailability
}

interface ZhiziBatchTestResponse {
  total: number
  succeeded: number
  failed: number
}

const { t } = useI18n()
const auth = useAuthStore()
const nodes = ref<ZhiziNode[]>([])
const availability = ref<ZhiziAvailability>({
  enabledNodes: 0,
  totalSlots: 0,
  activeSlots: 0,
  available: 0,
})
const loading = ref(false)
const saving = ref(false)
const probing = ref(false)
const batchTesting = ref(false)
const batchInitializing = ref(false)
const batchDeleting = ref(false)
const testingId = ref('')
const selectedNodeIDs = ref<string[]>([])
const filters = reactive({
  search: '',
  status: '',
  authType: '',
})
const error = ref('')
const notice = ref('')
const drawerOpen = ref(false)
const editingID = ref('')
const hostKeyProbes = ref<HostKeyProbe[]>([])
const form = reactive({
  name: '',
  host: '',
  port: 22,
  username: 'root',
  authType: 'key' as 'key' | 'password',
  password: '',
  privateKey: '',
  workRoot: '/home/sophon/sophon',
  maxSlots: 1,
  enabled: true,
})

const canWrite = computed(() => auth.hasPermission('zhizi:write'))
const canDelete = computed(() => auth.hasPermission('zhizi:delete'))
const sortedNodes = computed(() =>
  [...nodes.value].sort((left, right) => {
    if (left.enabled !== right.enabled) {
      return left.enabled ? -1 : 1
    }
    return left.name.localeCompare(right.name)
  }),
)
type NodeRuntimeStatus = 'ready' | 'busy' | 'error' | 'unverified' | 'disabled'

function nodeRuntimeStatus(node: ZhiziNode): NodeRuntimeStatus {
  if (!node.enabled) {
    return 'disabled'
  }
  if (!node.hostKeyFingerprint) {
    return 'unverified'
  }
  if (node.lastTestError) {
    return 'error'
  }
  if (!node.lastTestAt || node.lastTestAt.startsWith('0001-')) {
    return 'unverified'
  }
  if (node.activeSlots > 0) {
    return 'busy'
  }
  return 'ready'
}

const filteredNodes = computed(() => {
  const search = filters.search.trim().toLowerCase()
  return sortedNodes.value.filter((node) => {
    if (search && ![
      node.name,
      node.host,
      node.username,
      node.hostKeyFingerprint,
    ].some((value) => value.toLowerCase().includes(search))) {
      return false
    }
    if (filters.authType && node.authType !== filters.authType) {
      return false
    }
    if (filters.status && nodeRuntimeStatus(node) !== filters.status) {
      return false
    }
    return true
  })
})
const selectableNodes = computed(() =>
  filteredNodes.value.filter((node) => node.enabled && Boolean(node.hostKeyFingerprint)),
)
const allSelectableSelected = computed(
  () =>
    selectableNodes.value.length > 0 &&
    selectableNodes.value.every((node) => selectedNodeIDs.value.includes(node.id)),
)
const readyNodeCount = computed(
  () => nodes.value.filter((node) => ['ready', 'busy'].includes(nodeRuntimeStatus(node))).length,
)
const busyNodeCount = computed(
  () => nodes.value.filter((node) => node.activeSlots > 0).length,
)
const errorNodeCount = computed(
  () => nodes.value.filter((node) => nodeRuntimeStatus(node) === 'error').length,
)
const hasRunningInitialization = computed(
  () => nodes.value.some((node) => node.initStatus === 'queued' || node.initStatus === 'running'),
)
let initPollTimer: number | undefined

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<ZhiziListResponse>('/zhizi/nodes')
    nodes.value = response.items ?? []
    availability.value = response.availability
    const selectable = new Set(
      nodes.value
        .filter((node) => node.enabled && Boolean(node.hostKeyFingerprint))
        .map((node) => node.id),
    )
    selectedNodeIDs.value = selectedNodeIDs.value.filter((id) => selectable.has(id))
    scheduleInitPoll()
  } catch (loadError) {
    error.value = loadError instanceof Error ? loadError.message : t('zhizi.loadFailed')
  } finally {
    loading.value = false
  }
}

function resetForm() {
  form.name = ''
  form.host = ''
  form.port = 22
  form.username = 'root'
  form.authType = 'key'
  form.password = ''
  form.privateKey = ''
  hostKeyProbes.value = []
  form.workRoot = '/home/sophon/sophon'
  form.maxSlots = 1
  form.enabled = true
}

function openCreate() {
  editingID.value = ''
  resetForm()
  drawerOpen.value = true
}

function openEdit(node: ZhiziNode) {
  editingID.value = node.id
  form.name = node.name
  form.host = node.host
  form.port = node.port
  form.username = node.username
  form.authType = node.authType
  form.password = ''
  form.privateKey = ''
  hostKeyProbes.value = []
  form.workRoot = node.workRoot
  form.maxSlots = node.maxSlots
  form.enabled = node.enabled
  drawerOpen.value = true
}

function closeDrawer() {
  if (!saving.value) {
    drawerOpen.value = false
  }
}

async function saveNode() {
  if (saving.value || probing.value) {
    return
  }
  if (!hostKeyProbes.value.length) {
    await probeHosts()
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const hosts = requestedHosts()
    const hostFingerprints = Object.fromEntries(
      hostKeyProbes.value.map((item) => [item.host, item.fingerprint]),
    )
    const payload = {
      name: form.name.trim(),
      host: hosts[0] || form.host.trim(),
      hosts,
      port: form.port,
      username: form.username.trim(),
      authType: form.authType,
      password: form.password,
      privateKey: form.privateKey,
      hostFingerprint: hostKeyProbes.value[0]?.fingerprint || '',
      hostFingerprints,
      workRoot: form.workRoot.trim(),
      maxSlots: form.maxSlots,
      enabled: form.enabled,
    }
    if (editingID.value) {
      await apiPut(`/zhizi/nodes/${editingID.value}`, payload)
      notice.value = t('zhizi.updated')
    } else {
      await apiPost('/zhizi/nodes', payload)
      notice.value = t('zhizi.created')
    }
    drawerOpen.value = false
    hostKeyProbes.value = []
    await load()
  } catch (saveError) {
    error.value = saveError instanceof Error ? saveError.message : t('zhizi.saveFailed')
  } finally {
    saving.value = false
  }
}

function requestedHosts() {
  if (form.authType === 'password' && !editingID.value) {
    return form.host
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean)
  }
  return [form.host.trim()].filter(Boolean)
}

function setAuthType(type: 'key' | 'password') {
  if (type === form.authType) {
    return
  }
  const firstHost =
    form.host
      .split(/\r?\n/)
      .map((value) => value.trim())
      .find(Boolean) || ''
  form.authType = type
  if (type === 'key') {
    form.host = firstHost
  }
  hostKeyProbes.value = []
}

async function probeHosts() {
  if (probing.value) {
    return
  }
  const hosts = requestedHosts()
  if (!hosts.length) {
    error.value = t('zhizi.hostRequired')
    return
  }
  probing.value = true
  error.value = ''
  notice.value = ''
  try {
    const response = await apiPost<{ items: HostKeyProbe[] }>('/zhizi/nodes/probe', {
      hosts,
      port: form.port,
    })
    hostKeyProbes.value = response.items ?? []
    if (!hostKeyProbes.value.length) {
      error.value = t('zhizi.fingerprintProbeEmpty')
    }
  } catch (probeError) {
    hostKeyProbes.value = []
    error.value =
      probeError instanceof Error ? probeError.message : t('zhizi.fingerprintProbeFailed')
  } finally {
    probing.value = false
  }
}

watch(
  () => [form.host, form.port, form.authType] as const,
  () => {
    hostKeyProbes.value = []
  },
)

async function testNode(node: ZhiziNode) {
  if (testingId.value || batchTesting.value) {
    return
  }
  testingId.value = node.id
  error.value = ''
  notice.value = ''
  try {
    await apiPost(`/zhizi/nodes/${node.id}/test`, {})
    notice.value = t('zhizi.testSucceeded', { name: node.name })
    await load()
  } catch (testError) {
    error.value = testError instanceof Error ? testError.message : t('zhizi.testFailed')
    await load()
  } finally {
    testingId.value = ''
  }
}

function toggleNodeSelection(node: ZhiziNode, event: Event) {
  const checked = (event.target as HTMLInputElement).checked
  if (checked && !selectedNodeIDs.value.includes(node.id)) {
    selectedNodeIDs.value = [...selectedNodeIDs.value, node.id]
  } else if (!checked) {
    selectedNodeIDs.value = selectedNodeIDs.value.filter((id) => id !== node.id)
  }
}

function toggleSelectAll(event: Event) {
  selectedNodeIDs.value = (event.target as HTMLInputElement).checked
    ? selectableNodes.value.map((node) => node.id)
    : []
}

function clearSelection() {
  selectedNodeIDs.value = []
}

async function testSelectedNodes() {
  if (batchTesting.value || testingId.value || !selectedNodeIDs.value.length) {
    return
  }
  batchTesting.value = true
  error.value = ''
  notice.value = ''
  try {
    const response = await apiPost<ZhiziBatchTestResponse>('/zhizi/nodes/test', {
      ids: selectedNodeIDs.value,
    })
    notice.value = t('zhizi.batchTestResult', {
      succeeded: response.succeeded,
      failed: response.failed,
    })
    if (response.failed > 0) {
      error.value = t('zhizi.batchTestPartialFailure')
    }
    await load()
  } catch (testError) {
    error.value =
      testError instanceof Error ? testError.message : t('zhizi.batchTestFailed')
  } finally {
    batchTesting.value = false
  }
}

async function initializeSelectedNodes() {
  if (batchInitializing.value || batchDeleting.value || !selectedNodeIDs.value.length) {
    return
  }
  if (!window.confirm(t('zhizi.initConfirm', { count: selectedNodeIDs.value.length }))) {
    return
  }
  batchInitializing.value = true
  error.value = ''
  notice.value = ''
  try {
    const response = await apiPost<{ accepted: number; skipped: number }>(
      '/zhizi/nodes/init',
      { ids: selectedNodeIDs.value },
    )
    notice.value = t('zhizi.initStarted', {
      accepted: response.accepted,
      skipped: response.skipped,
    })
    await load()
  } catch (initError) {
    error.value = initError instanceof Error ? initError.message : t('zhizi.initFailed')
  } finally {
    batchInitializing.value = false
  }
}

async function deleteSelectedNodes() {
  if (batchDeleting.value || batchInitializing.value || !selectedNodeIDs.value.length) {
    return
  }
  if (!window.confirm(t('zhizi.deleteConfirm', { count: selectedNodeIDs.value.length }))) {
    return
  }
  batchDeleting.value = true
  error.value = ''
  notice.value = ''
  try {
    const response = await apiPost<{ deleted: number }>('/zhizi/nodes/delete', {
      ids: selectedNodeIDs.value,
    })
    notice.value = t('zhizi.deleteResult', { count: response.deleted })
    clearSelection()
    await load()
  } catch (deleteError) {
    error.value =
      deleteError instanceof Error ? deleteError.message : t('zhizi.deleteFailed')
  } finally {
    batchDeleting.value = false
  }
}

function scheduleInitPoll() {
  if (initPollTimer) {
    window.clearTimeout(initPollTimer)
    initPollTimer = undefined
  }
  if (!hasRunningInitialization.value) {
    return
  }
  initPollTimer = window.setTimeout(() => {
    initPollTimer = undefined
    void load()
  }, 3000)
}

async function disableNode(node: ZhiziNode) {
  if (!canDelete.value || !node.enabled) {
    return
  }
  if (!window.confirm(t('zhizi.disableConfirm', { name: node.name }))) {
    return
  }
  try {
    await apiDelete(`/zhizi/nodes/${node.id}`)
    notice.value = t('zhizi.disabledNotice')
    await load()
  } catch (disableError) {
    error.value = disableError instanceof Error ? disableError.message : t('zhizi.disableFailed')
  }
}

function authLabel(value: string) {
  return value === 'password' ? t('zhizi.passwordAuth') : t('zhizi.keyAuth')
}

function nodeStatusLabel(node: ZhiziNode) {
  return t(`zhizi.nodeStatus.${nodeRuntimeStatus(node)}`)
}

function initStatusLabel(status: ZhiziNode['initStatus']) {
  return t(`zhizi.initStatus.${status}`)
}

function shortFingerprint(value: string) {
  if (!value) {
    return '-'
  }
  return value.length > 26 ? `${value.slice(0, 22)}...` : value
}

function formatTime(value: string) {
  if (!value || value.startsWith('0001-')) {
    return '-'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function resetFilters() {
  filters.search = ''
  filters.status = ''
  filters.authType = ''
}

onMounted(load)
onUnmounted(() => {
  if (initPollTimer) {
    window.clearTimeout(initPollTimer)
  }
})
</script>

<template>
  <section class="page factory-page page-zhizi zhizi-page">
    <header class="page-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="teal" />
        <div>
          <p class="eyebrow">ZHIZI REMOTE EXECUTORS</p>
          <h1>{{ t('nav.zhizi') }}</h1>
          <p class="page-header-hint">{{ t('zhizi.subtitle') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          {{ t('common.refresh') }}
        </button>
        <button v-if="canWrite" class="button zhizi-primary" type="button" @click="openCreate">
          {{ t('zhizi.addNode') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>

    <div class="stat-row">
      <button class="stat-chip" type="button" @click="resetFilters">
        <small>{{ t('zhizi.totalNodes') }}</small>
        <strong>{{ nodes.length }}</strong>
      </button>
      <button class="stat-chip tone-ready" type="button" @click="filters.status = 'ready'">
        <small>{{ t('zhizi.readyNodes') }}</small>
        <strong>{{ readyNodeCount }}</strong>
      </button>
      <button class="stat-chip tone-busy" type="button" @click="filters.status = 'busy'">
        <small>{{ t('zhizi.busyNodes') }}</small>
        <strong>{{ busyNodeCount }}</strong>
      </button>
      <button class="stat-chip tone-error" type="button" @click="filters.status = 'error'">
        <small>{{ t('zhizi.errorNodes') }}</small>
        <strong>{{ errorNodeCount }}</strong>
      </button>
      <button class="stat-chip tone-slots" type="button" @click="filters.status = ''">
        <small>{{ t('zhizi.availableSlots') }}</small>
        <strong>{{ availability.available }}</strong>
      </button>
    </div>

    <div class="filter-bar zhizi-filter-bar">
      <input
        v-model="filters.search"
        type="search"
        :placeholder="t('zhizi.searchPlaceholder')"
        :aria-label="t('zhizi.searchPlaceholder')"
      />
      <select v-model="filters.status" :aria-label="t('common.status')">
        <option value="">{{ t('zhizi.allStatus') }}</option>
        <option v-for="status in ['ready', 'busy', 'error', 'unverified', 'disabled']" :key="status" :value="status">
          {{ t(`zhizi.nodeStatus.${status}`) }}
        </option>
      </select>
      <select v-model="filters.authType" :aria-label="t('zhizi.auth')">
        <option value="">{{ t('zhizi.allAuthTypes') }}</option>
        <option value="password">{{ t('zhizi.passwordAuth') }}</option>
        <option value="key">{{ t('zhizi.keyAuth') }}</option>
      </select>
      <button class="button compact" type="button" @click="resetFilters">{{ t('common.reset') }}</button>
    </div>

    <div v-if="selectedNodeIDs.length" class="batch-bar">
      <span>{{ t('zhizi.selectedCount', { count: selectedNodeIDs.length }) }}</span>
      <button
        class="button compact"
        type="button"
        :disabled="batchTesting || batchInitializing || batchDeleting || Boolean(testingId)"
        @click="testSelectedNodes"
      >
        {{ batchTesting ? t('zhizi.batchTesting') : t('zhizi.batchTest') }}
      </button>
      <button
        v-if="canWrite"
        class="button compact"
        type="button"
        :disabled="batchTesting || batchInitializing || batchDeleting"
        @click="initializeSelectedNodes"
      >
        {{ batchInitializing ? t('zhizi.initializingBatch') : t('zhizi.batchInit') }}
      </button>
      <button
        v-if="canDelete"
        class="button compact danger"
        type="button"
        :disabled="batchTesting || batchInitializing || batchDeleting"
        @click="deleteSelectedNodes"
      >
        {{ batchDeleting ? t('zhizi.deletingBatch') : t('zhizi.batchDelete') }}
      </button>
      <button
        class="text-button dark"
        type="button"
        :disabled="batchTesting || batchInitializing || batchDeleting"
        @click="clearSelection"
      >
        {{ t('zhizi.clearSelection') }}
      </button>
    </div>

    <div class="factory-table-scroll zhizi-table-wrap">
      <table class="zhizi-table">
        <thead>
          <tr>
            <th v-if="canWrite" class="check-cell">
              <input
                type="checkbox"
                :aria-label="t('zhizi.selectAll')"
                :checked="allSelectableSelected"
                :disabled="!selectableNodes.length || batchTesting"
                @change="toggleSelectAll"
              />
            </th>
            <th>{{ t('zhizi.node') }}</th>
            <th>SSH</th>
            <th>{{ t('zhizi.user') }}</th>
            <th>{{ t('zhizi.auth') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('zhizi.slots') }}</th>
            <th>{{ t('zhizi.hostKey') }}</th>
            <th>{{ t('zhizi.lastTest') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="node in filteredNodes" :key="node.id">
            <td v-if="canWrite" class="check-cell">
              <input
                type="checkbox"
                :checked="selectedNodeIDs.includes(node.id)"
                :disabled="!node.enabled || !node.hostKeyFingerprint || batchTesting"
                :aria-label="t('zhizi.selectNode', { name: node.name })"
                @change="toggleNodeSelection(node, $event)"
              />
            </td>
            <td>
              <strong class="zhizi-node-name">{{ node.name }}</strong>
              <small class="cell-hint">{{ node.id.slice(0, 10) }}</small>
              <small
                v-if="node.initStatus !== 'never'"
                class="zhizi-init-state"
                :class="`tone-${node.initStatus}`"
                :title="node.initMessage"
              >
                {{ initStatusLabel(node.initStatus) }}
              </small>
            </td>
            <td><code class="zhizi-address">{{ node.host }}:{{ node.port }}</code></td>
            <td>{{ node.username }}</td>
            <td><span class="zhizi-auth-badge">{{ authLabel(node.authType) }}</span></td>
            <td>
              <span class="zhizi-state" :class="`tone-${nodeRuntimeStatus(node)}`">
                <i></i>{{ nodeStatusLabel(node) }}
              </span>
              <small v-if="node.lastTestError" class="cell-hint zhizi-error-hint" :title="node.lastTestError">
                {{ node.lastTestError }}
              </small>
            </td>
            <td>
              <div class="zhizi-slot-meter">
                <strong>{{ node.activeSlots }} / {{ node.maxSlots }}</strong>
                <span><i :style="{ width: `${Math.min(100, (node.activeSlots / Math.max(1, node.maxSlots)) * 100)}%` }"></i></span>
              </div>
            </td>
            <td>
              <code class="zhizi-fingerprint" :title="node.hostKeyFingerprint">
                {{ shortFingerprint(node.hostKeyFingerprint) }}
              </code>
            </td>
            <td class="cell-time">{{ formatTime(node.lastTestAt) }}</td>
            <td class="row-actions">
              <button
                class="button compact"
                type="button"
                :disabled="testingId === node.id || !node.enabled || batchTesting"
                @click="testNode(node)"
              >
                {{ testingId === node.id ? t('zhizi.testing') : t('zhizi.test') }}
              </button>
              <button
                v-if="canWrite"
                class="button compact"
                type="button"
                :disabled="
                  node.activeSlots > 0 ||
                  node.initStatus === 'queued' ||
                  node.initStatus === 'running' ||
                  batchTesting
                "
                @click="openEdit(node)"
              >
                {{ t('common.edit') }}
              </button>
              <button
                v-if="canDelete && node.enabled"
                class="button compact danger"
                type="button"
                @click="disableNode(node)"
              >
                {{ t('zhizi.disable') }}
              </button>
            </td>
          </tr>
          <tr v-if="!filteredNodes.length && !loading">
            <td class="empty-cell" :colspan="canWrite ? 10 : 9">
              {{ nodes.length ? t('zhizi.noFilteredNodes') : t('zhizi.emptyHint') }}
            </td>
          </tr>
          <tr v-if="loading && !nodes.length">
            <td class="empty-cell" :colspan="canWrite ? 10 : 9">{{ t('common.loading') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <Teleport to="body">
    <div v-if="drawerOpen" class="zhizi-drawer-layer" @click.self="closeDrawer">
    <aside class="editor-drawer zhizi-drawer" role="dialog" aria-modal="true">
      <header>
        <div>
          <span class="page-code">SSH NODE</span>
          <h2>{{ editingID ? t('zhizi.editNode') : t('zhizi.addNode') }}</h2>
        </div>
        <button class="text-button dark" type="button" @click="closeDrawer">
          {{ t('common.close') }}
        </button>
      </header>
      <form @submit.prevent="saveNode">
        <div class="zhizi-auth-switch">
          <button
            type="button"
            :class="{ active: form.authType === 'password' }"
            @click="setAuthType('password')"
          >
            {{ t('zhizi.passwordAuth') }}
          </button>
          <button
            type="button"
            :class="{ active: form.authType === 'key' }"
            @click="setAuthType('key')"
          >
            {{ t('zhizi.keyAuth') }}
          </button>
        </div>
        <label>
          <span>
            {{
              form.authType === 'password' && !editingID
                ? t('zhizi.namePrefix')
                : t('zhizi.name')
            }}
          </span>
          <input v-model="form.name" maxlength="80" required />
          <small v-if="form.authType === 'password' && !editingID">
            {{ t('zhizi.batchNameHint') }}
          </small>
        </label>
        <template v-if="form.authType === 'password' && !editingID">
          <label class="zhizi-field-wide">
            <span>{{ t('zhizi.hosts') }}</span>
            <textarea
              v-model="form.host"
              rows="6"
              placeholder="10.0.0.10&#10;10.0.0.11"
              required
            ></textarea>
            <small>{{ t('zhizi.multiHostHint') }}</small>
          </label>
          <div class="zhizi-form-grid zhizi-runtime-grid">
            <label>
              <span>{{ t('zhizi.port') }}</span>
              <input v-model.number="form.port" type="number" min="1" max="65535" required />
            </label>
            <label>
              <span>{{ t('zhizi.user') }}</span>
              <input v-model="form.username" required />
            </label>
            <label>
              <span>{{ t('zhizi.maxSlots') }}</span>
              <input v-model.number="form.maxSlots" type="number" min="1" max="64" required />
            </label>
          </div>
          <label class="zhizi-field-wide">
            <span>{{ t('zhizi.password') }}</span>
            <input v-model="form.password" type="password" autocomplete="new-password" />
          </label>
        </template>
        <template v-else>
          <div class="zhizi-form-grid">
            <label>
              <span>{{ t('zhizi.host') }}</span>
              <input v-model="form.host" placeholder="10.0.0.10" required />
            </label>
            <label>
              <span>{{ t('zhizi.port') }}</span>
              <input v-model.number="form.port" type="number" min="1" max="65535" required />
            </label>
          </div>
          <div class="zhizi-form-grid">
            <label>
              <span>{{ t('zhizi.user') }}</span>
              <input v-model="form.username" required />
            </label>
            <label>
              <span>{{ t('zhizi.maxSlots') }}</span>
              <input v-model.number="form.maxSlots" type="number" min="1" max="64" required />
            </label>
          </div>
          <label v-if="form.authType === 'password'" class="zhizi-field-wide">
            <span>{{ t('zhizi.password') }}</span>
            <input
              v-model="form.password"
              type="password"
              autocomplete="new-password"
              :placeholder="editingID ? t('zhizi.secretKeepHint') : ''"
            />
          </label>
          <label v-else class="zhizi-field-wide">
            <span>{{ t('zhizi.privateKey') }}</span>
            <textarea
              v-model="form.privateKey"
              rows="7"
              spellcheck="false"
              :placeholder="editingID ? t('zhizi.secretKeepHint') : '-----BEGIN OPENSSH PRIVATE KEY-----'"
            ></textarea>
          </label>
        </template>
        <label>
          <span>{{ t('zhizi.workRoot') }}</span>
          <input v-model="form.workRoot" required />
        </label>
        <label class="zhizi-enabled-toggle">
          <input v-model="form.enabled" type="checkbox" />
          <span>{{ t('zhizi.enabled') }}</span>
        </label>
        <section v-if="hostKeyProbes.length" class="zhizi-fingerprint-panel">
          <header>
            <strong>{{ t('zhizi.hostFingerprints') }}</strong>
            <small>{{ t('zhizi.fingerprintConfirmHint') }}</small>
          </header>
          <ul>
            <li v-for="item in hostKeyProbes" :key="item.host">
              <span>
                <strong>{{ item.host }}:{{ item.port }}</strong>
                <small>{{ item.algorithm }}</small>
              </span>
              <code>{{ item.fingerprint }}</code>
            </li>
          </ul>
          <p>{{ t('zhizi.fingerprintSecurityHint') }}</p>
        </section>
        <footer>
          <button class="button" type="submit" :disabled="saving || probing">
            {{
              probing
                ? t('zhizi.probingFingerprint')
                : hostKeyProbes.length
                  ? t('zhizi.confirmFingerprintAndSave')
                  : t('zhizi.probeFingerprint')
            }}
          </button>
          <button class="text-button dark" type="button" @click="closeDrawer">
            {{ t('common.cancel') }}
          </button>
        </footer>
      </form>
    </aside>
    </div>
    </Teleport>
  </section>
</template>

<style scoped>
.page-zhizi {
  --zhizi-accent: #14b8a6;
  --zhizi-accent-soft: color-mix(in srgb, #14b8a6 10%, transparent);
  display: grid;
  gap: 14px;
}

.page-zhizi .page-header {
  min-height: 78px;
  padding: 14px 16px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--surface);
}

.page-zhizi .page-header-hint,
.cell-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.header-actions,
.row-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.zhizi-primary {
  border-color: color-mix(in srgb, var(--zhizi-accent) 55%, var(--border)) !important;
  color: var(--zhizi-accent) !important;
  background: var(--zhizi-accent-soft) !important;
}

.stat-row {
  display: grid;
  grid-template-columns: repeat(5, minmax(120px, 1fr));
  gap: 10px;
}

.stat-chip {
  display: grid;
  gap: 4px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--text-muted);
  border-radius: 4px;
  color: var(--text-primary);
  background: var(--surface);
  text-align: left;
  cursor: pointer;
}

.stat-chip small {
  color: var(--text-muted);
  font-size: 12px;
}

.stat-chip strong {
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.stat-chip.tone-ready { border-left-color: var(--success); }
.stat-chip.tone-busy { border-left-color: var(--warning); }
.stat-chip.tone-error { border-left-color: var(--danger); }
.stat-chip.tone-slots { border-left-color: var(--zhizi-accent); }

.filter-bar,
.batch-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--line);
  background: var(--surface);
}

.filter-bar input {
  flex: 2 1 260px;
}

.filter-bar select {
  flex: 1 1 180px;
}

.filter-bar input,
.filter-bar select {
  min-height: 36px;
  padding: 7px 9px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-primary);
  background: var(--field-bg);
}

.batch-bar {
  border-left: 3px solid var(--zhizi-accent);
}

.batch-bar > span {
  margin-right: auto;
  color: var(--text-secondary);
  font-size: 12px;
}

.zhizi-table-wrap {
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--surface);
}

.zhizi-table {
  width: 100%;
  min-width: 1240px;
  border-collapse: collapse;
}

.zhizi-table th,
.zhizi-table td {
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 12px;
  vertical-align: middle;
}

.zhizi-table th {
  color: var(--text-secondary);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 700;
  white-space: nowrap;
}

.zhizi-table tbody tr:hover {
  background: color-mix(in srgb, var(--zhizi-accent) 4%, transparent);
}

.zhizi-table tbody tr:last-child td {
  border-bottom: 0;
}

.check-cell {
  width: 34px;
  text-align: center !important;
}

.check-cell input {
  width: 15px;
  height: 15px;
  accent-color: var(--zhizi-accent);
}

.zhizi-node-name {
  display: block;
  font-size: 13px;
}

.zhizi-init-state {
  display: block;
  margin-top: 3px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  text-transform: uppercase;
}

.zhizi-init-state.tone-queued,
.zhizi-init-state.tone-running {
  color: var(--warning);
}

.zhizi-init-state.tone-succeeded {
  color: var(--success);
}

.zhizi-init-state.tone-failed {
  color: var(--danger);
}

.zhizi-address,
.zhizi-fingerprint {
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 11px;
}

.zhizi-fingerprint {
  display: block;
  max-width: 190px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.zhizi-auth-badge {
  display: inline-flex;
  padding: 3px 7px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  background: var(--field-bg);
  font-size: 11px;
  white-space: nowrap;
}

.zhizi-state {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--text-muted);
  font-size: 11px;
  white-space: nowrap;
}

.zhizi-state i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 5px color-mix(in srgb, currentColor 50%, transparent);
}

.zhizi-state.tone-ready { color: var(--success); }
.zhizi-state.tone-busy { color: var(--warning); }
.zhizi-state.tone-error { color: var(--danger); }
.zhizi-state.tone-unverified { color: #f0a43a; }

.zhizi-error-hint {
  display: block;
  max-width: 190px;
  overflow: hidden;
  color: var(--danger);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.zhizi-slot-meter {
  display: grid;
  grid-template-columns: 38px 64px;
  align-items: center;
  gap: 7px;
}

.zhizi-slot-meter strong {
  font-family: var(--mono);
  font-size: 11px;
}

.zhizi-slot-meter > span {
  height: 5px;
  overflow: hidden;
  border: 1px solid var(--border);
  background: var(--surface-soft);
}

.zhizi-slot-meter i {
  display: block;
  height: 100%;
  background: var(--zhizi-accent);
}

.cell-time {
  color: var(--text-muted);
  white-space: nowrap;
}

.empty-cell {
  padding: 32px 12px !important;
  color: var(--text-muted);
  text-align: center !important;
}

.zhizi-drawer-layer {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: flex;
  justify-content: flex-end;
  background: rgb(0 0 0 / 42%);
}

.zhizi-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  width: min(680px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -12px 0 32px rgb(0 0 0 / 18%);
}

.zhizi-drawer > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.zhizi-drawer h2 {
  margin: 4px 0 0;
  font-size: 18px;
}

.zhizi-drawer form {
  display: grid;
  align-content: start;
  gap: 14px;
  padding: 18px 20px 28px;
  overflow: auto;
}

.zhizi-drawer label {
  display: grid;
  gap: 6px;
  align-content: start;
}

.zhizi-drawer label > span {
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 700;
}

.zhizi-drawer label > small {
  color: var(--text-muted);
  font-size: 10px;
  font-weight: 400;
  line-height: 1.5;
}

.zhizi-drawer input,
.zhizi-drawer select,
.zhizi-drawer textarea {
  width: 100%;
}

.zhizi-drawer input:not([type='checkbox']),
.zhizi-drawer select {
  height: 40px;
  min-height: 40px;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 3px;
  font-size: 13px;
}

.zhizi-drawer textarea {
  min-height: 112px;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: 3px;
  font-size: 13px;
  line-height: 1.5;
}

.zhizi-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.zhizi-form-grid > label {
  align-self: start;
}

.zhizi-runtime-grid {
  grid-template-columns: 110px minmax(0, 1fr) 120px;
}

.zhizi-field-wide {
  width: 100%;
}

.zhizi-auth-switch {
  display: grid;
  grid-template-columns: 1fr 1fr;
  border: 1px solid var(--border);
}

.zhizi-auth-switch button {
  min-height: 42px;
  border: 0;
  padding: 10px 12px;
  color: var(--text-secondary);
  background: var(--surface-soft);
  cursor: pointer;
  font-size: 13px;
}

.zhizi-auth-switch button + button {
  border-left: 1px solid var(--border);
}

.zhizi-auth-switch button.active {
  color: var(--zhizi-accent);
  background: var(--surface);
  box-shadow: inset 0 -2px 0 var(--zhizi-accent);
}

.zhizi-enabled-toggle {
  display: flex !important;
  align-items: center;
  gap: 8px;
}

.zhizi-enabled-toggle input {
  width: auto;
}

.zhizi-fingerprint-panel {
  display: grid;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--warning);
  background: color-mix(in srgb, var(--warning) 5%, var(--surface));
}

.zhizi-fingerprint-panel header {
  display: grid;
  gap: 4px;
}

.zhizi-fingerprint-panel header small,
.zhizi-fingerprint-panel p {
  color: var(--text-muted);
  font-size: 10px;
  line-height: 1.5;
}

.zhizi-fingerprint-panel ul {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.zhizi-fingerprint-panel li {
  display: grid;
  gap: 4px;
  padding: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
}

.zhizi-fingerprint-panel li > span {
  display: flex;
  justify-content: space-between;
  gap: 10px;
}

.zhizi-fingerprint-panel code {
  overflow-wrap: anywhere;
  font-size: 10px;
}

.zhizi-drawer footer {
  position: sticky;
  bottom: -28px;
  display: flex;
  gap: 10px;
  margin: 4px -20px -28px;
  padding: 14px 20px;
  border-top: 1px solid var(--line);
  background: var(--surface-soft);
}

@media (max-width: 900px) {
  .stat-row {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .header-actions {
    align-items: flex-end;
    flex-direction: column;
  }

  .filter-bar {
    align-items: stretch;
    flex-direction: column;
  }

  .filter-bar input,
  .filter-bar select,
  .filter-bar button {
    flex: 1 1 auto;
    width: 100%;
  }

  .stat-row,
  .zhizi-form-grid,
  .zhizi-runtime-grid {
    grid-template-columns: 1fr;
  }

  .zhizi-drawer {
    width: 100%;
  }
}
</style>
