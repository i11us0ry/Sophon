<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'

const { t } = useI18n()

interface MCPServer {
  id: string
  name: string
  transport: string
  command: string
  args: string[]
  env: Record<string, string>
  url: string
  description: string
  enabled: boolean
  status: string
  lastError: string
  toolCount: number
  builtin: boolean
}

interface TestResult {
  status: string
  message?: string
  tools?: string[]
  toolCount?: number
}

interface MCPToolParameter {
  name: string
  type: string
  description: string
  required: boolean
  enum?: string[]
}

interface AgentToolItem {
  name: string
  qualifiedName?: string
  serverName?: string
  kind: 'builtin' | 'mcp'
  exposure: 'direct' | 'searchable'
  description: string
  capability: string
  enabled: boolean
  toggleable: boolean
  parameters: MCPToolParameter[]
}

interface AgentToolInventory {
  direct: AgentToolItem[]
  searchable: AgentToolItem[]
  discovery: { searchTool: string; useTool: string; registered: number }
}

interface ToolSection {
  key: string
  title: string
  hint: string
  empty: string
  visible: number
  total: number
  items: AgentToolItem[]
}

interface MCPDoctorItem {
  serverName: string
  tool: string
  enabled: boolean
  registered: boolean
  status: string
  detail: string
}

interface MCPDoctorSummary {
  total: number
  available: number
  missingBinary: number
  missingDependency: number
  disabled: number
  serverError: number
}

const STATUS_LABELS: Record<string, string> = {
  connected: t('mcp.statusConnected'),
  error: t('mcp.statusError'),
  unknown: t('mcp.statusUnknown'),
  unsupported: t('mcp.statusUnsupported'),
}

const servers = ref<MCPServer[]>([])
const editingId = ref('')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const testResult = ref<TestResult | null>(null)
const directTools = ref<AgentToolItem[]>([])
const searchableTools = ref<AgentToolItem[]>([])
const discovery = ref({ searchTool: 'mcp_search_tools', useTool: 'mcp_use_tool', registered: 0 })
const toolSearch = ref('')
const toolStatus = ref<'' | 'enabled' | 'disabled'>('')
const toolSource = ref('')
const toolSaving = ref(false)
const toolBaseline = ref<Record<string, string>>({})
const expandedTools = ref<string[]>([])
const doctorRunning = ref(false)
const doctorItems = ref<MCPDoctorItem[]>([])
const doctorSummary = ref<MCPDoctorSummary | null>(null)
const doctorOnlyProblems = ref(true)
const activeTab = ref<'servers' | 'tools'>('servers')
const activeServerId = ref('')
const serverSearch = ref('')
const serverHealth = ref<'' | 'online' | 'issues' | 'disabled'>('')
const toolMode = ref<'all' | 'direct' | 'searchable'>('all')
const doctorOpen = ref(false)
const editorOpen = ref(false)

const toolItems = computed(() => [...directTools.value, ...searchableTools.value])
const editingServer = computed(
  () => servers.value.find((server) => server.id === editingId.value) ?? null,
)

const filteredServers = computed(() => {
  const keyword = serverSearch.value.trim().toLowerCase()
  return servers.value.filter((server) => {
    if (keyword) {
      const haystack =
        `${server.name} ${server.transport} ${server.command} ${server.description}`.toLowerCase()
      if (!haystack.includes(keyword)) {
        return false
      }
    }
    if (serverHealth.value === 'online') {
      return server.enabled && server.status === 'connected'
    }
    if (serverHealth.value === 'issues') {
      return server.enabled && server.status !== 'connected'
    }
    if (serverHealth.value === 'disabled') {
      return !server.enabled
    }
    return true
  })
})

const serverStats = computed(() => {
  const total = servers.value.length
  const online = servers.value.filter(
    (server) => server.enabled && server.status === 'connected',
  ).length
  const issues = servers.value.filter(
    (server) => server.enabled && server.status !== 'connected',
  ).length
  const disabled = servers.value.filter((server) => !server.enabled).length
  const toolCount = servers.value.reduce((totalTools, server) => totalTools + server.toolCount, 0)
  return { total, online, issues, disabled, toolCount }
})

const toolSources = computed(() => {
  const names = new Set(
    toolItems.value.map((item) => item.serverName).filter((name): name is string => Boolean(name)),
  )
  return Array.from(names).sort()
})

function matchesToolFilters(item: AgentToolItem) {
  const keyword = toolSearch.value.trim().toLowerCase()
  if (toolStatus.value === 'enabled' && !item.enabled) {
    return false
  }
  if (toolStatus.value === 'disabled' && item.enabled) {
    return false
  }
  if (toolSource.value && item.serverName !== toolSource.value) {
    return false
  }
  if (keyword) {
    const haystack = `${item.name} ${item.qualifiedName ?? ''} ${item.description}`.toLowerCase()
    if (!haystack.includes(keyword)) {
      return false
    }
  }
  return true
}

const filteredDirectTools = computed(() => directTools.value.filter(matchesToolFilters))
const filteredSearchableTools = computed(() => searchableTools.value.filter(matchesToolFilters))

const toolSections = computed<ToolSection[]>(() => {
  const searchTool = discovery.value.searchTool || 'mcp_search_tools'
  const useTool = discovery.value.useTool || 'mcp_use_tool'
  const sections = [
    {
      key: 'direct',
      title: t('mcp.directTools'),
      hint: t('mcp.directToolsHint'),
      empty: t('mcp.directToolsEmpty'),
      visible: filteredDirectTools.value.length,
      total: directTools.value.length,
      items: filteredDirectTools.value,
    },
    {
      key: 'searchable',
      title: t('mcp.searchableTools'),
      hint: t('mcp.searchableToolsHint', {
        tool: searchTool,
        use: useTool,
        count: discovery.value.registered,
      }),
      empty: t('mcp.searchableToolsEmpty'),
      visible: filteredSearchableTools.value.length,
      total: searchableTools.value.length,
      items: filteredSearchableTools.value,
    },
  ]
  if (toolMode.value === 'all') {
    return sections
  }
  return sections.filter((section) => section.key === toolMode.value)
})

const toolStats = computed(() => {
  const total = toolItems.value.length
  const enabled = toolItems.value.filter((item) => item.enabled).length
  return { total, enabled, disabled: total - enabled }
})

const toolDirty = computed(() =>
  toolItems.value.some(
    (item) => item.toggleable && toolBaseline.value[toolKey(item)] !== toolState(item),
  ),
)

const capabilityOptions = computed(() => [
  { value: 'passive', label: t('mcp.capabilityPassive') },
  { value: 'read', label: t('mcp.capabilityRead') },
  { value: 'intrusive', label: t('mcp.capabilityIntrusive') },
  { value: 'destructive', label: t('mcp.capabilityDestructive') },
])

const visibleDoctorItems = computed(() => {
  if (!doctorOnlyProblems.value) {
    return doctorItems.value
  }
  return doctorItems.value.filter(
    (item) => item.status !== 'available' && item.status !== 'disabled',
  )
})

const draft = reactive({
  name: '',
  transport: 'stdio',
  command: '',
  argsText: '',
  envText: '',
  url: '',
  description: '',
  enabled: true,
})

function statusLabel(server: MCPServer) {
  if (!server.enabled) {
    return t('mcp.statusDisabled')
  }
  return STATUS_LABELS[server.status] ?? server.status
}

function serverTone(server: MCPServer) {
  if (!server.enabled) {
    return 'disabled'
  }
  if (server.status === 'connected') {
    return 'online'
  }
  if (server.status === 'error' || server.status === 'unsupported') {
    return 'error'
  }
  return 'unknown'
}

function serverEndpoint(server: MCPServer) {
  if (server.transport === 'sse') {
    return server.url || '-'
  }
  const command = [server.command, ...(server.args ?? [])].filter(Boolean).join(' ')
  return command || '-'
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<{ items: MCPServer[] }>('/mcp/servers')
    servers.value = response.items ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readMcpFailed')
  } finally {
    loading.value = false
  }
}

async function loadTools() {
  try {
    const response = await apiGet<AgentToolInventory>('/mcp/agent-tools')
    const normalize = (item: AgentToolItem): AgentToolItem => ({
      ...item,
      parameters: item.parameters ?? [],
    })
    directTools.value = (response.direct ?? []).map(normalize)
    searchableTools.value = (response.searchable ?? []).map(normalize)
    discovery.value =
      response.discovery ?? { searchTool: 'mcp_search_tools', useTool: 'mcp_use_tool', registered: 0 }
    toolBaseline.value = Object.fromEntries(
      toolItems.value
        .filter((item) => item.toggleable)
        .map((item) => [toolKey(item), toolState(item)]),
    )
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readMcpFailed')
  }
}

function toolKey(item: AgentToolItem) {
  return item.qualifiedName || item.name
}

function toolState(item: AgentToolItem) {
  return `${item.enabled ? '1' : '0'}:${item.capability}`
}

function isExpanded(item: AgentToolItem) {
  return expandedTools.value.includes(toolKey(item))
}

function toggleExpand(item: AgentToolItem) {
  const key = toolKey(item)
  if (isExpanded(item)) {
    expandedTools.value = expandedTools.value.filter((value) => value !== key)
    return
  }
  expandedTools.value = [...expandedTools.value, key]
}

function toggleTool(item: AgentToolItem) {
  if (!item.toggleable) {
    return
  }
  item.enabled = !item.enabled
}

function capabilityLabel(value: string) {
  return capabilityOptions.value.find((option) => option.value === value)?.label ?? value
}

function toolSourceLabel(item: AgentToolItem) {
  if (item.kind === 'builtin') {
    return t('mcp.builtinTool')
  }
  return item.serverName || t('mcp.builtinTool')
}

function filterByServer(name: string) {
  activeTab.value = 'tools'
  toolSource.value = toolSource.value === name ? '' : name
}

async function saveTools() {
  toolSaving.value = true
  error.value = ''
  notice.value = ''
  try {
    await apiPut('/mcp/tools', {
      items: toolItems.value
        .filter((item) => item.toggleable && item.serverName)
        .map((item) => ({
          serverName: item.serverName,
          toolName: item.name,
          enabled: item.enabled,
          capability: item.capability,
        })),
    })
    notice.value = t('mcp.toolConfigSaved')
    await loadTools()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  } finally {
    toolSaving.value = false
  }
}

async function runDoctor() {
  doctorRunning.value = true
  doctorOpen.value = true
  doctorSummary.value = null
  doctorItems.value = []
  error.value = ''
  try {
    const response = await apiPost<{ summary: MCPDoctorSummary; items: MCPDoctorItem[] }>(
      '/mcp/tools/doctor',
    )
    doctorSummary.value = response.summary
    doctorItems.value = response.items ?? []
    doctorOpen.value = true
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
    doctorOpen.value = false
  } finally {
    doctorRunning.value = false
  }
}

function openDoctor() {
  closeEditor()
  void runDoctor()
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

function resetDraft() {
  draft.name = ''
  draft.transport = 'stdio'
  draft.command = ''
  draft.argsText = ''
  draft.envText = ''
  draft.url = ''
  draft.description = ''
  draft.enabled = true
}

function switchTab(tab: 'servers' | 'tools') {
  activeTab.value = tab
  if (tab === 'tools') {
    doctorOpen.value = false
  }
}

function closeEditor() {
  resetDraft()
  editingId.value = ''
  activeServerId.value = ''
  editorOpen.value = false
}

function closeDoctor() {
  doctorOpen.value = false
}

function openCreate() {
  activeTab.value = 'servers'
  activeServerId.value = ''
  doctorOpen.value = false
  editorOpen.value = true
  editingId.value = ''
  resetDraft()
}

function openEditor(server: MCPServer) {
  activeTab.value = 'servers'
  activeServerId.value = server.id
  doctorOpen.value = false
  editorOpen.value = true
  editingId.value = server.id
  draft.name = server.name
  draft.transport = server.transport || 'stdio'
  draft.command = server.command
  draft.argsText = (server.args ?? []).join('\n')
  draft.envText = Object.entries(server.env ?? {})
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
  draft.url = server.url
  draft.description = server.description
  draft.enabled = server.enabled
}

function parseArgs() {
  return draft.argsText
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

function parseEnv() {
  const result: Record<string, string> = {}
  draft.envText
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.includes('='))
    .forEach((line) => {
      const index = line.indexOf('=')
      result[line.slice(0, index).trim()] = line.slice(index + 1).trim()
    })
  return result
}

function payload() {
  return {
    name: draft.name.trim(),
    transport: draft.transport,
    command: draft.command.trim(),
    args: parseArgs(),
    env: parseEnv(),
    url: draft.url.trim(),
    description: draft.description.trim(),
    enabled: draft.enabled,
  }
}

function save() {
  if (!draft.name.trim()) {
    error.value = t('message.serverNameRequired')
    return
  }
  void run(async () => {
    if (editingId.value) {
      await apiPut(`/mcp/servers/${editingId.value}`, payload())
    } else {
      await apiPost('/mcp/servers', payload())
    }
    editingId.value = ''
    activeServerId.value = ''
    editorOpen.value = false
    resetDraft()
    await load()
  }, t('mcp.saved'))
}

function toggle(server: MCPServer) {
  void run(async () => {
    await apiPut(`/mcp/servers/${server.id}`, {
      name: server.name,
      transport: server.transport,
      command: server.command,
      args: server.args,
      env: server.env,
      url: server.url,
      description: server.description,
      enabled: !server.enabled,
    })
    await load()
  }, t('mcp.stateUpdated'))
}

function remove(server: MCPServer) {
  if (!window.confirm(t('mcp.confirmDelete', { name: server.name }))) {
    return
  }
  void run(async () => {
    await apiDelete(`/mcp/servers/${server.id}`)
    if (activeServerId.value === server.id) {
      activeServerId.value = ''
    }
    await load()
  }, t('mcp.deleted'))
}

function test(server: MCPServer) {
  testResult.value = null
  void run(async () => {
    testResult.value = await apiPost<TestResult>(`/mcp/servers/${server.id}/test`)
    await load()
  })
}

onMounted(() => {
  void load()
  void loadTools()
})
</script>

<template>
  <section class="page factory-page page-mcp mcp-control">
    <header class="page-header mcp-command-header">
      <div class="mcp-heading page-heading-with-robot">
        <PageTitleRobot tone="cyan" />
        <div>
          <p class="eyebrow">MCP FLOOR // ROBOT LINK</p>
          <h1>{{ t('mcp.controlCenter') }}</h1>
          <p class="mcp-page-hint">{{ t('mcp.controlHint') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button
          class="icon-button mcp-header-icon"
          type="button"
          :title="t('common.refresh')"
          :aria-label="t('common.refresh')"
          :disabled="loading"
          @click="load"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 11a8 8 0 1 0-2.34 5.66" />
            <path d="M20 4v7h-7" />
          </svg>
        </button>
        <button class="button" type="button" :disabled="doctorRunning" @click="openDoctor">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M14.7 6.3a4 4 0 0 0-5 5L3 18l3 3 6.7-6.7a4 4 0 0 0 5-5l-2.8 2.8-3-3z" />
          </svg>
          {{ doctorRunning ? t('mcp.doctorRunning') : t('mcp.inspectionBay') }}
        </button>
        <button class="button mcp-primary-button" type="button" @click="openCreate">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 5v14M5 12h14" />
          </svg>
          {{ t('mcp.connectRobot') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error mcp-alert">{{ error }}</div>
    <div v-if="notice" class="alert ok mcp-alert">{{ notice }}</div>
    <div
      v-if="testResult"
      class="alert mcp-test-banner"
      :class="testResult.status === 'connected' ? 'ok' : 'error'"
    >
      <span class="mcp-test-led" aria-hidden="true"></span>
      <strong>{{ t('mcp.testResult', { status: STATUS_LABELS[testResult.status] ?? testResult.status }) }}</strong>
      <span v-if="testResult.message">{{ testResult.message }}</span>
      <span v-if="testResult.tools?.length">
        {{ t('mcp.testTools', { count: testResult.tools.length, tools: testResult.tools.join(', ') }) }}
      </span>
    </div>

    <section class="mcp-status-rail" aria-label="MCP overview">
      <div class="mcp-stat">
        <small>
          <svg class="mcp-stat-glyph" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="5" y="7" width="14" height="12" rx="3" />
            <path d="M12 3v4M9 12h.01M15 12h.01M9 16h6" />
          </svg>
          {{ t('mcp.robotFleet') }}
        </small>
        <strong>{{ serverStats.total }}</strong>
      </div>
      <div class="mcp-stat tone-online">
        <small>
          <svg class="mcp-stat-glyph" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 11a10 10 0 0 1 16 0" />
            <path d="M7 14a6 6 0 0 1 10 0" />
            <path d="M10 17a2 2 0 0 1 4 0" />
            <circle cx="12" cy="20" r="1" />
          </svg>
          {{ t('mcp.online') }}
        </small>
        <strong>{{ serverStats.online }}</strong>
      </div>
      <div class="mcp-stat tone-tools">
        <small>
          <svg class="mcp-stat-glyph" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M14.7 6.3a4 4 0 0 0-5 5L3 18l3 3 6.7-6.7a4 4 0 0 0 5-5l-2.8 2.8-3-3 2.8-2.8Z" />
          </svg>
          {{ t('mcp.toolInventory') }}
        </small>
        <strong>{{ toolStats.total }}</strong>
      </div>
      <div class="mcp-stat" :class="serverStats.issues ? 'tone-error' : 'tone-muted'">
        <small>
          <svg class="mcp-stat-glyph" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M9 4h6l1 2h3v16H5V6h3l1-2Z" />
            <path d="M12 10v4M12 17h.01" />
          </svg>
          {{ t('mcp.attention') }}
        </small>
        <strong>{{ serverStats.issues }}</strong>
      </div>
      <div class="mcp-status-track" aria-hidden="true">
        <i></i><i></i><i></i><i></i><i></i>
      </div>
    </section>

    <nav class="mcp-tabs" :aria-label="t('mcp.controlCenter')">
      <button
        type="button"
        class="mcp-tab"
        :class="{ active: activeTab === 'servers' }"
        @click="switchTab('servers')"
      >
        <span class="mcp-tab-icon">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="7" width="16" height="12" rx="3" />
            <path d="M12 3v4M9 12h.01M15 12h.01M9 16h6" />
          </svg>
        </span>
        <span>
          <strong>{{ t('mcp.robotFleet') }}</strong>
          <small>{{ t('mcp.robotFleetHint') }}</small>
        </span>
        <b>{{ serverStats.total }}</b>
      </button>
      <button
        type="button"
        class="mcp-tab"
        :class="{ active: activeTab === 'tools' }"
        @click="switchTab('tools')"
      >
        <span class="mcp-tab-icon">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 7h16v13H4zM8 7V4h8v3M8 12h8M8 16h5" />
          </svg>
        </span>
        <span>
          <strong>{{ t('mcp.toolRack') }}</strong>
          <small>{{ t('mcp.toolRackHint') }}</small>
        </span>
        <b>{{ toolStats.total }}</b>
      </button>
    </nav>

    <section v-if="activeTab === 'servers'" class="mcp-fleet-layout">
      <div class="mcp-fleet-panel">
        <header class="mcp-floor-header">
          <div>
            <span class="mcp-floor-code">01 // ROBOT FLEET</span>
            <h2>{{ t('mcp.robotFleet') }}</h2>
          </div>
          <div class="mcp-server-tools">
            <label class="mcp-search-box">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="11" cy="11" r="6" />
                <path d="m16 16 4 4" />
              </svg>
              <input
                v-model="serverSearch"
                type="search"
                :placeholder="t('mcp.serverSearchPlaceholder')"
              />
            </label>
            <div class="mcp-segmented">
              <button type="button" :class="{ active: serverHealth === '' }" @click="serverHealth = ''">
                {{ t('mcp.healthAll') }}
              </button>
              <button
                type="button"
                :class="{ active: serverHealth === 'online' }"
                @click="serverHealth = 'online'"
              >
                {{ t('mcp.healthOnline') }}
              </button>
              <button
                type="button"
                :class="{ active: serverHealth === 'issues' }"
                @click="serverHealth = 'issues'"
              >
                {{ t('mcp.healthIssues') }}
              </button>
              <button
                type="button"
                :class="{ active: serverHealth === 'disabled' }"
                @click="serverHealth = 'disabled'"
              >
                {{ t('mcp.healthDisabled') }}
              </button>
            </div>
          </div>
        </header>

        <div v-if="filteredServers.length" class="robot-fleet-list">
          <article
            v-for="server in filteredServers"
            :key="server.id"
            class="robot-service-row"
            :class="[
              `tone-${serverTone(server)}`,
              { 'is-active': activeServerId === server.id, 'is-disabled': !server.enabled },
            ]"
          >
            <button class="robot-service-main" type="button" @click="openEditor(server)">
              <span class="robot-dock" aria-hidden="true"><i></i></span>
              <span class="robot-avatar" aria-hidden="true">
                <i class="robot-antenna"></i>
                <i class="robot-face"><b></b><b></b><em></em></i>
                <i class="robot-body"></i>
              </span>
              <span class="robot-identity">
                <span class="robot-name-line">
                  <strong>{{ server.name }}</strong>
                  <span v-if="server.builtin" class="mcp-lock-badge">{{ t('mcp.builtin') }}</span>
                </span>
                <small>{{ server.transport || 'stdio' }} · {{ server.description || serverEndpoint(server) }}</small>
              </span>
              <code class="robot-endpoint" :title="serverEndpoint(server)">{{ serverEndpoint(server) }}</code>
              <span class="robot-load">
                <strong>{{ server.toolCount }}</strong>
                <small>{{ t('mcp.toolInventory') }}</small>
              </span>
              <span class="robot-state" :class="`tone-${serverTone(server)}`">
                <i></i>{{ statusLabel(server) }}
              </span>
            </button>
            <div class="robot-actions" :aria-label="t('mcp.robotActions')">
              <button class="mcp-icon-action" type="button" :title="t('mcp.test')" @click="test(server)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="m13 2-9 12h7l-1 8 9-12h-7z" />
                </svg>
              </button>
              <button class="mcp-icon-action" type="button" :title="t('common.edit')" @click="openEditor(server)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="m4 20 4.5-1 10-10-3.5-3.5-10 10zM13.5 7l3.5 3.5" />
                </svg>
              </button>
              <button class="mcp-icon-action" type="button" :title="server.enabled ? t('common.disable') : t('common.enable')" @click="toggle(server)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 2v9M6.3 5.8a8 8 0 1 0 11.4 0" />
                </svg>
              </button>
              <button class="mcp-icon-action danger" type="button" :disabled="server.builtin" :title="t('common.delete')" @click="remove(server)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" />
                </svg>
              </button>
            </div>
            <button class="robot-tool-link" type="button" @click="filterByServer(server.name)">
              {{ server.toolCount }} {{ t('mcp.toolInventory') }} →
            </button>
            <p v-if="server.lastError" class="robot-error">{{ server.lastError }}</p>
          </article>
        </div>
        <div v-else class="mcp-empty-state">
          <span class="empty-robot" aria-hidden="true"><i></i><b></b><b></b></span>
          <strong>{{ serverSearch || serverHealth ? t('mcp.noServers') : t('mcp.empty') }}</strong>
        </div>
      </div>

      <aside class="mcp-fleet-rail">
        <section class="mcp-rail-block">
          <span class="mcp-floor-code">LINK STATUS</span>
          <h3>{{ t('mcp.robotFleet') }}</h3>
          <div class="mcp-legend">
            <span class="tone-online"><i></i>{{ t('mcp.statusConnected') }}</span>
            <span class="tone-unknown"><i></i>{{ t('mcp.statusUnknown') }}</span>
            <span class="tone-error"><i></i>{{ t('mcp.statusError') }}</span>
            <span class="tone-disabled"><i></i>{{ t('mcp.statusDisabled') }}</span>
          </div>
          <div class="mcp-rail-meter">
            <span
              :style="{ width: `${serverStats.total ? Math.round((serverStats.online / serverStats.total) * 100) : 0}%` }"
            ></span>
          </div>
          <small>{{ serverStats.online }} / {{ serverStats.total }} {{ t('mcp.online') }}</small>
        </section>
        <section class="mcp-rail-block mcp-discovery-mini">
          <span class="mcp-floor-code">TOOLCHAIN</span>
          <h3>{{ t('mcp.searchFlow') }}</h3>
          <p>{{ t('mcp.searchFlowHint') }}</p>
          <div class="mcp-mini-chain">
            <code>{{ discovery.searchTool }}</code>
            <i>→</i>
            <code>{{ discovery.useTool }}</code>
          </div>
          <button class="button compact" type="button" @click="switchTab('tools')">
            {{ t('mcp.toolRack') }}
          </button>
        </section>
      </aside>
    </section>

    <section v-else class="mcp-tool-floor">
      <header class="mcp-discovery-track">
        <div class="mcp-discovery-copy">
          <span class="mcp-floor-code">02 // TOOL LOADOUT</span>
          <h2>{{ t('mcp.toolRack') }}</h2>
          <p>{{ t('mcp.searchFlowHint') }}</p>
        </div>
        <div class="mcp-chain">
          <span class="mcp-chain-node search">
            <i></i>
            <code>{{ discovery.searchTool }}</code>
          </span>
          <span class="mcp-chain-track" aria-hidden="true"><b></b></span>
          <span class="mcp-chain-node use">
            <i></i>
            <code>{{ discovery.useTool }}</code>
          </span>
          <span class="mcp-chain-count">{{ discovery.registered }} MCP</span>
        </div>
      </header>

      <section class="mcp-rack-panel">
        <header class="mcp-rack-header">
          <div>
            <h3>{{ t('mcp.toolConfig') }}</h3>
            <span>{{ t('mcp.toolStats', { total: toolStats.total, enabled: toolStats.enabled, disabled: toolStats.disabled }) }}</span>
          </div>
          <div class="mcp-rack-actions">
            <span v-if="toolDirty" class="mcp-dirty-led">{{ t('mcp.filterEnabled') }}</span>
            <button class="button" type="button" :disabled="toolSaving || !toolDirty" @click="saveTools">
              {{ toolSaving ? t('common.saving') : t('mcp.saveToolConfig') }}
            </button>
          </div>
        </header>

        <div class="mcp-rack-toolbar">
          <label class="mcp-search-box">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="6" />
              <path d="m16 16 4 4" />
            </svg>
            <input v-model="toolSearch" type="search" :placeholder="t('mcp.toolSearchPlaceholder')" />
          </label>
          <div class="mcp-segmented">
            <button type="button" :class="{ active: toolMode === 'all' }" @click="toolMode = 'all'">
              {{ t('mcp.toolModeAll') }}
            </button>
            <button type="button" :class="{ active: toolMode === 'direct' }" @click="toolMode = 'direct'">
              {{ t('mcp.toolModeDirect') }}
            </button>
            <button type="button" :class="{ active: toolMode === 'searchable' }" @click="toolMode = 'searchable'">
              {{ t('mcp.toolModeSearchable') }}
            </button>
          </div>
          <div class="mcp-segmented compact">
            <button type="button" :class="{ active: toolStatus === '' }" @click="toolStatus = ''">
              {{ t('mcp.filterAll') }}
            </button>
            <button type="button" :class="{ active: toolStatus === 'enabled' }" @click="toolStatus = 'enabled'">
              {{ t('mcp.filterEnabled') }}
            </button>
            <button type="button" :class="{ active: toolStatus === 'disabled' }" @click="toolStatus = 'disabled'">
              {{ t('mcp.filterDisabled') }}
            </button>
          </div>
          <select
            v-model="toolSource"
            class="tool-source"
            :aria-label="t('mcp.toolSourceLabel')"
          >
            <option value="">{{ t('mcp.toolSourceAll') }}</option>
            <option v-for="source in toolSources" :key="source" :value="source">{{ source }}</option>
          </select>
        </div>

        <section v-for="section in toolSections" :key="section.key" class="mcp-tool-section">
          <header class="mcp-tool-section-head">
            <div>
              <span class="mcp-tool-section-mark" :class="section.key"></span>
              <h3>{{ section.title }}</h3>
              <b>{{ t('mcp.toolSectionCount', { visible: section.visible, total: section.total }) }}</b>
            </div>
            <p>{{ section.hint }}</p>
          </header>
          <div v-if="section.items.length" class="mcp-tool-list">
            <article
              v-for="item in section.items"
              :key="toolKey(item)"
              class="mcp-tool-row"
              :class="{ 'is-disabled': item.toggleable && !item.enabled, expanded: isExpanded(item) }"
            >
              <div class="mcp-tool-row-main">
                <span class="mcp-equipment-icon" :class="section.key" aria-hidden="true">
                  <svg v-if="section.key === 'direct'" viewBox="0 0 24 24">
                    <path d="M12 3v5M8 8h8v6H8zM6 14h12v6H6zM9 17h6" />
                  </svg>
                  <svg v-else viewBox="0 0 24 24">
                    <path d="M4 7h16v13H4zM8 7V4h8v3M8 12h8M8 16h5" />
                  </svg>
                </span>
                <div class="mcp-tool-identity">
                  <div class="mcp-tool-name-line">
                    <strong>{{ item.name }}</strong>
                    <span class="mcp-exposure-badge" :class="section.key">{{ section.key === 'direct' ? t('mcp.toolModeDirect') : t('mcp.toolModeSearchable') }}</span>
                  </div>
                  <code v-if="item.qualifiedName">{{ item.qualifiedName }}</code>
                  <p>{{ item.description || t('mcp.toolNoDescription') }}</p>
                </div>
                <span class="mcp-tool-source">{{ toolSourceLabel(item) }}</span>
                <label v-if="item.toggleable" class="mcp-switch" :title="item.enabled ? t('common.enabled') : t('common.disabled')">
                  <input type="checkbox" :checked="item.enabled" @change="toggleTool(item)" />
                  <i></i>
                </label>
                <span v-else class="mcp-lock-badge">{{ item.kind === 'builtin' ? t('mcp.builtinTool') : t('mcp.builtin') }}</span>
                <select
                  v-if="item.toggleable"
                  v-model="item.capability"
                  class="tool-capability-select"
                  :aria-label="item.name + ' ' + t('mcp.toolCapability')"
                >
                  <option v-for="option in capabilityOptions" :key="option.value" :value="option.value">
                    {{ option.label }}
                  </option>
                </select>
                <span v-else class="mcp-capability-badge">{{ capabilityLabel(item.capability) }}</span>
                <button class="mcp-expand-button" type="button" :aria-expanded="isExpanded(item)" @click="toggleExpand(item)">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="m8 10 4 4 4-4" />
                  </svg>
                  {{ t('mcp.toolParams', { count: item.parameters.length }) }}
                </button>
              </div>
              <ul v-if="isExpanded(item)" class="mcp-param-list">
                <li v-if="!item.parameters.length">{{ t('mcp.toolNoParams') }}</li>
                <li v-for="param in item.parameters" :key="param.name">
                  <code>{{ param.name }}</code>
                  <span class="param-type">{{ param.type }}</span>
                  <span v-if="param.required" class="param-required">{{ t('mcp.toolRequired') }}</span>
                  <span class="param-desc">{{ param.description }}</span>
                </li>
              </ul>
            </article>
          </div>
          <div v-else class="mcp-empty-state compact">
            <strong>{{ section.empty }}</strong>
          </div>
        </section>
      </section>
    </section>

    <Teleport to="body">
      <div v-if="doctorOpen" class="mcp-drawer-layer" @click.self="closeDoctor">
        <aside class="mcp-drawer doctor-drawer" role="dialog" aria-modal="true">
          <header class="mcp-drawer-head">
            <div>
              <span class="mcp-floor-code">INSPECTION BAY</span>
              <h2>{{ t('mcp.inspectionBay') }}</h2>
              <p>{{ t('mcp.inspectionHint') }}</p>
            </div>
            <button class="mcp-drawer-close" type="button" :aria-label="t('mcp.close')" @click="closeDoctor">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
            </button>
          </header>
          <div class="doctor-drawer-body">
            <div v-if="doctorRunning" class="mcp-scan-stage">
              <span class="mcp-scanner-robot" aria-hidden="true"><i></i><b></b><b></b></span>
              <span class="mcp-scan-line"></span>
              <strong>{{ t('mcp.doctorRunning') }}</strong>
            </div>
            <template v-else-if="doctorSummary">
              <div class="doctor-summary">
                <span class="doctor-chip">{{ t('mcp.doctorTotal') }} {{ doctorSummary.total }}</span>
                <span class="doctor-chip available">{{ t('mcp.doctorAvailable') }} {{ doctorSummary.available }}</span>
                <span class="doctor-chip missing">{{ t('mcp.doctorMissingBinary') }} {{ doctorSummary.missingBinary }}</span>
                <span class="doctor-chip missing">{{ t('mcp.doctorMissingDependency') }} {{ doctorSummary.missingDependency }}</span>
                <span class="doctor-chip">{{ t('mcp.doctorDisabled') }} {{ doctorSummary.disabled }}</span>
                <span class="doctor-chip error">{{ t('mcp.doctorServerError') }} {{ doctorSummary.serverError }}</span>
              </div>
              <label class="doctor-filter">
                <input v-model="doctorOnlyProblems" type="checkbox" />
                <span>{{ t('mcp.doctorOnlyProblems') }}</span>
              </label>
              <ul class="doctor-list">
                <li v-for="item in visibleDoctorItems" :key="`${item.serverName}-${item.tool}`" class="doctor-item" :class="item.status">
                  <span class="doctor-status">{{ t(`mcp.doctorStatus.${item.status}`) }}</span>
                  <strong>{{ item.tool }}</strong>
                  <span class="tool-source-badge">{{ item.serverName }}</span>
                  <em>{{ item.detail }}</em>
                </li>
                <li v-if="!visibleDoctorItems.length" class="doctor-empty">{{ t('mcp.doctorNoProblems') }}</li>
              </ul>
            </template>
            <div v-else class="mcp-empty-state compact">
              <strong>{{ t('mcp.doctorNoProblems') }}</strong>
            </div>
          </div>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="editorOpen" class="mcp-drawer-layer" @click.self="closeEditor">
        <aside class="mcp-drawer editor-drawer" role="dialog" aria-modal="true">
          <header class="mcp-drawer-head">
            <div>
              <span class="mcp-floor-code">{{ editingId ? 'ROBOT CONFIG' : 'ROBOT ONBOARDING' }}</span>
              <h2>{{ editingId ? t('mcp.editTitle') : t('mcp.connectRobot') }}</h2>
            </div>
            <button class="mcp-drawer-close" type="button" :aria-label="t('mcp.close')" @click="closeEditor">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
            </button>
          </header>
          <div class="editor-drawer-body">
            <section class="mcp-form-section">
              <span class="mcp-form-index">01</span>
              <div>
                <h3>{{ t('mcp.name') }}</h3>
                <div class="drawer-grid">
                  <label>
                    <span>{{ t('mcp.name') }}</span>
                    <input v-model="draft.name" :placeholder="t('mcp.namePlaceholder')" />
                  </label>
                  <label>
                    <span>{{ t('mcp.transportLabel') }}</span>
                    <div class="transport-switch">
                      <button type="button" :class="{ active: draft.transport === 'stdio' }" @click="draft.transport = 'stdio'">stdio</button>
                      <button type="button" :class="{ active: draft.transport === 'sse' }" @click="draft.transport = 'sse'">sse</button>
                    </div>
                  </label>
                </div>
                <label>
                  <span>{{ t('mcp.descriptionLabel') }}</span>
                  <input v-model="draft.description" :placeholder="t('project.attackDescriptionPlaceholder')" />
                </label>
              </div>
            </section>
            <section class="mcp-form-section">
              <span class="mcp-form-index">02</span>
              <div>
                <h3>{{ draft.transport === 'sse' ? t('mcp.urlLabel') : t('mcp.command') }}</h3>
                <template v-if="draft.transport === 'sse'">
                  <label>
                    <span>{{ t('mcp.urlLabel') }}</span>
                    <input v-model="draft.url" placeholder="http://127.0.0.1:9000/sse" />
                  </label>
                </template>
                <template v-else>
                  <label>
                    <span>{{ t('mcp.command') }}</span>
                    <input v-model="draft.command" :placeholder="t('mcp.commandPlaceholder')" />
                  </label>
                  <label>
                    <span>{{ t('mcp.argsLabel') }}</span>
                    <textarea v-model="draft.argsText" rows="3"></textarea>
                  </label>
                  <label>
                    <span>{{ t('mcp.envLabel') }}</span>
                    <textarea v-model="draft.envText" rows="4"></textarea>
                  </label>
                </template>
              </div>
            </section>
            <section class="mcp-form-section">
              <span class="mcp-form-index">03</span>
              <div>
                <h3>{{ t('mcp.enableLabel') }}</h3>
                <label class="checkbox-line mcp-enable-line">
                  <input v-model="draft.enabled" type="checkbox" />
                  <span>{{ t('mcp.enableLabel') }}</span>
                </label>
              </div>
            </section>
          </div>
          <footer class="mcp-drawer-foot">
            <button v-if="editingServer" class="button compact" type="button" :disabled="loading" @click="test(editingServer)">
              {{ t('mcp.test') }}
            </button>
            <span v-else></span>
            <div>
              <button class="button compact" type="button" @click="closeEditor">{{ t('common.cancel') }}</button>
              <button class="button mcp-primary-button" type="button" @click="save">{{ t('common.save') }}</button>
            </div>
          </footer>
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

.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.alert span {
  margin-left: 4px;
}

.mcp-table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid var(--line);
  background: var(--surface);
  box-shadow: none;
}

.mcp-table th,
.mcp-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 13px;
  vertical-align: top;
}

.mcp-table th {
  color: var(--text-secondary);
  font-family: var(--mono);
  font-size: 11px;
  background: var(--surface-soft);
}

.cell-hint,
.cell-error {
  display: block;
  margin-top: 3px;
  color: var(--text-muted);
  font-size: 12px;
}

.cell-error {
  max-width: min(560px, 40vw);
  overflow-wrap: anywhere;
  color: var(--danger);
}

.cell-command {
  max-width: min(560px, 40vw);
  overflow-wrap: anywhere;
  color: var(--text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}

.state-badge {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid currentColor;
  border-radius: 8px;
  font-size: 12px;
  background: var(--surface-soft);
  color: var(--text-secondary);
}

.state-connected {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.state-error {
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.state-disabled {
  color: var(--text-muted);
  background: var(--surface-soft);
}

.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.empty-cell {
  padding: 28px 12px;
  color: var(--text-muted);
  text-align: center;
}

.mcp-editor {
  position: fixed;
  top: 0;
  right: 0;
  z-index: 20;
  display: none;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(560px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
}

.mcp-editor.open {
  display: grid;
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

.text-button.dark {
  color: var(--text-muted);
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
.drawer-body select,
.drawer-body textarea {
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

.checkbox-line {
  display: flex !important;
  gap: 8px;
  align-items: center;
  font-weight: 400 !important;
}

.checkbox-line input {
  width: auto;
}

.tool-panel {
  margin-bottom: 16px;
  padding: 14px;
  border: 1px solid var(--line);
  background: var(--surface);
  box-shadow: none;
}

.tool-panel-header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.tool-panel-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.doctor-panel {
  display: grid;
  gap: 10px;
  margin-bottom: 12px;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.doctor-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.doctor-chip {
  padding: 3px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  font-size: 12px;
}

.doctor-chip.available {
  border-color: var(--success);
  color: var(--success);
}

.doctor-chip.missing {
  border-color: var(--warning);
  color: var(--warning);
}

.doctor-chip.error {
  border-color: var(--danger);
  color: var(--danger);
}

.doctor-filter {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  color: var(--text-muted);
  font-size: 12px;
}

.doctor-list {
  display: grid;
  gap: 6px;
  max-height: 320px;
  margin: 0;
  padding: 0;
  overflow: auto;
  list-style: none;
}

.doctor-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  font-size: 12px;
}

.doctor-item em {
  overflow: hidden;
  color: var(--text-muted);
  font-style: normal;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.doctor-status {
  flex: 0 0 auto;
  padding: 1px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  font-size: 11px;
}

.doctor-item.available .doctor-status {
  border-color: var(--success);
  color: var(--success);
}

.doctor-item.missing_binary .doctor-status,
.doctor-item.missing_dependency .doctor-status {
  border-color: var(--warning);
  color: var(--warning);
}

.doctor-item.server_error .doctor-status {
  border-color: var(--danger);
  color: var(--danger);
}

.doctor-item.disabled {
  opacity: 0.7;
}

.doctor-empty {
  padding: 12px;
  color: var(--text-muted);
  font-size: 12px;
  text-align: center;
}

.tool-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin: 12px 0;
}

.tool-search {
  flex: 1 1 220px;
  min-width: 160px;
  padding: 8px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: inherit;
}

.tool-filters {
  display: flex;
  gap: 6px;
}

.chip {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
}

.chip.active {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-soft);
}

.tool-source {
  padding: 7px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: inherit;
}

.tool-stats {
  color: var(--text-muted);
  font-size: 12px;
}

.tool-section + .tool-section {
  margin-top: 16px;
}

.tool-section-header {
  display: grid;
  gap: 2px;
  margin-bottom: 8px;
}

.tool-section-title {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: baseline;
}

.tool-section-title h3 {
  margin: 0;
  font-size: 13px;
  letter-spacing: 0;
}

.tool-section-count {
  color: var(--text-muted);
  font-size: 12px;
}

.tool-section-hint {
  margin: 0;
  color: var(--text-muted);
  font-size: 12px;
}

.tool-toggle.is-static input {
  opacity: 0.45;
  cursor: not-allowed;
}

.tool-capability-badge {
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  font-size: 11px;
}

.tool-card-qualified {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.tool-card-qualified code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

.tool-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 10px;
  max-height: 480px;
  padding: 2px 4px 2px 0;
  overflow-y: auto;
}

.tool-card {
  display: grid;
  gap: 6px;
  align-content: start;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.tool-card:hover {
  border-color: var(--accent);
  box-shadow: none;
  transform: translate(-1px, -1px);
}

.tool-card.is-disabled {
  opacity: 0.62;
}

.tool-card-head {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  justify-content: space-between;
}

.tool-card-name {
  min-width: 0;
  font-size: 13px;
  overflow-wrap: anywhere;
}

.tool-card-foot {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-top: 2px;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}

.tool-card-params {
  margin-left: auto;
}

.tool-toggle input {
  width: auto;
}

.tool-source-badge {
  padding: 2px 8px;
  border-radius: var(--radius);
  background: var(--surface-soft);
  color: var(--text-muted);
  font-size: 11px;
}

.tool-capability-select {
  flex: 0 1 150px;
  max-width: 150px;
  padding: 2px 6px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  color: var(--text);
  font-size: 12px;
}

.link-button {
  padding: 0;
  border: none;
  background: none;
  color: var(--accent);
  font-size: 12px;
  cursor: pointer;
}

.tool-card-desc {
  display: -webkit-box;
  margin: 0;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.5;
}

.tool-params {
  display: grid;
  gap: 4px;
  max-height: 160px;
  margin: 6px 0 0;
  padding: 6px 0 0;
  border-top: 1px dashed var(--border);
  overflow-y: auto;
  list-style: none;
}

.tool-params li {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: baseline;
  color: var(--text-muted);
  font-size: 12px;
}

.tool-params code {
  color: var(--text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

.param-type {
  padding: 1px 6px;
  border-radius: var(--radius);
  background: var(--surface-soft);
  font-size: 11px;
}

.param-required {
  color: var(--warning);
  font-size: 11px;
}

.param-desc {
  flex: 1 1 240px;
}

.tool-empty {
  padding: 16px;
  color: var(--text-muted);
  text-align: center;
}
</style>

<style scoped>
.main-column .page-mcp .mcp-command-header h1 {
  font-size: 26px;
}

.main-column .page-mcp .mcp-command-header .eyebrow {
  font-size: 9px;
}

.main-column .page-mcp .mcp-page-hint {
  font-size: 13px;
  line-height: 1.45;
}

.mcp-stat small {
  font-size: 10px;
}

.mcp-tab small {
  font-size: 9px;
}
</style>

<style scoped>
/* MCP robot control room */
.main-column .page-mcp.mcp-control {
  --mcp-accent: #55c7e8;
  --mcp-mint: #34d399;
  --mcp-amber: #f0a43a;
  --mcp-coral: #fb7185;
  --mcp-violet: #9d8cff;
  --mcp-panel: color-mix(in srgb, var(--surface) 95%, #071012);
  --mcp-panel-soft: color-mix(in srgb, var(--field-bg) 82%, transparent);
  --mcp-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-mcp.mcp-control .mcp-command-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  padding: 14px 16px;
  border-color: color-mix(in srgb, var(--mcp-accent) 22%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--mcp-accent) 9%, transparent), transparent 36%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--mcp-accent) 5%, transparent) 37px 38px
    ),
    var(--mcp-panel) !important;
}

.mcp-heading {
  display: flex;
  min-width: 0;
  gap: 13px;
  align-items: center;
}

.mcp-heading > div {
  min-width: 0;
}

.mcp-heading-robot {
  position: relative;
  display: inline-grid;
  flex: 0 0 48px;
  width: 48px;
  height: 52px;
  place-items: center;
  color: var(--mcp-accent);
}

.mcp-robot-antenna {
  position: absolute;
  top: 1px;
  left: 23px;
  width: 2px;
  height: 10px;
  background: currentColor;
}

.mcp-robot-antenna::before {
  position: absolute;
  top: -3px;
  left: -2px;
  width: 6px;
  height: 6px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, currentColor 28%, transparent);
  box-shadow: 0 0 8px color-mix(in srgb, currentColor 45%, transparent);
}

.mcp-robot-head {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  width: 38px;
  height: 29px;
  margin-top: 8px;
  border: 1px solid currentColor;
  border-radius: 7px 7px 5px 5px;
  background: color-mix(in srgb, currentColor 8%, var(--surface));
  box-shadow: inset 0 -5px 0 color-mix(in srgb, currentColor 7%, transparent);
}

.mcp-robot-head b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 7px currentColor;
  animation: mcp-robot-signal 3.4s ease-in-out infinite;
}

.mcp-heading .mcp-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.mcp-header-icon {
  width: 34px;
  height: 34px;
}

.main-column .page-mcp.mcp-control .header-actions .button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.main-column .page-mcp.mcp-control .header-actions .button svg,
.mcp-header-icon svg {
  width: 15px;
  height: 15px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.main-column .page-mcp.mcp-control .mcp-primary-button {
  border-color: color-mix(in srgb, var(--mcp-accent) 72%, var(--border)) !important;
  color: #071415 !important;
  background: var(--mcp-accent) !important;
}

.mcp-alert,
.mcp-test-banner {
  margin: 0 0 9px;
  border-radius: 4px;
}

.mcp-test-banner {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding: 8px 11px;
  border: 1px solid currentColor;
  font-size: 11px;
}

.mcp-test-led {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 7px currentColor;
}

.mcp-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(4, minmax(110px, 1fr));
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--mcp-line);
  border-radius: 5px;
  background: var(--mcp-line);
}

.mcp-stat {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 8px;
  min-height: 68px;
  padding: 10px 12px;
  background: var(--mcp-panel);
}

.mcp-stat-code {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.mcp-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 24px;
  font-weight: 500;
}

.mcp-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-stat::after {
  position: absolute;
  bottom: 0;
  left: 12px;
  width: 28px;
  height: 2px;
  content: '';
  background: var(--mcp-accent);
}

.mcp-stat.tone-online::after {
  background: var(--mcp-mint);
}

.mcp-stat.tone-tools::after {
  background: var(--mcp-violet);
}

.mcp-stat.tone-error::after {
  background: var(--mcp-coral);
}

.mcp-stat.tone-muted::after {
  background: var(--text-muted);
}

.mcp-status-track {
  position: absolute;
  right: 12px;
  bottom: 8px;
  display: flex;
  gap: 3px;
}

.mcp-status-track i {
  width: 3px;
  height: 8px;
  opacity: 0.38;
  background: var(--mcp-accent);
}

.mcp-status-track i:nth-child(2),
.mcp-status-track i:nth-child(4) {
  height: 4px;
}

.mcp-tabs {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
  margin-bottom: 10px;
}

.mcp-tab {
  display: grid;
  grid-template-columns: 34px minmax(0, 1fr) auto;
  gap: 9px;
  align-items: center;
  min-height: 54px;
  padding: 8px 11px;
  border: 1px solid var(--mcp-line);
  border-radius: 4px;
  color: var(--text-secondary);
  background: var(--mcp-panel);
  text-align: left;
  cursor: pointer;
}

.mcp-tab:hover {
  border-color: color-mix(in srgb, var(--mcp-accent) 42%, var(--border));
}

.mcp-tab.active {
  border-color: color-mix(in srgb, var(--mcp-accent) 66%, var(--border));
  color: var(--text-primary);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--mcp-accent) 9%, transparent), transparent),
    var(--mcp-panel);
  box-shadow: inset 3px 0 0 var(--mcp-accent);
}

.mcp-tab-icon {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid color-mix(in srgb, var(--mcp-accent) 25%, var(--border));
  border-radius: 50%;
  color: var(--mcp-accent);
  place-items: center;
}

.mcp-tab-icon svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.mcp-tab > span:nth-child(2) {
  display: grid;
  gap: 2px;
  min-width: 0;
}

.mcp-tab strong {
  font-size: 12px;
  font-weight: 600;
}

.mcp-tab small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-tab > b {
  color: var(--mcp-accent);
  font-family: var(--mono);
  font-size: 16px;
  font-weight: 500;
}

.mcp-fleet-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 248px;
  gap: 10px;
  align-items: start;
}

.mcp-fleet-panel,
.mcp-tool-floor,
.mcp-rail-block {
  border: 1px solid color-mix(in srgb, var(--mcp-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--mcp-panel);
}

.mcp-floor-header,
.mcp-rack-header {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 12px 13px;
  border-bottom: 1px solid var(--border);
}

.mcp-floor-code {
  color: var(--mcp-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.mcp-floor-header h2,
.mcp-rack-header h3,
.mcp-discovery-copy h2,
.mcp-rail-block h3 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 600;
}

.mcp-server-tools,
.mcp-rack-toolbar,
.mcp-rack-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
}

.mcp-search-box {
  display: flex;
  min-width: 190px;
  gap: 6px;
  align-items: center;
  padding: 0 9px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.mcp-search-box svg {
  flex: 0 0 auto;
  width: 14px;
  height: 14px;
  fill: none;
  stroke: var(--text-muted);
  stroke-width: 1.7;
  stroke-linecap: round;
}

.mcp-search-box input {
  min-width: 0;
  padding: 7px 0 !important;
  border: 0 !important;
  outline: 0;
  background: transparent !important;
  box-shadow: none !important;
}

.mcp-segmented,
.transport-switch {
  display: inline-flex;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.mcp-segmented button,
.transport-switch button {
  min-height: 27px;
  padding: 4px 8px;
  border: 0;
  border-radius: 2px;
  color: var(--text-muted);
  background: transparent;
  font-size: 10px;
  cursor: pointer;
}

.mcp-segmented button.active,
.transport-switch button.active {
  color: var(--text-primary);
  background: color-mix(in srgb, var(--mcp-accent) 13%, var(--surface));
  box-shadow: inset 0 -2px 0 var(--mcp-accent);
}

.mcp-segmented.compact button {
  min-height: 25px;
  font-size: 9px;
}

.robot-fleet-list {
  position: relative;
  display: grid;
  gap: 5px;
  padding: 10px 10px 10px 23px;
}

.robot-fleet-list::before {
  position: absolute;
  top: 13px;
  bottom: 13px;
  left: 14px;
  width: 1px;
  content: '';
  background: color-mix(in srgb, var(--mcp-accent) 30%, var(--border));
}

.robot-service-row {
  --robot-color: var(--mcp-amber);
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  gap: 4px 7px;
  align-items: center;
  padding: 6px 7px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--robot-color) 4%, transparent), transparent 28%),
    var(--surface);
  transition:
    border-color 0.15s ease,
    background 0.15s ease;
}

.robot-service-row.tone-online {
  --robot-color: var(--mcp-mint);
}

.robot-service-row.tone-error {
  --robot-color: var(--mcp-coral);
}

.robot-service-row.tone-unknown {
  --robot-color: var(--mcp-amber);
}

.robot-service-row.tone-disabled {
  --robot-color: var(--text-muted);
}

.robot-service-row:hover,
.robot-service-row.is-active {
  border-color: color-mix(in srgb, var(--robot-color) 52%, var(--border));
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--robot-color) 8%, transparent), transparent 34%),
    var(--surface);
}

.robot-service-row.is-active {
  box-shadow: inset 3px 0 0 var(--robot-color);
}

.robot-service-row.is-disabled {
  opacity: 0.66;
}

.robot-service-main {
  display: grid;
  grid-template-columns: 16px 42px minmax(150px, 1.2fr) minmax(130px, 1fr) 48px 86px;
  gap: 9px;
  align-items: center;
  min-width: 0;
  padding: 2px 3px;
  border: 0;
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.robot-dock {
  position: relative;
  width: 16px;
  height: 16px;
  border: 1px solid color-mix(in srgb, var(--robot-color) 65%, var(--border));
  border-radius: 50%;
  background: var(--mcp-panel);
}

.robot-dock::before {
  position: absolute;
  top: 50%;
  right: -8px;
  width: 8px;
  height: 1px;
  content: '';
  background: var(--robot-color);
}

.robot-dock i {
  position: absolute;
  inset: 4px;
  border-radius: 50%;
  background: var(--robot-color);
  box-shadow: 0 0 6px color-mix(in srgb, var(--robot-color) 55%, transparent);
}

.robot-service-row.tone-online .robot-dock i {
  animation: mcp-dock-pulse 3s ease-in-out infinite;
}

.robot-avatar {
  position: relative;
  display: block;
  width: 38px;
  height: 40px;
  color: var(--robot-color);
}

.robot-antenna {
  position: absolute;
  top: 0;
  left: 18px;
  width: 2px;
  height: 8px;
  background: currentColor;
}

.robot-antenna::before {
  position: absolute;
  top: -3px;
  left: -2px;
  width: 5px;
  height: 5px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, currentColor 28%, transparent);
}

.robot-face {
  position: absolute;
  top: 6px;
  left: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  width: 32px;
  height: 23px;
  border: 1px solid currentColor;
  border-radius: 6px 6px 4px 4px;
  background: color-mix(in srgb, currentColor 7%, var(--surface));
}

.robot-face b {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 5px currentColor;
}

.tone-online .robot-face b {
  animation: mcp-robot-signal 3s ease-in-out infinite;
}

.robot-face em {
  position: absolute;
  bottom: 3px;
  width: 8px;
  height: 1px;
  background: currentColor;
}

.robot-body {
  position: absolute;
  bottom: 0;
  left: 8px;
  width: 23px;
  height: 10px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

.tone-disabled .robot-face b {
  width: 5px;
  height: 1px;
  border-radius: 0;
  box-shadow: none;
}

.tone-error .robot-face {
  border-radius: 3px;
}

.tone-error .robot-face b:first-child {
  transform: rotate(28deg);
}

.tone-error .robot-face b:nth-child(2) {
  transform: rotate(-28deg);
}

.robot-identity {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.robot-name-line {
  display: flex;
  min-width: 0;
  gap: 6px;
  align-items: center;
}

.robot-name-line strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.robot-identity small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.robot-endpoint {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.robot-load {
  display: grid;
  gap: 1px;
  justify-items: end;
}

.robot-load strong {
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 14px;
  font-weight: 500;
}

.robot-load small {
  color: var(--text-muted);
  font-size: 8px;
}

.robot-state {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  justify-content: flex-end;
  color: var(--robot-color);
  font-family: var(--mono);
  font-size: 9px;
  white-space: nowrap;
}

.robot-state i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px color-mix(in srgb, currentColor 55%, transparent);
}

.robot-actions {
  display: flex;
  gap: 3px;
  align-items: center;
}

.mcp-icon-action,
.mcp-drawer-close,
.mcp-expand-button {
  display: inline-grid;
  align-items: center;
  justify-content: center;
  border: 1px solid transparent;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
}

.mcp-icon-action {
  width: 27px;
  height: 27px;
  border-radius: 3px;
}

.mcp-icon-action:hover {
  border-color: color-mix(in srgb, var(--mcp-accent) 40%, var(--border));
  color: var(--mcp-accent);
  background: color-mix(in srgb, var(--mcp-accent) 8%, transparent);
}

.mcp-icon-action.danger:hover {
  border-color: color-mix(in srgb, var(--mcp-coral) 50%, var(--border));
  color: var(--mcp-coral);
}

.mcp-icon-action:disabled {
  opacity: 0.28;
  cursor: not-allowed;
}

.mcp-icon-action svg,
.mcp-drawer-close svg,
.mcp-expand-button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.robot-tool-link {
  grid-column: 3;
  justify-self: end;
  padding: 3px 5px;
  border: 0;
  color: var(--mcp-accent);
  background: transparent;
  font-family: var(--mono);
  font-size: 8px;
  cursor: pointer;
  white-space: nowrap;
}

.robot-tool-link:hover {
  text-decoration: underline;
}

.robot-error {
  grid-column: 1 / -1;
  margin: 2px 0 0;
  padding: 5px 7px;
  overflow-wrap: anywhere;
  border-left: 2px solid var(--mcp-coral);
  color: var(--mcp-coral);
  background: color-mix(in srgb, var(--mcp-coral) 6%, transparent);
  font-size: 9px;
}

.mcp-lock-badge,
.mcp-exposure-badge,
.mcp-capability-badge,
.tool-source-badge {
  display: inline-flex;
  align-items: center;
  min-height: 18px;
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 8px;
  white-space: nowrap;
}

.mcp-fleet-rail {
  display: grid;
  gap: 8px;
}

.mcp-rail-block {
  position: relative;
  padding: 12px;
  overflow: hidden;
}

.mcp-rail-block::before {
  position: absolute;
  top: 0;
  right: 0;
  width: 34px;
  height: 2px;
  content: '';
  background: var(--mcp-accent);
}

.mcp-legend {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 7px;
  margin: 11px 0;
}

.mcp-legend span {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-legend i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}

.tone-online {
  color: var(--mcp-mint);
}

.tone-unknown {
  color: var(--mcp-amber);
}

.tone-error {
  color: var(--mcp-coral);
}

.tone-disabled,
.tone-muted {
  color: var(--text-muted);
}

.mcp-rail-meter {
  height: 4px;
  overflow: hidden;
  border-radius: 2px;
  background: var(--field-bg);
}

.mcp-rail-meter span {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--mcp-mint), var(--mcp-accent));
}

.mcp-rail-block > small {
  display: block;
  margin-top: 5px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.mcp-discovery-mini p {
  margin: 7px 0;
  color: var(--text-muted);
  font-size: 9px;
  line-height: 1.45;
}

.mcp-mini-chain {
  display: grid;
  gap: 4px;
  margin-bottom: 9px;
}

.mcp-mini-chain code {
  padding: 5px 6px;
  overflow: hidden;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  background: var(--field-bg);
  font-size: 8px;
  text-overflow: ellipsis;
}

.mcp-mini-chain i {
  color: var(--mcp-accent);
  font-style: normal;
  text-align: center;
}

.mcp-discovery-mini .button {
  width: 100%;
}

.mcp-empty-state {
  display: grid;
  min-height: 160px;
  gap: 10px;
  place-items: center;
  align-content: center;
  color: var(--text-muted);
  font-size: 11px;
}

.mcp-empty-state.compact {
  min-height: 84px;
}

.empty-robot {
  position: relative;
  display: block;
  width: 36px;
  height: 32px;
  border: 1px solid var(--text-muted);
  border-radius: 7px;
  opacity: 0.55;
}

.empty-robot::before {
  position: absolute;
  top: -8px;
  left: 16px;
  width: 1px;
  height: 7px;
  content: '';
  background: var(--text-muted);
}

.empty-robot i {
  position: absolute;
  bottom: 6px;
  left: 9px;
  width: 16px;
  height: 1px;
  background: var(--text-muted);
}

.empty-robot b {
  position: absolute;
  top: 10px;
  width: 5px;
  height: 1px;
  background: var(--text-muted);
}

.empty-robot b:nth-of-type(1) {
  left: 8px;
}

.empty-robot b:nth-of-type(2) {
  right: 8px;
}

.mcp-tool-floor {
  overflow: hidden;
}

.mcp-discovery-track {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
  padding: 13px 15px;
  border-bottom: 1px solid var(--border);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--mcp-violet) 8%, transparent), transparent 48%),
    var(--mcp-panel);
}

.mcp-discovery-copy p {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-chain {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
}

.mcp-chain-node {
  display: inline-flex;
  gap: 6px;
  align-items: center;
  min-height: 30px;
  padding: 5px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.mcp-chain-node i {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--mcp-accent);
  box-shadow: 0 0 7px color-mix(in srgb, var(--mcp-accent) 50%, transparent);
}

.mcp-chain-node.use i {
  background: var(--mcp-violet);
  box-shadow: 0 0 7px color-mix(in srgb, var(--mcp-violet) 50%, transparent);
}

.mcp-chain-node code {
  color: var(--text-secondary);
  font-size: 9px;
}

.mcp-chain-track {
  position: relative;
  width: 48px;
  height: 1px;
  background: color-mix(in srgb, var(--mcp-accent) 45%, var(--border));
}

.mcp-chain-track::after {
  position: absolute;
  top: -2px;
  right: -1px;
  width: 5px;
  height: 5px;
  content: '';
  border-top: 1px solid var(--mcp-accent);
  border-right: 1px solid var(--mcp-accent);
  transform: rotate(45deg);
}

.mcp-chain-track b {
  position: absolute;
  top: -2px;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--mcp-accent);
  animation: mcp-chain-packet 2.8s linear infinite;
}

.mcp-chain-count {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.mcp-rack-panel {
  min-width: 0;
}

.mcp-rack-header > div:first-child {
  display: grid;
  gap: 2px;
}

.mcp-rack-header span {
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-dirty-led {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--mcp-amber) !important;
  font-family: var(--mono);
  font-size: 8px !important;
}

.mcp-dirty-led::before {
  width: 6px;
  height: 6px;
  content: '';
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 7px currentColor;
}

.mcp-rack-toolbar {
  position: sticky;
  top: 0;
  z-index: 2;
  padding: 9px 11px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--mcp-panel) 94%, transparent);
  backdrop-filter: blur(10px);
}

.mcp-rack-toolbar .mcp-search-box {
  flex: 1 1 230px;
}

.tool-source {
  min-height: 32px;
  padding: 5px 8px;
  border-radius: 3px;
  font-size: 10px;
}

.mcp-tool-section {
  padding: 11px;
}

.mcp-tool-section + .mcp-tool-section {
  border-top: 1px solid var(--border);
}

.mcp-tool-section-head {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 12px;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 7px;
}

.mcp-tool-section-head > div {
  display: flex;
  gap: 7px;
  align-items: center;
}

.mcp-tool-section-mark {
  width: 4px;
  height: 16px;
  border-radius: 1px;
  background: var(--mcp-accent);
}

.mcp-tool-section-mark.searchable {
  background: var(--mcp-violet);
}

.mcp-tool-section-head h3 {
  margin: 0;
  color: var(--text-primary);
  font-size: 11px;
  font-weight: 600;
}

.mcp-tool-section-head b {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 400;
}

.mcp-tool-section-head p {
  max-width: 680px;
  margin: 0;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-tool-list {
  display: grid;
  gap: 4px;
}

.mcp-tool-row {
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  transition: border-color 0.15s ease;
}

.mcp-tool-row:hover,
.mcp-tool-row.expanded {
  border-color: color-mix(in srgb, var(--mcp-accent) 38%, var(--border));
}

.mcp-tool-row.is-disabled {
  opacity: 0.62;
}

.mcp-tool-row-main {
  display: grid;
  grid-template-columns: 34px minmax(200px, 1.5fr) minmax(70px, 0.5fr) auto minmax(94px, 0.6fr) auto;
  gap: 8px;
  align-items: center;
  padding: 7px 9px;
}

.mcp-equipment-icon {
  display: grid;
  width: 32px;
  height: 32px;
  border: 1px solid color-mix(in srgb, var(--mcp-accent) 28%, var(--border));
  border-radius: 4px;
  color: var(--mcp-accent);
  background: color-mix(in srgb, var(--mcp-accent) 6%, var(--surface));
  place-items: center;
}

.mcp-equipment-icon.searchable {
  border-color: color-mix(in srgb, var(--mcp-violet) 35%, var(--border));
  color: var(--mcp-violet);
  background: color-mix(in srgb, var(--mcp-violet) 6%, var(--surface));
}

.mcp-equipment-icon svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.mcp-tool-identity {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.mcp-tool-name-line {
  display: flex;
  min-width: 0;
  gap: 6px;
  align-items: center;
}

.mcp-tool-name-line strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-exposure-badge.direct {
  border-color: color-mix(in srgb, var(--mcp-accent) 42%, var(--border));
  color: var(--mcp-accent);
}

.mcp-exposure-badge.searchable {
  border-color: color-mix(in srgb, var(--mcp-violet) 42%, var(--border));
  color: var(--mcp-violet);
}

.mcp-tool-identity code {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-tool-identity p {
  margin: 1px 0 0;
  overflow: hidden;
  color: var(--text-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-tool-source {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mcp-switch {
  position: relative;
  display: inline-flex;
  width: 31px;
  height: 17px;
  cursor: pointer;
}

.mcp-switch input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}

.mcp-switch i {
  width: 100%;
  height: 100%;
  border: 1px solid var(--border-strong);
  border-radius: 20px;
  background: var(--field-bg);
  transition: background 0.15s ease;
}

.mcp-switch i::after {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 11px;
  height: 11px;
  content: '';
  border-radius: 50%;
  background: var(--text-muted);
  transition: transform 0.15s ease;
}

.mcp-switch input:checked + i {
  border-color: color-mix(in srgb, var(--mcp-mint) 60%, var(--border));
  background: color-mix(in srgb, var(--mcp-mint) 17%, var(--field-bg));
}

.mcp-switch input:checked + i::after {
  background: var(--mcp-mint);
  box-shadow: 0 0 6px color-mix(in srgb, var(--mcp-mint) 55%, transparent);
  transform: translateX(14px);
}

.mcp-capability-badge {
  color: var(--text-secondary);
}

.mcp-expand-button {
  display: inline-flex;
  gap: 3px;
  min-height: 27px;
  padding: 4px 5px;
  border-radius: 3px;
  font-size: 8px;
  white-space: nowrap;
}

.mcp-expand-button:hover {
  color: var(--mcp-accent);
  background: color-mix(in srgb, var(--mcp-accent) 7%, transparent);
}

.mcp-expand-button svg {
  transition: transform 0.15s ease;
}

.mcp-tool-row.expanded .mcp-expand-button svg {
  transform: rotate(180deg);
}

.mcp-param-list {
  display: grid;
  gap: 4px;
  margin: 0;
  padding: 7px 10px 9px 51px;
  border-top: 1px dashed var(--border);
  background: color-mix(in srgb, var(--field-bg) 52%, transparent);
  list-style: none;
}

.mcp-param-list li {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: baseline;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-param-list code {
  color: var(--text-secondary);
  font-family: var(--mono);
}

.param-type {
  padding: 0 4px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  background: var(--surface-soft);
  font-size: 8px;
}

.param-required {
  color: var(--mcp-amber);
  font-size: 8px;
}

.param-desc {
  flex: 1 1 280px;
}

.mcp-drawer-layer {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: flex;
  justify-content: flex-end;
  background: rgba(4, 9, 10, 0.58);
  backdrop-filter: blur(3px);
}

.mcp-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(560px, 100%);
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--mcp-accent) 28%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--mcp-accent) 4%, transparent), transparent 160px),
    var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.34);
  animation: mcp-drawer-in 0.22s ease-out both;
}

.doctor-drawer {
  width: min(520px, 100%);
}

.mcp-drawer-head,
.mcp-drawer-foot {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 14px 17px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface-soft) 76%, transparent);
}

.mcp-drawer-foot {
  border-top: 1px solid var(--border);
  border-bottom: 0;
}

.mcp-drawer-foot > div {
  display: flex;
  gap: 7px;
}

.mcp-drawer-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 17px;
  font-weight: 600;
}

.mcp-drawer-head p {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 9px;
}

.mcp-drawer-close {
  flex: 0 0 32px;
  width: 32px;
  height: 32px;
  border-color: var(--border);
  border-radius: 3px;
}

.mcp-drawer-close:hover {
  color: var(--mcp-coral);
  border-color: color-mix(in srgb, var(--mcp-coral) 45%, var(--border));
}

.doctor-drawer-body,
.editor-drawer-body {
  overflow: auto;
}

.doctor-drawer-body {
  display: grid;
  align-content: start;
  gap: 10px;
  padding: 14px;
}

.mcp-scan-stage {
  position: relative;
  display: grid;
  min-height: 220px;
  gap: 13px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--mcp-accent);
  background:
    repeating-linear-gradient(
      0deg,
      transparent 0 19px,
      color-mix(in srgb, var(--mcp-accent) 6%, transparent) 19px 20px
    ),
    var(--field-bg);
  place-items: center;
  align-content: center;
}

.mcp-scan-stage::before {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  content: '';
  background: linear-gradient(transparent, currentColor, transparent);
  box-shadow: 0 0 15px currentColor;
  animation: mcp-scan-sweep 2.2s ease-in-out infinite;
}

.mcp-scan-stage strong {
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 500;
  letter-spacing: 0.08em;
}

.mcp-scanner-robot {
  position: relative;
  display: flex;
  width: 48px;
  height: 34px;
  align-items: center;
  justify-content: center;
  gap: 9px;
  border: 1px solid currentColor;
  border-radius: 8px;
  background: color-mix(in srgb, currentColor 8%, var(--surface));
}

.mcp-scanner-robot::before {
  position: absolute;
  top: -10px;
  left: 23px;
  width: 1px;
  height: 9px;
  content: '';
  background: currentColor;
}

.mcp-scanner-robot b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
}

.mcp-scanner-robot i {
  position: absolute;
  bottom: -11px;
  width: 28px;
  height: 10px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
}

.doctor-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.doctor-chip {
  padding: 3px 7px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 8px;
}

.doctor-chip.available {
  color: var(--mcp-mint);
  border-color: color-mix(in srgb, var(--mcp-mint) 45%, var(--border));
}

.doctor-chip.missing {
  color: var(--mcp-amber);
  border-color: color-mix(in srgb, var(--mcp-amber) 45%, var(--border));
}

.doctor-chip.error {
  color: var(--mcp-coral);
  border-color: color-mix(in srgb, var(--mcp-coral) 45%, var(--border));
}

.doctor-filter {
  display: inline-flex;
  gap: 6px;
  align-items: center;
  color: var(--text-muted);
  font-size: 9px;
}

.doctor-list {
  display: grid;
  gap: 4px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.doctor-item {
  display: grid;
  grid-template-columns: 58px minmax(110px, 0.7fr) minmax(80px, 0.5fr) minmax(0, 1.5fr);
  gap: 7px;
  align-items: center;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  font-size: 9px;
}

.doctor-item strong {
  overflow: hidden;
  color: var(--text-primary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.doctor-item em {
  overflow: hidden;
  color: var(--text-muted);
  font-style: normal;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.doctor-status {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.doctor-item.available .doctor-status {
  color: var(--mcp-mint);
}

.doctor-item.missing_binary .doctor-status,
.doctor-item.missing_dependency .doctor-status {
  color: var(--mcp-amber);
}

.doctor-item.server_error .doctor-status {
  color: var(--mcp-coral);
}

.doctor-empty {
  padding: 24px;
  color: var(--text-muted);
  text-align: center;
}

.editor-drawer-body {
  display: grid;
  gap: 9px;
  align-content: start;
  padding: 14px;
}

.mcp-form-section {
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr);
  gap: 9px;
  padding: 11px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--field-bg);
}

.mcp-form-index {
  color: var(--mcp-accent);
  font-family: var(--mono);
  font-size: 9px;
}

.mcp-form-section > div {
  display: grid;
  gap: 10px;
}

.mcp-form-section h3 {
  margin: 0;
  color: var(--text-primary);
  font-size: 11px;
  font-weight: 600;
}

.mcp-form-section label {
  display: grid;
  gap: 5px;
  color: var(--text-secondary);
  font-size: 10px;
}

.drawer-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}

.mcp-enable-line {
  display: flex !important;
  flex-direction: row !important;
  gap: 7px !important;
  align-items: center;
}

.mcp-enable-line input {
  width: auto;
}

.transport-switch {
  width: fit-content;
}

@keyframes mcp-robot-signal {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@keyframes mcp-dock-pulse {
  0%,
  100% {
    box-shadow: 0 0 4px color-mix(in srgb, var(--robot-color) 38%, transparent);
  }
  50% {
    box-shadow: 0 0 9px color-mix(in srgb, var(--robot-color) 68%, transparent);
  }
}

@keyframes mcp-chain-packet {
  from {
    left: 0;
  }
  to {
    left: 44px;
  }
}

@keyframes mcp-scan-sweep {
  0% {
    left: 8%;
  }
  50% {
    left: 92%;
  }
  100% {
    left: 8%;
  }
}

@keyframes mcp-drawer-in {
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
  .mcp-fleet-layout {
    grid-template-columns: 1fr;
  }

  .mcp-fleet-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .robot-service-main {
    grid-template-columns: 16px 42px minmax(150px, 1fr) minmax(120px, 0.8fr) 44px;
  }

  .robot-state {
    display: none;
  }

  .mcp-tool-row-main {
    grid-template-columns: 34px minmax(180px, 1fr) auto minmax(88px, auto) auto;
  }

  .mcp-tool-source {
    display: none;
  }
}

@media (max-width: 760px) {
  .main-column .page-mcp.mcp-control {
    overflow-x: hidden;
  }

  .main-column .page-mcp.mcp-control .mcp-command-header {
    align-items: stretch;
  }

  .mcp-heading {
    align-items: flex-start;
  }

  .mcp-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .mcp-tabs {
    grid-template-columns: 1fr;
  }

  .mcp-tabs,
  .mcp-tab,
  .mcp-fleet-layout,
  .mcp-fleet-panel,
  .mcp-tool-floor,
  .mcp-status-rail {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .mcp-tab {
    overflow: hidden;
  }

  .mcp-fleet-rail {
    grid-template-columns: 1fr;
  }

  .mcp-floor-header {
    align-items: stretch;
    flex-direction: column;
  }

  .mcp-server-tools,
  .mcp-rack-toolbar {
    align-items: stretch;
    flex-direction: column;
    width: 100%;
    min-width: 0;
  }

  .mcp-server-tools > *,
  .mcp-rack-toolbar > * {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .mcp-search-box {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .mcp-segmented {
    width: 100%;
    max-width: 100%;
    overflow-x: auto;
  }

  .robot-service-row {
    grid-template-columns: minmax(0, 1fr) auto;
    min-width: 0;
    max-width: 100%;
    overflow: hidden;
  }

  .robot-service-main {
    grid-template-columns: 14px 38px minmax(0, 1fr) 42px;
    width: 100%;
    min-width: 0;
    overflow: hidden;
  }

  .robot-endpoint,
  .robot-state {
    display: none;
  }

  .robot-identity,
  .robot-name-line {
    min-width: 0;
    overflow: hidden;
  }

  .robot-actions {
    grid-column: 1 / -1;
    flex-wrap: wrap;
    justify-content: flex-end;
    border-top: 1px dashed var(--border);
    padding-top: 4px;
  }

  .robot-tool-link {
    grid-column: 2;
    grid-row: 2;
  }

  .mcp-discovery-track {
    align-items: flex-start;
    flex-direction: column;
  }

  .mcp-chain-track {
    width: 24px;
  }

  .mcp-tool-row-main {
    grid-template-columns: 32px minmax(0, 1fr) auto auto;
    gap: 6px;
  }

  .mcp-tool-row-main .mcp-capability-badge,
  .mcp-tool-row-main .tool-capability-select,
  .mcp-tool-source {
    display: none;
  }

  .mcp-param-list {
    padding-left: 10px;
  }

  .mcp-drawer {
    width: 100%;
  }

  .doctor-item {
    grid-template-columns: 58px minmax(0, 1fr);
  }

  .doctor-item .tool-source-badge,
  .doctor-item em {
    grid-column: 1 / -1;
  }
}

@media (prefers-reduced-motion: reduce) {
  .mcp-robot-head b,
  .robot-face b,
  .robot-dock i,
  .mcp-chain-track b,
  .mcp-scan-stage::before {
    animation: none;
  }

  .mcp-drawer {
    animation: none;
  }
}
</style>

<style scoped>
/* MCP Management in the Vulnerability Management visual system */
.main-column .page-mcp.mcp-control .mcp-command-header {
  min-height: 78px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-mcp .mcp-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-mcp .mcp-command-header .button {
  min-height: 30px;
  padding: 5px 9px;
  border-radius: 3px;
  font-size: 10px;
}

.main-column .page-mcp .mcp-command-header .mcp-primary-button {
  border-color: color-mix(in srgb, var(--accent) 58%, var(--border));
  color: var(--accent);
  background: var(--accent-soft);
}

.mcp-status-rail {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  padding: 0;
  border: 0;
  background: transparent;
}

.mcp-stat {
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

.mcp-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: var(--accent);
  font-size: 12px;
}

.mcp-stat-glyph {
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

.mcp-stat::after {
  display: none;
}

.mcp-stat.tone-online {
  border-left-color: var(--success);
}

.mcp-stat.tone-online small,
.mcp-stat.tone-online strong {
  color: var(--success);
}

.mcp-stat.tone-tools {
  border-left-color: #55c7e8;
}

.mcp-stat.tone-tools small,
.mcp-stat.tone-tools strong {
  color: #55c7e8;
}

.mcp-stat.tone-error {
  border-left-color: var(--danger);
}

.mcp-stat.tone-error small,
.mcp-stat.tone-error strong {
  color: var(--danger);
}

.mcp-stat.tone-muted {
  border-left-color: var(--text-muted);
}

.mcp-stat.tone-muted small,
.mcp-stat.tone-muted strong {
  color: var(--text-muted);
}

.mcp-stat strong {
  color: var(--accent);
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.mcp-status-track {
  display: none;
}

.mcp-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.mcp-tab {
  min-height: 44px;
  flex: 1;
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: var(--surface);
}

.mcp-tab.active {
  border-left-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 6%, var(--surface));
}

.mcp-tab-icon {
  width: 26px;
  height: 26px;
}

.mcp-tab small {
  display: none;
}

.mcp-tab strong {
  font-size: 11px;
}

.mcp-fleet-layout {
  gap: 10px;
}

.mcp-fleet-panel,
.mcp-fleet-rail,
.mcp-rail-block,
.mcp-rack-panel,
.mcp-discovery-track {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.mcp-floor-header,
.mcp-rack-header,
.mcp-rack-toolbar {
  background: var(--surface-soft);
}

.robot-fleet-list {
  border: 1px solid var(--line);
  background: var(--surface);
}

.robot-service-row {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
}

.robot-service-row:hover {
  background: color-mix(in srgb, var(--accent) 4%, transparent);
}

.mcp-tool-list {
  border: 1px solid var(--line);
  background: var(--surface);
}

.mcp-tool-row {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
}

.mcp-tool-row:hover {
  background: color-mix(in srgb, var(--accent) 4%, transparent);
}

.mcp-drawer-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.mcp-drawer {
  width: min(720px, 100%);
  border-left-color: color-mix(in srgb, var(--accent) 32%, var(--border));
  background: var(--surface);
}

.mcp-drawer-head,
.mcp-drawer-foot {
  background: var(--surface-soft);
}

.mcp-form-section {
  padding-bottom: 12px;
  border-color: var(--border);
  border-radius: 0;
  background: transparent;
}

@media (max-width: 760px) {
  .mcp-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .mcp-tabs {
    flex-direction: column;
  }

  .mcp-drawer {
    width: 100%;
  }
}
</style>
