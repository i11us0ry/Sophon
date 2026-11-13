<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref, watch, type Ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import AttackGraphCanvas from '../components/graph/AttackGraphCanvas.vue'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()

interface Project {
  id: string
  name: string
  description: string
  goals: string
  scope: string
  status?: string
  createdAt: string
  updatedAt: string
}

interface ProjectCounts {
  facts: number
  attackSteps: number
  assets: number
  conversations: number
  vulnerabilities: number
}

interface CoverageTarget {
  kind: string
  refId: string
  label: string
  reason: string
  score: number
}

interface ProjectCoverage {
  assetsTotal: number
  assetsTested: number
  assetsCovered: number
  assetsPartial: number
  assetsBlocked: number
  assetsSuspicious: number
  assetsUntested: number
  findingsTotal: number
  findingsConfirmed: number
  findingsWithoutEvidence: number
  factsWithoutEvidence: number
  intentsOpen: number
  intentsRunning: number
  coverageRatio: number
  fullCoverageRatio: number
  nextTargets: CoverageTarget[]
}

interface Fact {
  id: string
  assetId: string
  factType: string
  key: string
  value: string
  summary: string
  body: string
  evidence: string
  relation: string
  confidence: number
  updatedAt: string
}

interface GraphNode {
  id: string
  projectId: string
  kind: string
  title: string
  detail: string
  status: string
  confidence: number
  severity: string
  assetId: string
  source: string
  posX: number
  posY: number
  createdAt: string
  updatedAt: string
}

interface GraphEdge {
  id: string
  projectId: string
  srcId: string
  dstId: string
  rel: string
  createdAt: string
}

interface Asset {
  id: string
  name: string
  kind: string
  value: string
  status: string
  criticality: string
  riskScore: number
}

interface Conversation {
  id: string
  title: string
  assetId?: string
  agentRoleId?: string
  updatedAt: string
}

interface Vulnerability {
  id: string
  title: string
  severity: string
  status: string
  target: string
  updatedAt: string
}

interface PageResponse<T> {
  items: T[]
  total: number
  hasMore: boolean
  nextOffset: number
}

const TABS = [
  { key: 'facts', labelKey: 'project.tabFacts', countKey: 'facts' },
  { key: 'attack', labelKey: 'project.attackSteps', countKey: 'attackSteps' },
  { key: 'assets', labelKey: 'project.tabAssets', countKey: 'assets' },
  { key: 'conversations', labelKey: 'project.tabConversations', countKey: 'conversations' },
  { key: 'vulnerabilities', labelKey: 'project.tabVulnerabilities', countKey: 'vulnerabilities' },
]

const visibleTabs = computed(() =>
  TABS.filter((tab) => {
    if (tab.key === 'attack' || tab.key === 'vulnerabilities') {
      return auth.hasPermission('vulnerability:read')
    }
    if (tab.key === 'assets') {
      return auth.hasPermission('asset:read')
    }
    if (tab.key === 'conversations') {
      return auth.hasPermission('chat:read')
    }
    return true
  }),
)

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'severity.critical',
  high: 'severity.high',
  medium: 'severity.medium',
  low: 'severity.low',
  info: 'severity.info',
}

const GRAPH_KINDS = ['begin', 'goal', 'intent', 'fact', 'finding', 'hint', 'asset', 'chain', 'digest'] as const
const GRAPH_CREATE_KINDS = ['begin', 'goal', 'intent', 'fact', 'finding', 'hint'] as const

const GRAPH_STATUS_OPTIONS: Record<string, string[]> = {
  begin: ['open'],
  goal: ['open', 'met', 'abandoned'],
  intent: ['open', 'running', 'done', 'blocked', 'exhausted', 'capacity_blocked'],
  fact: ['confirmed', 'dismissed'],
  finding: ['confirmed', 'dismissed'],
  hint: ['active', 'consumed'],
}

const GRAPH_STATUS_LABELS: Record<string, string> = {
  open: 'graphStatus.open',
  met: 'graphStatus.met',
  abandoned: 'graphStatus.abandoned',
  running: 'graphStatus.running',
  done: 'graphStatus.done',
  blocked: 'graphStatus.blocked',
  exhausted: 'graphStatus.exhausted',
  capacity_blocked: 'graphStatus.capacityBlocked',
  confirmed: 'graphStatus.confirmed',
  dismissed: 'graphStatus.dismissed',
  active: 'graphStatus.active',
  consumed: 'graphStatus.consumed',
  cold: 'graphStatus.cold',
  candidate: 'graphStatus.candidate',
  testing: 'graphStatus.testing',
  verified: 'graphStatus.verified',
  failed: 'graphStatus.failed',
}

const GRAPH_RELATIONS = ['spawns', 'derived_from', 'yields', 'proves', 'blocks', 'contradicts']

const STATUS_LABELS: Record<string, string> = {
  open: 'vulnStatus.open',
  confirmed: 'vulnStatus.confirmed',
  fixed: 'vulnStatus.fixed',
  ignored: 'vulnStatus.ignored',
  false_positive: 'vulnStatus.false_positive',
}

const route = useRoute()
const projectId = String(route.params.id ?? '')

const project = ref<Project | null>(null)
const counts = ref<ProjectCounts | null>(null)
const coverage = ref<ProjectCoverage | null>(null)
const activeTab = ref('facts')
const loading = ref(false)
const error = ref('')
const notice = ref('')

const facts = ref<Fact[]>([])
const factAssetFilter = ref('')
const factsHasMore = ref(false)
const factsNextOffset = ref(0)
const factsLoadingMore = ref(false)
const assets = ref<Asset[]>([])
const assetsHasMore = ref(false)
const assetsNextOffset = ref(0)
const assetsLoadingMore = ref(false)
const assetsFullyLoaded = ref(false)
const conversations = ref<Conversation[]>([])
const conversationsHasMore = ref(false)
const conversationsNextOffset = ref(0)
const conversationsLoadingMore = ref(false)
const vulnerabilities = ref<Vulnerability[]>([])
const vulnerabilitiesHasMore = ref(false)
const vulnerabilitiesNextOffset = ref(0)
const vulnerabilitiesLoadingMore = ref(false)
const graphNodes = ref<GraphNode[]>([])
const graphEdges = ref<GraphEdge[]>([])
const graphAssetFilter = ref('')
const graphScope = ref<'chain' | 'full'>('chain')
const editingNodeId = ref('')
const nodeDraft = reactive({
  kind: 'intent',
  title: '',
  detail: '',
  status: 'open',
  confidence: 80,
  severity: 'medium',
  assetId: '',
  parentId: '',
  relation: 'spawns',
})
const graphView = ref<'canvas' | 'list'>('canvas')
const graphSyncing = ref(false)
let layoutTimer: number | undefined
let graphRequestId = 0
const drawerOpen = ref(false)
const drawerMode = ref<'create' | 'edit' | 'view'>('create')

const factDraft = reactive({
  assetId: '',
  factType: 'general',
  key: '',
  value: '',
  summary: '',
  body: '',
  evidence: '',
  relation: '',
  confidence: 100,
})
const editingFactId = ref('')
const showFactModal = ref(false)
const factModalRef = ref<HTMLElement | null>(null)
const factKeyInput = ref<HTMLInputElement | null>(null)

function formatTime(value: string) {
  if (!value) {
    return '-'
  }
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function projectStatusLabel(status?: string) {
  return status ? t(`projectStatus.${status}`) : t('common.unknown')
}

function severityLabel(value: string) {
  const key = SEVERITY_LABELS[value]
  return key ? t(key) : value
}

function vulnerabilityStatusLabel(value: string) {
  const key = STATUS_LABELS[value]
  return key ? t(key) : value
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

async function loadProject() {
  loading.value = true
  error.value = ''
  try {
    const [projectResponse, summary] = await Promise.all([
      apiGet<Project>(`/projects/${projectId}`),
      apiGet<{ counts: ProjectCounts }>(`/projects/${projectId}/summary`),
    ])
    project.value = projectResponse
    counts.value = summary.counts
    void loadCoverage()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readProjectsFailed')
  } finally {
    loading.value = false
  }
}

// 覆盖率接口独立降级：失败时隐藏卡片，不影响项目详情其余内容。
async function loadCoverage() {
  if (!projectId) {
    return
  }
  try {
    coverage.value = await apiGet<ProjectCoverage>(`/projects/${projectId}/coverage`)
  } catch {
    coverage.value = null
  }
}

async function loadTab() {
  if (!projectId) {
    return
  }
  try {
    if ((activeTab.value === 'facts' || activeTab.value === 'attack') && !assetsFullyLoaded.value) {
      await loadAllProjectAssets()
    }
    if (activeTab.value === 'facts') {
      const factQuery = factAssetFilter.value
        ? `&assetId=${encodeURIComponent(factAssetFilter.value)}`
        : ''
      const response = await apiGet<PageResponse<Fact>>(
        `/projects/${projectId}/facts?limit=200&offset=0${factQuery}`,
      )
      facts.value = response.items ?? []
      factsHasMore.value = Boolean(response.hasMore)
      factsNextOffset.value = response.nextOffset || 0
    } else if (activeTab.value === 'attack') {
      const requestId = ++graphRequestId
      const query = new URLSearchParams()
      if (graphAssetFilter.value) {
        query.set('assetId', graphAssetFilter.value)
      }
      if (graphScope.value === 'chain') {
        query.set('view', 'chain')
      }
      const queryString = query.toString()
      const graph = await apiGet<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
        `/projects/${projectId}/graph${queryString ? `?${queryString}` : ''}`,
      )
      if (requestId !== graphRequestId) {
        return
      }
      graphNodes.value = graph.nodes ?? []
      graphEdges.value = graph.edges ?? []
    } else if (activeTab.value === 'assets') {
      const response = await apiGet<PageResponse<Asset>>(
        `/projects/${projectId}/assets?limit=200&offset=0`,
      )
      assets.value = response.items ?? []
      assetsHasMore.value = Boolean(response.hasMore)
      assetsNextOffset.value = response.nextOffset || 0
      assetsFullyLoaded.value = false
    } else if (activeTab.value === 'conversations') {
      const response = await apiGet<PageResponse<Conversation>>(
        `/projects/${projectId}/conversations?limit=200&offset=0`,
      )
      conversations.value = response.items ?? []
      conversationsHasMore.value = Boolean(response.hasMore)
      conversationsNextOffset.value = response.nextOffset || 0
    } else if (activeTab.value === 'vulnerabilities') {
      const response = await apiGet<PageResponse<Vulnerability>>(
        `/projects/${projectId}/vulnerabilities?limit=200&offset=0`,
      )
      vulnerabilities.value = response.items ?? []
      vulnerabilitiesHasMore.value = Boolean(response.hasMore)
      vulnerabilitiesNextOffset.value = response.nextOffset || 0
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readDataFailed')
  }
}

async function loadAllProjectAssets() {
  const loaded: Asset[] = []
  let offset = 0
  do {
    const response = await apiGet<PageResponse<Asset>>(
      `/projects/${projectId}/assets?limit=500&offset=${offset}`,
    )
    loaded.push(...(response.items ?? []))
    offset = response.nextOffset || loaded.length
    if (!response.hasMore) {
      break
    }
  } while (true)
  assets.value = loaded
  assetsHasMore.value = false
  assetsNextOffset.value = loaded.length
  assetsFullyLoaded.value = true
}

async function loadMorePage<T extends { id: string }>(
  items: Ref<T[]>,
  hasMore: Ref<boolean>,
  nextOffset: Ref<number>,
  loadingMore: Ref<boolean>,
  path: string,
) {
  if (!hasMore.value || loadingMore.value) {
    return
  }
  loadingMore.value = true
  try {
    const response = await apiGet<PageResponse<T>>(
      `${path}${path.includes('?') ? '&' : '?'}limit=200&offset=${nextOffset.value}`,
    )
    const existing = new Set(items.value.map((item) => item.id))
    items.value.push(...response.items.filter((item) => !existing.has(item.id)))
    hasMore.value = Boolean(response.hasMore)
    nextOffset.value = response.nextOffset || items.value.length
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readDataFailed')
  } finally {
    loadingMore.value = false
  }
}

function loadMoreFacts() {
  const query = factAssetFilter.value
    ? `?assetId=${encodeURIComponent(factAssetFilter.value)}`
    : ''
  return loadMorePage(
    facts,
    factsHasMore,
    factsNextOffset,
    factsLoadingMore,
    `/projects/${projectId}/facts${query}`,
  )
}

function loadMoreAssets() {
  return loadMorePage(assets, assetsHasMore, assetsNextOffset, assetsLoadingMore, `/projects/${projectId}/assets`)
}

function loadMoreConversations() {
  return loadMorePage(
    conversations,
    conversationsHasMore,
    conversationsNextOffset,
    conversationsLoadingMore,
    `/projects/${projectId}/conversations`,
  )
}

function loadMoreVulnerabilities() {
  return loadMorePage(
    vulnerabilities,
    vulnerabilitiesHasMore,
    vulnerabilitiesNextOffset,
    vulnerabilitiesLoadingMore,
    `/projects/${projectId}/vulnerabilities`,
  )
}

function switchTab(key: string) {
  showFactModal.value = false
  activeTab.value = key
  void loadTab()
}

function countValue(tab: (typeof TABS)[number]) {
  return counts.value?.[tab.countKey as keyof ProjectCounts] ?? 0
}

function resetFactDraft() {
  editingFactId.value = ''
  factDraft.assetId = factAssetFilter.value
  factDraft.factType = 'general'
  factDraft.key = ''
  factDraft.value = ''
  factDraft.summary = ''
  factDraft.body = ''
  factDraft.evidence = ''
  factDraft.relation = ''
  factDraft.confidence = 100
}

function editFact(fact: Fact) {
  editingFactId.value = fact.id
  factDraft.assetId = fact.assetId || ''
  factDraft.factType = fact.factType || 'general'
  factDraft.key = fact.key
  factDraft.value = fact.value
  factDraft.summary = fact.summary || fact.value
  factDraft.body = fact.body || ''
  factDraft.evidence = fact.evidence || ''
  factDraft.relation = fact.relation || ''
  factDraft.confidence = fact.confidence || 100
  showFactModal.value = true
  void nextTick(() => factModalRef.value?.focus())
}

function openCreateFact() {
  resetFactDraft()
  showFactModal.value = true
  void nextTick(() => factKeyInput.value?.focus())
}

function closeFactModal() {
  showFactModal.value = false
  resetFactDraft()
}

function saveFact() {
  if (!factDraft.key.trim()) {
    error.value = t('message.factKeyRequired')
    return
  }
  void run(async () => {
    if (editingFactId.value) {
      await apiPut(`/projects/${projectId}/facts/${editingFactId.value}`, {
        factType: factDraft.factType,
        value: factDraft.value,
        summary: factDraft.summary,
        body: factDraft.body,
        evidence: factDraft.evidence,
        relation: factDraft.relation,
        confidence: factDraft.confidence,
      })
    } else {
      await apiPost(`/projects/${projectId}/facts`, {
        assetId: factDraft.assetId,
        factType: factDraft.factType,
        key: factDraft.key,
        value: factDraft.value,
        summary: factDraft.summary,
        body: factDraft.body,
        evidence: factDraft.evidence,
        relation: factDraft.relation,
        confidence: factDraft.confidence,
      })
    }
    showFactModal.value = false
    resetFactDraft()
    await loadTab()
    await loadProject()
  }, t('project.saved'))
}

function removeFact(fact: Fact) {
  void run(async () => {
    await apiDelete(`/projects/${projectId}/facts/${fact.id}`)
    await loadTab()
    await loadProject()
  }, t('project.deletedFact'))
}

const nodeStatusOptions = computed(() => GRAPH_STATUS_OPTIONS[nodeDraft.kind] ?? [])

const nodesByKind = computed(() => {
  const result: Record<string, GraphNode[]> = {}
  GRAPH_KINDS.forEach((kind) => {
    result[kind] = graphNodes.value.filter((node) => node.kind === kind)
  })
  return result
})

const nodeMap = computed(() => new Map(graphNodes.value.map((node) => [node.id, node])))

watch(
  () => nodeDraft.kind,
  (kind) => {
    const options = GRAPH_STATUS_OPTIONS[kind] ?? []
    if (!options.includes(nodeDraft.status)) {
      nodeDraft.status = options[0] ?? 'open'
    }
  },
)

watch(factAssetFilter, () => {
  if (activeTab.value === 'facts') {
    void loadTab()
  }
})

watch(graphAssetFilter, () => {
  if (activeTab.value === 'attack') {
    void loadTab()
  }
})

watch(graphScope, () => {
  if (activeTab.value === 'attack') {
    void loadTab()
  }
})

function isSyntheticNode(node: GraphNode) {
  return node.source === 'synthetic' || node.id.startsWith('view-')
}

function isSyntheticEdge(edge: GraphEdge) {
  return edge.id.startsWith('view-')
}

function resetNodeDraft() {
  editingNodeId.value = ''
  nodeDraft.kind = 'intent'
  nodeDraft.title = ''
  nodeDraft.detail = ''
  nodeDraft.status = 'open'
  nodeDraft.confidence = 80
  nodeDraft.severity = 'medium'
  nodeDraft.assetId = ''
  nodeDraft.parentId = ''
  nodeDraft.relation = 'spawns'
}

function editNode(node: GraphNode) {
  editingNodeId.value = node.id
  nodeDraft.kind = node.kind
  nodeDraft.title = node.title
  nodeDraft.detail = node.detail
  nodeDraft.status = node.status
  nodeDraft.confidence = node.confidence || 0
  nodeDraft.severity = node.severity || 'medium'
  nodeDraft.assetId = node.assetId
  nodeDraft.parentId = ''
  nodeDraft.relation = 'spawns'
}

const currentNode = computed(
  () => graphNodes.value.find((node) => node.id === editingNodeId.value) ?? null,
)

function openCreateDrawer() {
  resetNodeDraft()
  drawerMode.value = 'create'
  drawerOpen.value = true
}

function openEditDrawer(node: GraphNode) {
  editNode(node)
  drawerMode.value = 'edit'
  drawerOpen.value = true
}

function closeDrawer() {
  drawerOpen.value = false
  resetNodeDraft()
}

function saveNode() {
  if (!nodeDraft.title.trim()) {
    error.value = t('graph.titleRequired')
    return
  }
  void run(async () => {
    const payload = {
      kind: nodeDraft.kind,
      title: nodeDraft.title.trim(),
      detail: nodeDraft.detail.trim(),
      status: nodeDraft.status,
      confidence: Number(nodeDraft.confidence) || 0,
      severity: nodeDraft.kind === 'finding' ? nodeDraft.severity : '',
      assetId: nodeDraft.assetId,
      parentId: editingNodeId.value ? '' : nodeDraft.parentId,
      relation: nodeDraft.relation,
    }
    if (editingNodeId.value) {
      await apiPut(`/projects/${projectId}/graph/nodes/${editingNodeId.value}`, payload)
    } else {
      await apiPost(`/projects/${projectId}/graph/nodes`, payload)
    }
    closeDrawer()
    await loadTab()
  }, t('graph.saved'))
}

function removeNode(node: GraphNode) {
  if (!window.confirm(t('graph.confirmDelete', { name: node.title }))) {
    return
  }
  void run(async () => {
    await apiDelete(`/projects/${projectId}/graph/nodes/${node.id}`)
    closeDrawer()
    await loadTab()
  }, t('graph.deleted'))
}

function importSteps() {
  void run(async () => {
    const result = await apiPost<{ imported: number }>(
      `/projects/${projectId}/attack-steps/import`,
    )
    notice.value = t('graph.imported', { count: result.imported ?? 0 })
    await loadTab()
    await loadProject()
  })
}

function syncGraph() {
  void run(async () => {
    graphSyncing.value = true
    try {
      const result = await apiPost<{ createdNodes: number; createdEdges: number }>(
        `/projects/${projectId}/graph/sync`,
      )
      notice.value = t('graph.synced', {
        nodes: result.createdNodes ?? 0,
        edges: result.createdEdges ?? 0,
      })
      await loadTab()
    } finally {
      graphSyncing.value = false
    }
  })
}

function nodeEdges(nodeId: string) {
  return graphEdges.value.filter((edge) => edge.srcId === nodeId || edge.dstId === nodeId)
}

function edgeText(edge: GraphEdge, node: GraphNode) {
  const relation = t(`graph.rel.${edge.rel}`)
  if (edge.srcId === node.id) {
    return `→ ${nodeMap.value.get(edge.dstId)?.title ?? '?'} · ${relation}`
  }
  return `← ${nodeMap.value.get(edge.srcId)?.title ?? '?'} · ${relation}`
}

function removeEdge(edge: GraphEdge) {
  void run(async () => {
    await apiDelete(`/projects/${projectId}/graph/edges/${edge.id}`)
    await loadTab()
  }, t('graph.edgeRemoved'))
}

function graphStatusLabel(status: string) {
  const key = GRAPH_STATUS_LABELS[status]
  return key ? t(key) : status
}

function assetName(assetId: string) {
  return assets.value.find((item) => item.id === assetId)?.name ?? assetId
}

function relationLabel(rel: string) {
  return t(`graph.rel.${rel}`)
}

function onCanvasLayoutChange(items: Array<{ id: string; x: number; y: number }>) {
  for (const item of items) {
    const target = graphNodes.value.find((node) => node.id === item.id)
    if (target && !isSyntheticNode(target)) {
      target.posX = item.x
      target.posY = item.y
    }
  }
  if (layoutTimer) {
    window.clearTimeout(layoutTimer)
  }
  layoutTimer = window.setTimeout(() => {
    const persisted = items.filter((item) => {
      const target = graphNodes.value.find((node) => node.id === item.id)
      return target && !isSyntheticNode(target)
    })
    if (persisted.length) {
      void saveLayout(persisted)
    }
  }, 500)
}

async function saveLayout(items: Array<{ id: string; x: number; y: number }>) {
  try {
    await apiPut(`/projects/${projectId}/graph/layout`, { items })
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  }
}

function onCanvasConnect(payload: { source: string; target: string }) {
  void run(async () => {
    await apiPost(`/projects/${projectId}/graph/edges`, {
      srcId: payload.source,
      dstId: payload.target,
      rel: 'spawns',
    })
    await loadTab()
  }, t('graph.edgeCreated'))
}

function onCanvasEdgeClick(edge: GraphEdge) {
  if (isSyntheticEdge(edge)) {
    return
  }
  if (!window.confirm(t('graph.confirmEdgeDelete'))) {
    return
  }
  void run(async () => {
    await apiDelete(`/projects/${projectId}/graph/edges/${edge.id}`)
    await loadTab()
  }, t('graph.edgeRemoved'))
}

function onCanvasNodeDblClick(node: GraphNode) {
  if (isSyntheticNode(node)) {
    openReadOnlyDrawer(node)
    return
  }
  openEditDrawer(node)
}

function openReadOnlyDrawer(node: GraphNode) {
  editNode(node)
  drawerMode.value = 'view'
  drawerOpen.value = true
}

onMounted(async () => {
  await loadProject()
  await loadTab()
})
</script>

<template>
  <section class="page factory-page page-projects">
    <header class="page-header project-detail-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="orange" />
        <div class="project-detail-heading">
          <p class="eyebrow">PROJECT CONTROL // MISSION DETAIL</p>
          <div class="project-title-line">
            <h1>{{ project?.name ?? t('project.detailEyebrow') }}</h1>
            <span
              class="project-detail-status"
              :class="`status-${project?.status || 'active'}`"
            >
              {{ projectStatusLabel(project?.status) }}
            </span>
          </div>
          <p class="project-page-hint">
            {{ project?.description || t('role.noDescription') }}
          </p>
          <dl class="project-brief">
            <div>
              <dt>{{ t('project.goalsLabel') }}</dt>
              <dd>{{ project?.goals || t('project.briefEmpty') }}</dd>
            </div>
            <div>
              <dt>{{ t('project.scopeLabel') }}</dt>
              <dd>{{ project?.scope || t('project.briefEmpty') }}</dd>
            </div>
          </dl>
        </div>
      </div>
      <div class="header-actions">
        <RouterLink class="button compact project-detail-action" to="/projects">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19 12H5M11 6l-6 6 6 6" /></svg>
          {{ t('project.backToList') }}
        </RouterLink>
        <button class="button compact project-detail-action" type="button" @click="loadProject(); loadTab()">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
          {{ t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error project-alert">{{ error }}</div>
    <div v-if="notice" class="alert ok project-alert">{{ notice }}</div>

    <section v-if="coverage" class="coverage-panel project-mission-panel">
      <header class="coverage-head">
        <div>
          <span class="project-code">01 // MISSION COVERAGE</span>
          <h2>{{ t('project.missionStatus') }}</h2>
        </div>
        <span class="coverage-rate">{{ Math.round(coverage.fullCoverageRatio * 100) }}%</span>
      </header>
      <div class="coverage-body">
        <div class="coverage-progress">
          <div class="coverage-bar">
            <i :style="{ width: `${Math.round(coverage.fullCoverageRatio * 100)}%` }"></i>
          </div>
          <div class="coverage-stats">
            <span>{{ t('project.coverageAssets', { tested: coverage.assetsTested, total: coverage.assetsTotal }) }}</span>
            <span>{{ t('project.fullCoverageAssets', { covered: coverage.assetsCovered, total: coverage.assetsTotal }) }}</span>
            <span>{{ t('project.partialAssets', { count: coverage.assetsPartial }) }}</span>
            <span>{{ t('project.blockedAssets', { count: coverage.assetsBlocked }) }}</span>
            <span>{{ t('project.untestedAssets', { count: coverage.assetsUntested }) }}</span>
          </div>
        </div>
        <div class="coverage-signals">
          <span>
            <small>{{ t('project.evidenceGapLabel') }}</small>
            <strong>{{ coverage.factsWithoutEvidence + coverage.findingsWithoutEvidence }}</strong>
          </span>
          <span>
            <small>{{ t('project.pendingIntentLabel') }}</small>
            <strong>{{ coverage.intentsOpen + coverage.intentsRunning }}</strong>
          </span>
          <span>
            <small>{{ t('project.assets') }}</small>
            <strong>{{ coverage.assetsTotal }}</strong>
          </span>
        </div>
      </div>
      <div v-if="coverage.nextTargets.length" class="coverage-targets">
        <div
          v-for="target in coverage.nextTargets.slice(0, 5)"
          :key="`${target.kind}-${target.refId}`"
          class="coverage-target"
        >
          <span class="target-kind">{{ target.kind }}</span>
          <span class="target-label">{{ target.label }}</span>
          <span class="target-reason">{{ target.reason }}</span>
          <span class="target-score">{{ target.score }}</span>
        </div>
      </div>
      <p v-else class="muted">{{ t('project.coverageComplete') }}</p>
    </section>

    <div class="count-row project-module-nav">
      <button
        v-for="tab in visibleTabs"
        :key="tab.key"
        class="count-chip"
        :class="{ active: activeTab === tab.key }"
        type="button"
        @click="switchTab(tab.key)"
      >
        <svg class="project-module-icon" viewBox="0 0 24 24" aria-hidden="true">
          <template v-if="tab.key === 'facts'">
            <path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" />
          </template>
          <template v-else-if="tab.key === 'attack'">
            <circle cx="5" cy="12" r="2" />
            <circle cx="12" cy="6" r="2" />
            <circle cx="19" cy="12" r="2" />
            <path d="M7 11l3-3M14 7l3 3" />
          </template>
          <template v-else-if="tab.key === 'assets'">
            <rect x="3" y="4" width="18" height="6" rx="2" />
            <rect x="3" y="14" width="18" height="6" rx="2" />
            <path d="M7 7h.01M7 17h.01" />
          </template>
          <template v-else-if="tab.key === 'conversations'">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </template>
          <template v-else>
            <path d="m12 3 7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z" />
            <path d="M12 8v4M12 16h.01" />
          </template>
        </svg>
        <small>{{ t(tab.labelKey) }}</small>
        <strong>{{ countValue(tab) }}</strong>
      </button>
    </div>

    <section v-if="activeTab === 'facts'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabFacts') }}</h2>
        <div class="header-actions">
          <select
            v-model="factAssetFilter"
            class="asset-filter-select"
            :aria-label="t('project.factAsset')"
          >
            <option value="">{{ t('project.allAssets') }}</option>
            <option v-for="asset in assets" :key="asset.id" :value="asset.id">
              {{ asset.name || asset.value }}
            </option>
          </select>
          <span class="panel-hint">{{ t('project.factHint') }}</span>
          <button class="button compact" type="button" @click="openCreateFact">
            {{ t('project.addFact') }}
          </button>
        </div>
      </header>
      <div v-if="facts.length" class="fact-grid">
        <article v-for="fact in facts" :key="fact.id" class="fact-card">
          <header>
            <span class="fact-type">{{ fact.factType || 'general' }}</span>
            <strong class="fact-key" :title="fact.key">{{ fact.key }}</strong>
            <span class="fact-confidence">{{ fact.confidence }}%</span>
          </header>
          <p class="fact-summary" :title="fact.summary || fact.value">
            {{ fact.summary || fact.value }}
          </p>
          <p v-if="fact.assetId" class="fact-scope">
            {{ t('project.factAsset') }}: {{ assetName(fact.assetId) }}
          </p>
          <p v-else class="fact-scope">{{ t('project.factProjectScope') }}</p>
          <p v-if="fact.body" class="fact-body" :title="fact.body">{{ fact.body }}</p>
          <dl class="fact-meta">
            <div v-if="fact.evidence">
              <dt>{{ t('project.factEvidence') }}</dt>
              <dd :title="fact.evidence">{{ fact.evidence }}</dd>
            </div>
            <div v-if="fact.relation">
              <dt>{{ t('project.factRelation') }}</dt>
              <dd :title="fact.relation">{{ fact.relation }}</dd>
            </div>
          </dl>
          <footer>
            <small>{{ formatTime(fact.updatedAt) }}</small>
            <div class="fact-actions">
              <button class="button compact" type="button" @click="editFact(fact)">
                {{ t('common.edit') }}
              </button>
              <button class="button compact danger" type="button" @click="removeFact(fact)">
                {{ t('common.delete') }}
              </button>
            </div>
          </footer>
        </article>
      </div>
      <p v-else class="fact-empty">{{ t('project.factEmpty') }}</p>
      <button
        v-if="factsHasMore"
        class="button panel-load-more"
        type="button"
        :disabled="factsLoadingMore"
        @click="loadMoreFacts"
      >
        {{ factsLoadingMore ? t('common.loading') : t('common.loadMore') }}
      </button>

      <div v-if="showFactModal" class="fact-modal-backdrop" @click.self="closeFactModal">
        <section
          ref="factModalRef"
          class="fact-modal"
          role="dialog"
          aria-modal="true"
          tabindex="-1"
          @keydown.esc="closeFactModal"
        >
          <header class="fact-modal-head">
            <h3>{{ editingFactId ? t('common.edit') : t('project.addFact') }}</h3>
            <button class="text-button dark" type="button" @click="closeFactModal">
              {{ t('common.close') }}
            </button>
          </header>
          <div class="fact-form">
            <div class="fact-form-head">
              <input
                ref="factKeyInput"
                v-model="factDraft.key"
                :aria-label="t('project.factKey')"
                :placeholder="t('project.factKeyPlaceholder')"
                :disabled="!!editingFactId"
              />
              <input
                v-model="factDraft.factType"
                :aria-label="t('project.factType')"
                :placeholder="t('project.factTypePlaceholder')"
              />
              <input
                v-model.number="factDraft.confidence"
                type="number"
                min="1"
                max="100"
                :aria-label="t('project.confidence')"
              />
            </div>
            <select
              v-model="factDraft.assetId"
              :aria-label="t('project.factAsset')"
              :disabled="!!editingFactId"
            >
              <option value="">{{ t('project.factProjectScope') }}</option>
              <option v-for="asset in assets" :key="asset.id" :value="asset.id">
                {{ asset.name || asset.value }}
              </option>
            </select>
            <input
              v-model="factDraft.summary"
              :aria-label="t('project.factSummary')"
              :placeholder="t('project.factSummaryPlaceholder')"
            />
            <textarea
              v-model="factDraft.body"
              rows="10"
              :aria-label="t('project.factBody')"
              :placeholder="t('project.factBodyPlaceholder')"
            ></textarea>
            <div class="fact-form-evidence">
              <input
                v-model="factDraft.evidence"
                :aria-label="t('project.factEvidence')"
                :placeholder="t('project.factEvidencePlaceholder')"
              />
              <input
                v-model="factDraft.relation"
                :aria-label="t('project.factRelation')"
                :placeholder="t('project.factRelationPlaceholder')"
              />
            </div>
            <div class="fact-form-actions">
              <button class="button compact" type="button" @click="saveFact">
                {{ editingFactId ? t('common.save') : t('project.addFact') }}
              </button>
              <button class="button compact" type="button" @click="closeFactModal">
                {{ t('common.cancel') }}
              </button>
            </div>
          </div>
        </section>
      </div>
    </section>

    <section v-if="activeTab === 'attack'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.attackSteps') }}</h2>
        <div class="header-actions">
          <select
            v-model="graphAssetFilter"
            class="asset-filter-select"
            :aria-label="t('project.assets')"
          >
            <option value="">{{ t('project.allAssets') }}</option>
            <option v-for="asset in assets" :key="asset.id" :value="asset.id">
              {{ asset.name || asset.value }}
            </option>
          </select>
          <div class="view-switch">
            <button
              type="button"
              :class="{ active: graphScope === 'chain' }"
              @click="graphScope = 'chain'"
            >
              {{ t('graph.scopeChain') }}
            </button>
            <button
              type="button"
              :class="{ active: graphScope === 'full' }"
              @click="graphScope = 'full'"
            >
              {{ t('graph.scopeFull') }}
            </button>
          </div>
          <div class="view-switch">
            <button
              type="button"
              :class="{ active: graphView === 'canvas' }"
              @click="graphView = 'canvas'"
            >
              {{ t('graph.viewCanvas') }}
            </button>
            <button
              type="button"
              :class="{ active: graphView === 'list' }"
              @click="graphView = 'list'"
            >
              {{ t('graph.viewList') }}
            </button>
          </div>
          <button class="button compact" type="button" @click="importSteps">
            {{ t('graph.importSteps') }}
          </button>
          <button
            class="button compact"
            type="button"
            :disabled="graphSyncing"
            @click="syncGraph"
          >
            {{ graphSyncing ? t('graph.syncing') : t('graph.sync') }}
          </button>
          <button class="button compact" type="button" @click="openCreateDrawer">
            {{ t('graph.addNode') }}
          </button>
          <span class="panel-hint">
            {{ graphView === 'canvas' ? t('graph.canvasHint') : t('graph.hint') }}
          </span>
        </div>
      </header>
      <div class="graph-brief">
        <div>
          <span class="graph-brief-label">{{ t('project.goalsLabel') }}</span>
          <p>{{ project?.goals || t('project.briefEmpty') }}</p>
        </div>
        <div>
          <span class="graph-brief-label">{{ t('project.scopeLabel') }}</span>
          <p>{{ project?.scope || t('project.briefEmpty') }}</p>
        </div>
      </div>
      <AttackGraphCanvas
        v-if="graphView === 'canvas'"
        :nodes="graphNodes"
        :edges="graphEdges"
        :assets="assets"
        @node-dblclick="onCanvasNodeDblClick"
        @edge-click="onCanvasEdgeClick"
        @connect="onCanvasConnect"
        @layout-change="onCanvasLayoutChange"
      />

      <div v-if="graphView === 'list'" class="graph-board">
        <section v-for="kind in GRAPH_KINDS" :key="kind" class="graph-column">
          <header class="graph-column-header">
            <span class="graph-kind-dot" :class="`kind-${kind}`"></span>
            <strong>{{ t(`graph.kind.${kind}`) }}</strong>
            <small>{{ nodesByKind[kind].length }}</small>
          </header>
          <article v-for="node in nodesByKind[kind]" :key="node.id" class="graph-node">
            <div class="graph-node-head">
              <strong>{{ node.title }}</strong>
              <span class="chip chip-plain">{{ graphStatusLabel(node.status) }}</span>
            </div>
            <p v-if="node.detail" class="graph-node-detail">{{ node.detail }}</p>
            <div class="graph-node-meta">
              <span v-if="node.assetId" class="chip chip-plain">{{ assetName(node.assetId) }}</span>
              <span v-if="node.severity" class="chip" :class="`sev-${node.severity}`">
                {{ severityLabel(node.severity) }}
              </span>
              <span v-if="node.kind === 'fact' || node.kind === 'hint'" class="chip chip-plain">
                {{ t('graph.confidenceShort', { value: node.confidence }) }}
              </span>
              <span v-if="node.source !== 'manual'" class="chip chip-plain">
                {{ t('graph.importedSource') }}
              </span>
            </div>
            <ul v-if="nodeEdges(node.id).length" class="graph-node-edges">
              <li v-for="edge in nodeEdges(node.id)" :key="edge.id">
                <span>{{ edgeText(edge, node) }}</span>
                <button
                  v-if="!isSyntheticEdge(edge)"
                  class="link-button"
                  type="button"
                  @click="removeEdge(edge)"
                >
                  ×
                </button>
              </li>
            </ul>
            <div v-if="!isSyntheticNode(node)" class="graph-node-actions">
              <button class="button compact" type="button" @click="openEditDrawer(node)">
                {{ t('common.edit') }}
              </button>
              <button class="button compact danger" type="button" @click="removeNode(node)">
                {{ t('common.delete') }}
              </button>
            </div>
          </article>
          <p v-if="!nodesByKind[kind].length" class="graph-empty">{{ t('graph.emptyColumn') }}</p>
        </section>
      </div>

      <div v-if="drawerOpen" class="drawer-mask" @click="closeDrawer"></div>
      <aside v-if="drawerOpen" class="node-drawer">
        <header class="drawer-header">
          <h3>{{ drawerMode === 'create' ? t('graph.addNode') : t('graph.editNode') }}</h3>
          <button class="drawer-close" type="button" @click="closeDrawer">×</button>
        </header>
        <fieldset :disabled="drawerMode === 'view'" class="drawer-body">
          <label class="drawer-field">
            <span>{{ t('graph.kindLabel') }}</span>
            <select v-model="nodeDraft.kind">
              <option v-for="kind in GRAPH_CREATE_KINDS" :key="kind" :value="kind">
                {{ t(`graph.kind.${kind}`) }}
              </option>
            </select>
          </label>
          <label class="drawer-field">
            <span>{{ t('graph.titleLabel') }}</span>
            <input v-model="nodeDraft.title" :placeholder="t('graph.titlePlaceholder')" />
          </label>
          <label class="drawer-field">
            <span>{{ t('graph.statusLabel') }}</span>
            <select v-model="nodeDraft.status">
              <option v-for="status in nodeStatusOptions" :key="status" :value="status">
                {{ graphStatusLabel(status) }}
              </option>
            </select>
          </label>
          <label v-if="nodeDraft.kind === 'finding'" class="drawer-field">
            <span>{{ t('graph.severityLabel') }}</span>
            <select v-model="nodeDraft.severity">
              <option value="critical">{{ t('severity.critical') }}</option>
              <option value="high">{{ t('severity.high') }}</option>
              <option value="medium">{{ t('severity.medium') }}</option>
              <option value="low">{{ t('severity.low') }}</option>
              <option value="info">{{ t('severity.info') }}</option>
            </select>
          </label>
          <label
            v-if="nodeDraft.kind === 'fact' || nodeDraft.kind === 'hint'"
            class="drawer-field"
          >
            <span>{{ t('graph.confidenceLabel') }}</span>
            <input v-model.number="nodeDraft.confidence" type="number" min="0" max="100" />
          </label>
          <label class="drawer-field">
            <span>{{ t('graph.assetLabel') }}</span>
            <select v-model="nodeDraft.assetId">
              <option value="">{{ t('graph.assetNone') }}</option>
              <option v-for="asset in assets" :key="asset.id" :value="asset.id">
                {{ asset.name }}
              </option>
            </select>
          </label>
          <template v-if="drawerMode === 'create'">
            <label class="drawer-field">
              <span>{{ t('graph.parentLabel') }}</span>
              <select v-model="nodeDraft.parentId">
                <option value="">{{ t('graph.parentNone') }}</option>
                <option v-for="node in graphNodes" :key="node.id" :value="node.id">
                  {{ t(`graph.kind.${node.kind}`) }} · {{ node.title }}
                </option>
              </select>
            </label>
            <label v-if="nodeDraft.parentId" class="drawer-field">
              <span>{{ t('graph.relationLabel') }}</span>
              <select v-model="nodeDraft.relation">
                <option v-for="rel in GRAPH_RELATIONS" :key="rel" :value="rel">
                  {{ relationLabel(rel) }}
                </option>
              </select>
            </label>
          </template>
          <label class="drawer-field">
            <span>{{ t('graph.detailLabel') }}</span>
            <textarea
              v-model="nodeDraft.detail"
              rows="8"
              :placeholder="t('graph.detailPlaceholder')"
            ></textarea>
          </label>
          <div v-if="drawerMode !== 'create' && currentNode" class="drawer-relations">
            <span class="drawer-relations-title">{{ t('graph.relationsLabel') }}</span>
            <ul v-if="nodeEdges(currentNode.id).length">
              <li v-for="edge in nodeEdges(currentNode.id)" :key="edge.id">
                <span>{{ edgeText(edge, currentNode) }}</span>
                <button
                  v-if="drawerMode === 'edit' && !isSyntheticEdge(edge)"
                  class="link-button"
                  type="button"
                  @click="removeEdge(edge)"
                >
                  ×
                </button>
              </li>
            </ul>
            <p v-else class="drawer-relations-empty">{{ t('graph.noRelations') }}</p>
          </div>
        </fieldset>
        <footer class="drawer-footer">
          <button
            v-if="drawerMode !== 'view'"
            class="button compact"
            type="button"
            @click="saveNode"
          >
            {{ t('common.save') }}
          </button>
          <button
            v-if="drawerMode === 'edit' && currentNode"
            class="button compact danger"
            type="button"
            @click="removeNode(currentNode)"
          >
            {{ t('common.delete') }}
          </button>
          <button class="button compact" type="button" @click="closeDrawer">
            {{ t('graph.close') }}
          </button>
        </footer>
      </aside>
    </section>

    <section v-if="activeTab === 'assets'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabAssets') }}</h2>
        <RouterLink class="panel-link" to="/business">{{ t('project.createAsset') }}</RouterLink>
      </header>
      <div class="factory-table-scroll">
        <table class="data-list">
        <thead>
          <tr>
            <th>{{ t('project.assetName') }}</th>
            <th>{{ t('vulnerability.type') }}</th>
            <th>{{ t('project.assetValue') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('project.assetCriticality') }}</th>
            <th>{{ t('project.assetRisk') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="asset in assets" :key="asset.id">
            <td>{{ asset.name }}</td>
            <td>{{ asset.kind }}</td>
            <td class="wrap-cell">{{ asset.value }}</td>
            <td>{{ asset.status }}</td>
            <td>{{ asset.criticality }}</td>
            <td>{{ asset.riskScore }}</td>
          </tr>
          <tr v-if="!assets.length">
            <td class="empty-cell" colspan="6">{{ t('project.assetEmpty') }}</td>
          </tr>
        </tbody>
        </table>
      </div>
      <button
        v-if="assetsHasMore"
        class="button panel-load-more"
        type="button"
        :disabled="assetsLoadingMore"
        @click="loadMoreAssets"
      >
        {{ assetsLoadingMore ? t('common.loading') : t('common.loadMore') }}
      </button>
    </section>

    <section v-if="activeTab === 'conversations'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabConversations') }}</h2>
      </header>
      <ul class="simple-list">
        <li v-for="conversation in conversations" :key="conversation.id">
          <RouterLink :to="`/chat?conversationId=${conversation.id}`">
            {{ conversation.title }}
          </RouterLink>
          <small>{{ formatTime(conversation.updatedAt) }}</small>
        </li>
      </ul>
      <p v-if="!conversations.length" class="empty-cell">{{ t('project.conversationEmpty') }}</p>
      <button
        v-if="conversationsHasMore"
        class="button panel-load-more"
        type="button"
        :disabled="conversationsLoadingMore"
        @click="loadMoreConversations"
      >
        {{ conversationsLoadingMore ? t('common.loading') : t('common.loadMore') }}
      </button>
    </section>

    <section v-if="activeTab === 'vulnerabilities'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabVulnerabilities') }}</h2>
        <RouterLink class="panel-link" to="/vulnerabilities">{{ t('project.goVulnerabilities') }}</RouterLink>
      </header>
      <div class="factory-table-scroll">
        <table class="data-list">
        <thead>
          <tr>
            <th>{{ t('vulnerability.severity') }}</th>
            <th>{{ t('vulnerability.name') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('vulnerability.target') }}</th>
            <th>{{ t('common.updatedAt') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in vulnerabilities" :key="item.id">
            <td><span class="chip" :class="`sev-${item.severity}`">{{ severityLabel(item.severity) }}</span></td>
            <td>{{ item.title }}</td>
            <td>{{ vulnerabilityStatusLabel(item.status) }}</td>
            <td class="wrap-cell">{{ item.target || '-' }}</td>
            <td>{{ formatTime(item.updatedAt) }}</td>
          </tr>
          <tr v-if="!vulnerabilities.length">
            <td class="empty-cell" colspan="5">{{ t('project.vulnerabilityEmpty') }}</td>
          </tr>
        </tbody>
        </table>
      </div>
      <button
        v-if="vulnerabilitiesHasMore"
        class="button panel-load-more"
        type="button"
        :disabled="vulnerabilitiesLoadingMore"
        @click="loadMoreVulnerabilities"
      >
        {{ vulnerabilitiesLoadingMore ? t('common.loading') : t('common.loadMore') }}
      </button>
    </section>
  </section>
</template>

<style scoped>
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.asset-filter-select {
  min-width: 180px;
  max-width: 260px;
  padding: 7px 10px;
  color: var(--text-primary);
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.panel-load-more {
  width: 100%;
  margin-top: 12px;
}

.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.count-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}

.count-chip {
  display: grid;
  gap: 2px;
  padding: 10px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid var(--text-muted);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
  text-align: left;
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease;
}

.count-chip:hover,
.count-chip:focus-visible {
  border-color: var(--accent);
  outline: none;
  box-shadow: none;
}

.count-chip.active {
  border-left-color: var(--accent);
  background: var(--accent-soft);
}

.count-row small {
  color: var(--text-muted);
  font-size: 12px;
}

.count-row strong {
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.tab-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border);
}

.tab-button {
  padding: 9px 14px;
  border: 0;
  border-bottom: 3px solid transparent;
  color: var(--text-secondary);
  background: transparent;
  font-size: 13px;
  cursor: pointer;
}

.tab-button.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
  font-weight: 700;
}

.panel {
  padding: 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.panel-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.panel-header h2 {
  margin: 0;
  font-size: 17px;
}

.panel-hint,
.panel-link {
  color: var(--text-muted);
  font-size: 12px;
}

.fact-form {
  display: grid;
  gap: 8px;
  margin-bottom: 14px;
}

.fact-form-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px;
}

.fact-form input,
.fact-form textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
}

.fact-form textarea {
  min-height: 58px;
  resize: vertical;
}

.fact-form-actions {
  display: flex;
  gap: 8px;
}

.inline-form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 8px;
  margin-bottom: 14px;
}

.inline-form input,
.inline-form select {
  padding: 8px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
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
  font-family: var(--mono);
  font-size: 11px;
  background: var(--surface-soft);
}

.wrap-cell {
  max-width: min(560px, 40vw);
  overflow-wrap: anywhere;
  color: var(--text-secondary);
}

.row-actions {
  display: flex;
  gap: 6px;
}

.empty-cell {
  padding: 20px 10px;
  color: var(--text-muted);
  text-align: center;
}

.graph-board {
  display: grid;
  grid-template-columns:
    minmax(190px, 0.85fr)
    minmax(190px, 0.85fr)
    minmax(210px, 0.95fr)
    minmax(280px, 1.25fr)
    minmax(300px, 1.35fr)
    minmax(200px, 0.9fr);
  gap: 12px;
  padding-bottom: 4px;
  overflow-x: auto;
}

.graph-column {
  display: grid;
  gap: 8px;
  align-content: start;
  min-width: 0;
}

.graph-column-header {
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.graph-column-header small {
  margin-left: auto;
  color: var(--text-muted);
}

.graph-kind-dot {
  width: 8px;
  height: 8px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--accent);
}

.graph-kind-dot.kind-begin {
  background: #8b949e;
}

.graph-kind-dot.kind-goal {
  background: var(--success);
}

.graph-kind-dot.kind-intent {
  background: var(--accent-solid);
}

.graph-kind-dot.kind-fact {
  background: var(--accent-lime);
}

.graph-kind-dot.kind-finding {
  background: var(--accent-coral);
}

.graph-kind-dot.kind-hint {
  background: #a371f7;
}

.graph-node {
  display: grid;
  gap: 6px;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.graph-node-head {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  justify-content: space-between;
}

.graph-node-detail {
  margin: 0;
  color: var(--text-secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
}

.graph-node-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.graph-node-edges {
  display: grid;
  gap: 4px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.graph-node-edges li {
  display: flex;
  gap: 6px;
  align-items: center;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 11px;
}

.graph-node-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.graph-empty {
  margin: 0;
  padding: 12px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  color: var(--text-muted);
  font-size: 12px;
  text-align: center;
}

.link-button {
  padding: 0;
  border: none;
  background: none;
  color: var(--accent);
  font-size: 12px;
  cursor: pointer;
}

.chip {
  padding: 1px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
  color: var(--text-secondary);
  font-size: 12px;
}

.chip-done {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.chip-doing {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.chip-failed {
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.chip-plain {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.sev-critical {
  color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.sev-high {
  color: #ffab00;
  background: color-mix(in srgb, #ffab00 10%, var(--surface));
}

.sev-medium {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.sev-low {
  color: var(--accent);
  background: var(--accent-soft);
}

.sev-info {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.simple-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.simple-list li {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.simple-list a {
  color: var(--accent);
  font-weight: 700;
  text-decoration: none;
}

.simple-list small {
  color: var(--text-muted);
  font-size: 12px;
}

.view-switch {
  display: inline-flex;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.view-switch button {
  padding: 4px 10px;
  border: none;
  border-radius: var(--radius);
  background: transparent;
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
}

.view-switch button.active {
  background: var(--accent-lime);
  color: #ffffff;
}

.drawer-mask {
  position: fixed;
  inset: 0;
  z-index: 40;
  background: rgb(15 23 42 / 0.35);
}

.node-drawer {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  z-index: 41;
  display: flex;
  flex-direction: column;
  width: min(420px, 92vw);
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
}

.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.drawer-header h3 {
  margin: 0;
  font-size: 15px;
}

.drawer-close {
  padding: 0 6px;
  border: none;
  background: none;
  color: var(--text-muted);
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
}

.drawer-body {
  display: grid;
  flex: 1;
  gap: 12px;
  min-width: 0;
  margin: 0;
  padding: 16px;
  border: 0;
  overflow-y: auto;
}

.drawer-field {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.drawer-field input,
.drawer-field select,
.drawer-field textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: transparent;
  color: inherit;
  font: inherit;
  font-weight: 400;
}

.drawer-field textarea {
  min-height: 160px;
  line-height: 1.55;
  resize: vertical;
}

.drawer-relations {
  display: grid;
  gap: 6px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.drawer-relations-title {
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.drawer-relations ul {
  display: grid;
  gap: 4px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.drawer-relations li {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 12px;
}

.drawer-relations-empty {
  margin: 0;
  color: var(--text-muted);
  font-size: 12px;
}

.drawer-footer {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid var(--line);
  background: var(--surface-soft);
}

.project-brief {
  display: grid;
  gap: 4px;
  margin: 10px 0 0;
}

.project-brief div {
  display: flex;
  gap: 8px;
  align-items: baseline;
}

.project-brief dt {
  flex-shrink: 0;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 600;
}

.project-brief dd {
  margin: 0;
  color: var(--text-secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.graph-brief {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  margin-bottom: 12px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-soft);
  box-shadow: none;
}

.graph-brief > div {
  display: grid;
  gap: 4px;
  min-width: 0;
}

.graph-brief-label {
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 600;
}

.graph-brief p {
  margin: 0;
  color: var(--text-secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.coverage-panel {
  margin-bottom: 16px;
  padding: 16px 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.coverage-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.coverage-head h2 {
  margin: 0;
  font-size: 15px;
}

.coverage-rate {
  color: var(--accent);
  font-family: var(--mono);
  font-size: 20px;
  font-weight: 700;
}

.coverage-bar {
  height: 6px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.coverage-bar i {
  display: block;
  height: 100%;
  background: var(--accent);
}

.coverage-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  margin-top: 10px;
  color: var(--text-muted);
  font-size: 12px;
}

.coverage-targets {
  display: grid;
  gap: 6px;
  margin-top: 12px;
}

.coverage-target {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr) auto 44px;
  gap: 10px;
  align-items: center;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
  font-size: 12px;
}

.target-kind {
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
  text-align: center;
  text-transform: uppercase;
}

.target-label {
  overflow: hidden;
  color: var(--text-secondary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.target-reason {
  color: var(--text-muted);
  white-space: nowrap;
}

.target-score {
  color: var(--accent);
  font-family: var(--mono);
  text-align: right;
}

.fact-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 14px;
}

.fact-card {
  display: grid;
  gap: 8px;
  align-content: start;
  padding: 14px 16px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.fact-card header {
  display: flex;
  gap: 8px;
  align-items: center;
  min-width: 0;
}

.fact-type {
  flex: 0 0 auto;
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 11px;
}

.fact-key {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 14px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.fact-confidence {
  flex: 0 0 auto;
  margin-left: auto;
  padding: 2px 8px;
  border: 1px solid var(--accent-line);
  border-radius: var(--radius);
  color: var(--accent);
  background: var(--accent-soft);
  font-family: var(--mono);
  font-size: 11px;
}

.fact-summary,
.fact-body {
  display: -webkit-box;
  margin: 0;
  overflow: hidden;
  color: var(--text-secondary);
  -webkit-box-orient: vertical;
  font-size: 13px;
  line-height: 1.5;
}

.fact-summary {
  -webkit-line-clamp: 2;
}

.fact-scope {
  margin: 0;
  color: var(--accent);
  font-size: 11px;
}

.fact-body {
  color: var(--text-muted);
  -webkit-line-clamp: 4;
}

.fact-meta {
  display: grid;
  gap: 4px;
  margin: 0;
  color: var(--text-muted);
  font-size: 12px;
}

.fact-meta div {
  display: flex;
  gap: 6px;
  min-width: 0;
}

.fact-meta dt {
  flex: 0 0 auto;
}

.fact-meta dd {
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.fact-card footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}

.fact-card footer small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 11px;
}

.fact-actions {
  display: flex;
  gap: 6px;
}

.fact-empty {
  margin: 0;
  padding: 22px 10px;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
}

.fact-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 6, 12, 0.55);
}

.fact-modal {
  display: grid;
  gap: 14px;
  width: min(100%, 780px);
  max-height: min(90vh, 900px);
  overflow: auto;
  padding: 22px 26px 24px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.fact-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.fact-modal-head h3 {
  margin: 0;
  font-size: 16px;
}

.fact-modal .fact-form {
  gap: 12px;
  margin-bottom: 0;
}

.fact-modal .fact-form input,
.fact-modal .fact-form textarea,
.fact-modal .fact-form select {
  padding: 10px 12px;
  font-size: 13px;
}

.fact-modal .fact-form select {
  color: var(--text-primary);
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.fact-modal .fact-form textarea {
  min-height: 240px;
}

.fact-form-head {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) 120px;
  gap: 8px;
}

.fact-form-evidence {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

@media (max-width: 640px) {
  .fact-form-head,
  .fact-form-evidence {
    grid-template-columns: 1fr;
  }
}

</style>

<style scoped>
/* Project mission control */
.main-column .page-projects {
  --project-accent: #fb923c;
  --project-mint: #34d399;
  --project-coral: #fb7185;
  --project-violet: #9d8cff;
  --project-panel: color-mix(in srgb, var(--surface) 95%, #100d08);
  --project-line: color-mix(in srgb, var(--border-strong) 58%, transparent);
}

.main-column .page-projects .project-detail-header {
  align-items: center;
  min-height: 96px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--project-accent) 30%, var(--border)) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-projects .project-detail-header::after {
  display: none;
}

.project-detail-heading {
  min-width: 0;
}

.project-title-line {
  display: flex;
  flex-wrap: wrap;
  gap: 9px;
  align-items: center;
}

.project-title-line h1 {
  overflow-wrap: anywhere;
}

.project-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 12px;
  line-height: 1.5;
}

.project-detail-status {
  padding: 2px 7px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 600;
}

.project-detail-status.status-active {
  border-color: color-mix(in srgb, var(--project-mint) 45%, var(--border));
  color: var(--project-mint);
  background: color-mix(in srgb, var(--project-mint) 7%, transparent);
}

.project-detail-status.status-planning {
  border-color: color-mix(in srgb, var(--project-accent) 45%, var(--border));
  color: var(--project-accent);
}

.project-detail-status.status-paused {
  color: #facc15;
}

.project-detail-status.status-done {
  border-color: color-mix(in srgb, var(--project-violet) 45%, var(--border));
  color: var(--project-violet);
}

.project-detail-status.status-archived {
  color: var(--text-muted);
}

.project-detail-action {
  display: inline-flex;
  gap: 5px;
  align-items: center;
}

.project-detail-action svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.project-brief {
  gap: 3px;
  margin-top: 8px;
}

.project-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.project-mission-panel {
  margin-bottom: 10px;
  padding: 0;
  overflow: hidden;
  border-color: color-mix(in srgb, var(--project-accent) 22%, var(--border));
  border-radius: 4px;
  background: var(--surface);
}

.project-mission-panel .coverage-head {
  margin: 0;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}

.project-mission-panel .coverage-head h2 {
  margin: 2px 0 0;
  font-size: 13px;
}

.project-code {
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.1em;
}

.project-mission-panel .coverage-rate {
  color: var(--project-accent);
  font-size: 24px;
  font-weight: 500;
}

.coverage-body {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  align-items: center;
  padding: 11px 12px;
}

.coverage-progress {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.coverage-progress .coverage-bar {
  height: 7px;
  border: 0;
  border-radius: 2px;
  background: color-mix(in srgb, var(--field-bg) 78%, var(--project-accent));
}

.coverage-progress .coverage-bar i {
  background:
    repeating-linear-gradient(
      90deg,
      var(--project-accent) 0 8px,
      color-mix(in srgb, var(--project-accent) 58%, transparent) 8px 10px
    );
}

.coverage-progress .coverage-stats {
  gap: 5px 12px;
  margin: 0;
  font-family: var(--mono);
  font-size: 8px;
}

.coverage-signals {
  display: grid;
  grid-template-columns: repeat(3, minmax(74px, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid var(--project-line);
  border-radius: 4px;
  background: var(--project-line);
}

.coverage-signals span {
  display: grid;
  gap: 2px;
  min-width: 74px;
  padding: 7px 9px;
  background: var(--project-panel);
}

.coverage-signals small {
  color: var(--text-muted);
  font-size: 8px;
  white-space: nowrap;
}

.coverage-signals strong {
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 16px;
  font-weight: 500;
}

.project-mission-panel .coverage-targets {
  gap: 1px;
  margin: 0;
  padding: 1px;
  border-top: 1px solid var(--border);
  background: var(--project-line);
}

.project-mission-panel .coverage-target {
  border: 0;
  border-radius: 0;
  background: var(--project-panel);
}

.project-mission-panel > .muted {
  margin: 0;
  padding: 10px 12px;
  border-top: 1px solid var(--border);
  font-size: 10px;
}

.project-module-nav {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 10px;
  overflow: visible;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.project-module-nav .count-chip {
  display: grid;
  grid-template-columns: 20px minmax(0, 1fr);
  grid-template-areas:
    'icon label'
    'icon value';
  gap: 2px 7px;
  align-items: center;
  min-height: 64px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: var(--surface);
}

.project-module-nav .count-chip:hover {
  border-color: var(--border);
  border-left-color: var(--project-accent);
  background: color-mix(in srgb, var(--project-accent) 5%, var(--surface));
}

.project-module-nav .count-chip.active {
  border-left-color: var(--project-accent);
  background: color-mix(in srgb, var(--project-accent) 6%, var(--surface));
}

.project-module-icon {
  grid-area: icon;
  width: 16px;
  height: 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
  color: var(--project-accent);
}

.project-module-nav .count-chip small {
  grid-area: label;
  color: var(--text-muted);
  font-size: 10px;
}

.project-module-nav .count-chip strong {
  grid-area: value;
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 18px;
  font-weight: 500;
}

.main-column .page-projects > .panel {
  padding: 0;
  overflow: hidden;
  border-color: color-mix(in srgb, var(--project-accent) 20%, var(--border));
  border-radius: 5px;
  background: var(--project-panel);
}

.main-column .page-projects > .panel > .panel-header {
  margin: 0;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 42%, transparent);
}

.main-column .page-projects > .panel > .panel-header h2 {
  font-size: 13px;
}

.main-column .page-projects > .panel > .panel-header .header-actions {
  flex-wrap: wrap;
  justify-content: flex-end;
}

.main-column .page-projects > .panel > .fact-grid,
.main-column .page-projects > .panel > .simple-list,
.main-column .page-projects > .panel > .fact-empty,
.main-column .page-projects > .panel > .empty-cell {
  margin: 11px;
}

.main-column .page-projects > .panel > .fact-grid {
  gap: 9px;
}

.fact-card {
  border-color: var(--project-line);
  border-radius: 4px;
  background: color-mix(in srgb, var(--surface) 96%, var(--project-accent));
}

.fact-card:hover {
  border-color: color-mix(in srgb, var(--project-accent) 38%, var(--border));
}

.fact-card header {
  gap: 6px;
}

.fact-type,
.fact-confidence {
  border-radius: 2px;
  font-size: 8px;
}

.fact-key {
  font-size: 12px;
}

.fact-summary {
  font-size: 11px;
}

.fact-body,
.fact-meta,
.fact-scope {
  font-size: 9px;
}

.fact-card footer {
  border-top-color: var(--project-line);
}

.main-column .page-projects .factory-table-scroll {
  margin: 11px;
}

.main-column .page-projects .data-list {
  border-color: var(--project-line);
  border-radius: 4px;
  background: var(--project-panel);
}

.main-column .page-projects .data-list th {
  font-size: 8px;
}

.main-column .page-projects .data-list td {
  font-size: 9px;
}

.main-column .page-projects .simple-list {
  gap: 1px;
  overflow: hidden;
  border: 1px solid var(--project-line);
  border-radius: 4px;
  background: var(--project-line);
}

.main-column .page-projects .simple-list li {
  border: 0;
  border-radius: 0;
  background: var(--project-panel);
}

.main-column .page-projects .simple-list a {
  color: var(--project-accent);
}

.main-column .page-projects .panel-load-more {
  width: auto;
  margin: 0 11px 11px;
}

.graph-brief {
  margin: 11px;
  border-color: var(--project-line);
  background: color-mix(in srgb, var(--field-bg) 52%, transparent);
}

.main-column .page-projects .fact-modal-backdrop {
  z-index: 80;
  background: rgba(4, 9, 10, 0.7);
  backdrop-filter: blur(3px);
}

.main-column .page-projects .fact-modal {
  align-content: start;
  border-color: color-mix(in srgb, var(--project-accent) 32%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--project-accent) 4%, transparent), transparent 160px),
    var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
}

.main-column .page-projects .drawer-mask {
  z-index: 80;
  background: rgba(4, 9, 10, 0.68);
  backdrop-filter: blur(3px);
}

.main-column .page-projects .node-drawer {
  z-index: 81;
  border-left-color: color-mix(in srgb, var(--project-accent) 32%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--project-accent) 4%, transparent), transparent 160px),
    var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.42);
}

.main-column .page-projects .drawer-header,
.main-column .page-projects .drawer-footer {
  background: color-mix(in srgb, var(--surface-soft) 76%, transparent);
}

@media (max-width: 980px) {
  .coverage-body {
    grid-template-columns: 1fr;
  }

  .coverage-signals {
    width: fit-content;
  }
}

@media (max-width: 760px) {
  .main-column .page-projects .project-detail-header {
    align-items: stretch;
  }

  .project-detail-header .header-actions {
    width: 100%;
  }

  .project-detail-action {
    flex: 1;
    justify-content: center;
  }

  .project-title-line {
    align-items: flex-start;
  }

  .project-brief div {
    align-items: flex-start;
    flex-direction: column;
    gap: 2px;
  }

  .coverage-signals {
    width: 100%;
  }

  .project-module-nav {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .project-module-nav .count-chip:last-child {
    grid-column: span 2;
  }

  .main-column .page-projects > .panel > .panel-header {
    align-items: stretch;
    flex-direction: column;
  }

  .main-column .page-projects > .panel > .panel-header .header-actions {
    align-items: stretch;
    flex-direction: column;
    width: 100%;
  }

  .asset-filter-select {
    width: 100%;
    max-width: none;
  }

  .view-switch {
    width: 100%;
  }

  .view-switch button {
    flex: 1;
  }

  .fact-grid {
    grid-template-columns: 1fr;
  }

  .project-mission-panel .coverage-target {
    grid-template-columns: 58px minmax(0, 1fr) 34px;
  }

  .target-reason {
    display: none;
  }

  .main-column .page-projects .fact-modal {
    max-height: none;
    width: 100%;
    height: 100dvh;
    padding: 14px;
    border: 0;
    border-radius: 0;
  }

  .main-column .page-projects .fact-modal-backdrop {
    padding: 0;
    place-items: stretch;
  }

  .main-column .page-projects .fact-modal .fact-form textarea {
    min-height: 180px;
  }

  .main-column .page-projects .node-drawer {
    width: 100%;
  }
}
</style>
