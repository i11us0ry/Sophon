<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import AttackGraphCanvas from '../components/graph/AttackGraphCanvas.vue'
import DataPagination from '../components/DataPagination.vue'
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
  constraints?: string
  scope: string
  status?: string
  createdAt: string
  updatedAt: string
}

interface ProjectCounts {
  facts: number
  pendingIntents: number
  totalIntents: number
  capacityBlockedIntents: number
  blockedIntents: number
  intentCapacity: number
  oldestIntentAt: number
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
  pendingIntentTargets?: CoverageTarget[]
  evidenceGapTargets?: CoverageTarget[]
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
  executionState?: string
  outcomeState?: string
  stateReason?: string
  result?: string
  evidence?: string
  evidenceRefs?: string[]
  findingId?: string
  attempts?: number
  testConfidence?: number
  lastFinishedAt?: string
  lastWorkerSessionId?: string
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
  source?: string
  qualityStatus?: string
  criticality: string
  riskScore: number
  updatedAt?: string
}

interface AssetOverview extends Asset {
  authorizationState: string
  workState: string
  priority: number
  stateReason: string
  coverageStatus: string
  testsTotal: number
  testsCovered: number
  findings: number
  updatedAt: string
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

interface VulnerabilityDetail extends Vulnerability {
  projectId: string
  assetId: string
  vulnerabilityType: string
  parameter: string
  httpMethod: string
  preconditions: string
  reproductionSteps: string
  description: string
  evidence: string
  evidenceRefs: string[]
  impact: string
  recommendation: string
  retestNotes: string
  verificationState: string
  confidence: number
  exploitability: string
  testTechnique: string
}

interface VulnerabilityReportDraft {
  id: string
  fingerprint: string
  status: string
  attempts: number
  lastError: string
  vulnerabilityId: string
  title: string
  severity: string
  vulnerabilityType: string
  target: string
  nextAttemptAt: string
  updatedAt: string
}

interface EvidenceGap {
  id: string
  kind: 'fact' | 'finding'
  assetId: string
  title: string
  summary: string
  factType: string
  severity: string
  status: string
  verificationState: string
  updatedAt: string
}

interface PageResponse<T> {
  items: T[]
  total: number
  hasMore: boolean
  nextOffset: number
}

const TABS = [
  { key: 'pending-intents', labelKey: 'project.tabPendingIntents', countKey: 'pendingIntents' },
  { key: 'evidence-gaps', labelKey: 'project.tabEvidenceGaps', countKey: 'evidenceGaps' },
  { key: 'facts', labelKey: 'project.tabFacts', countKey: 'facts' },
  { key: 'attack', labelKey: 'project.attackSteps', countKey: 'attackSteps' },
  { key: 'assets', labelKey: 'project.tabAssets', countKey: 'assets' },
  { key: 'conversations', labelKey: 'project.tabConversations', countKey: 'conversations' },
  { key: 'vulnerabilities', labelKey: 'project.tabVulnerabilities', countKey: 'vulnerabilities' },
]

const visibleTabs = computed(() =>
  TABS.filter((tab) => {
    if (tab.key === 'pending-intents' || tab.key === 'evidence-gaps' || tab.key === 'attack' || tab.key === 'vulnerabilities') {
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
const SEVERITY_OPTIONS = Object.keys(SEVERITY_LABELS)

const GRAPH_KINDS = ['begin', 'goal', 'intent', 'fact', 'finding', 'hint', 'asset', 'chain', 'digest'] as const
const GRAPH_CREATE_KINDS = ['begin', 'goal', 'intent', 'fact', 'finding', 'hint'] as const

const GRAPH_STATUS_OPTIONS: Record<string, string[]> = {
  begin: ['open'],
  goal: ['open', 'met', 'abandoned'],
  intent: ['open', 'running', 'done', 'blocked', 'exhausted', 'capacity_blocked', 'stopped'],
  fact: ['confirmed', 'dismissed'],
  finding: ['open', 'confirmed', 'dismissed'],
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
  pending_review: 'vulnStatus.pending_review',
  confirmed: 'vulnStatus.confirmed',
  fixed: 'vulnStatus.fixed',
  ignored: 'vulnStatus.ignored',
  false_positive: 'vulnStatus.false_positive',
}
const VULNERABILITY_STATUS_OPTIONS = Object.keys(STATUS_LABELS)

const route = useRoute()
const projectId = String(route.params.id ?? '')
let projectStatusTimer: number | undefined
let projectStatusSequence = 0

const project = ref<Project | null>(null)
const scopeExpanded = ref(false)
const projectScope = computed(() => project.value?.scope?.trim() ?? '')
const projectScopeNeedsToggle = computed(() => {
  const text = projectScope.value
  return (
    Array.from(text).length > 120 ||
    text.split(/\r?\n/).filter((line) => line.trim()).length > 3
  )
})
const counts = ref<ProjectCounts | null>(null)
const coverage = ref<ProjectCoverage | null>(null)
const pendingIntentTargets = computed(() =>
  (coverage.value?.pendingIntentTargets?.length
    ? coverage.value.pendingIntentTargets
    : (coverage.value?.nextTargets ?? []).filter((target) => target.kind === 'intent'))
    .filter((target) => target.kind === 'intent')
    .slice(0, 6),
)
const evidenceGapTargets = computed(() =>
  (coverage.value?.evidenceGapTargets?.length
    ? coverage.value.evidenceGapTargets
    : (coverage.value?.nextTargets ?? []).filter((target) => target.kind === 'evidence'))
    .filter((target) => target.kind === 'evidence')
    .slice(0, 6),
)
const pendingIntentTotal = computed(
  () => (coverage.value?.intentsOpen ?? 0) + (coverage.value?.intentsRunning ?? 0),
)
const intentCapacity = computed(() => counts.value?.intentCapacity || 100)
const activeIntentTotal = computed(
  () => counts.value?.pendingIntents ?? pendingIntentTotal.value,
)
const intentCapacityRatio = computed(() =>
  intentCapacity.value > 0 ? activeIntentTotal.value / intentCapacity.value : 0,
)
const intentCapacityWarning = computed(() => intentCapacityRatio.value >= 0.8)
const evidenceGapTotal = computed(
  () => (coverage.value?.factsWithoutEvidence ?? 0) + (coverage.value?.findingsWithoutEvidence ?? 0),
)
const activeTab = ref('facts')
const loading = ref(false)
const error = ref('')
const notice = ref('')

const facts = ref<Fact[]>([])
const factAssetFilter = ref('')
const factSearchQuery = ref('')
const factStatusFilter = ref('')
const factTypeFilter = ref('')
const factsTotal = ref(0)
const factsPage = ref(1)
const factsPageSize = ref(20)
const evidenceGapItems = ref<EvidenceGap[]>([])
const evidenceGapResultTotal = ref(0)
const evidenceGapPage = ref(1)
const evidenceGapPageSize = ref(20)
const evidenceGapFilter = reactive({
  assetId: '',
  kind: '',
  status: 'missing_evidence',
  query: '',
})
const assets = ref<Asset[]>([])
const assetOverviewItems = ref<AssetOverview[]>([])
const assetOverviewTotal = ref(0)
const assetOverviewPage = ref(1)
const assetOverviewPageSize = ref(20)
const assetOverviewFilter = reactive({
  state: 'all',
  kind: '',
  search: '',
})
const assetsFullyLoaded = ref(false)
const conversations = ref<Conversation[]>([])
const conversationsTotal = ref(0)
const conversationsPage = ref(1)
const conversationsPageSize = ref(20)
const vulnerabilities = ref<Vulnerability[]>([])
const vulnerabilitiesTotal = ref(0)
const vulnerabilitiesPage = ref(1)
const vulnerabilitiesPageSize = ref(20)
const vulnerabilityReportDrafts = ref<VulnerabilityReportDraft[]>([])
const vulnerabilityDraftsTotal = ref(0)
const vulnerabilityDraftsPage = ref(1)
const vulnerabilityDraftsPageSize = ref(20)
const vulnerabilityDraftsExpanded = ref(false)
const vulnerabilityDraftAttentionCount = computed(
  () =>
    vulnerabilityReportDrafts.value.filter(
      (item) => Boolean(item.lastError) || canRetryVulnerabilityDraft(item),
    ).length,
)
const vulnerabilityEditOpen = ref(false)
const vulnerabilityEditLoading = ref(false)
const reviewRetryingId = ref('')
const vulnerabilityDraftConfirmingId = ref('')
const vulnerabilityDraftDeletingId = ref('')
const vulnerabilityDraft = ref<VulnerabilityDetail | null>(null)
const graphNodes = ref<GraphNode[]>([])
const graphEdges = ref<GraphEdge[]>([])
const intentNodes = ref<GraphNode[]>([])
const intentTotal = ref(0)
const intentPage = ref(1)
const intentPageSize = ref(20)
const intentSearchQuery = ref('')
const intentStatusFilter = ref('')
const intentAssetFilter = ref('')
const pendingIntentCards = computed(() => {
  const graph = new Map(graphNodes.value.map((node) => [node.id, node]))
  return pendingIntentTargets.value
    .map((target) => ({ target, node: graph.get(target.refId) }))
    .filter((item): item is { target: CoverageTarget; node: GraphNode } => Boolean(item.node))
})
const intentCards = computed(() => {
  const statusOrder: Record<string, number> = {
    running: 0,
    open: 1,
    blocked: 2,
    exhausted: 3,
    capacity_blocked: 4,
    done: 5,
    stopped: 6,
  }
  const targetByID = new Map(
    (coverage.value?.pendingIntentTargets ?? []).map((target) => [target.refId, target]),
  )
  return intentNodes.value
    .slice()
    .sort((left, right) => {
      const statusDiff = (statusOrder[left.status] ?? 9) - (statusOrder[right.status] ?? 9)
      return statusDiff || new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
    })
    .map((node) => ({
      node,
      score: targetByID.get(node.id)?.score ?? node.confidence ?? 0,
      reason: targetByID.get(node.id)?.reason ?? graphStatusLabel(node.status),
    }))
})
const filteredIntentCards = computed(() => intentCards.value)
const filteredFacts = computed(() => facts.value)
const evidenceGapFacts = computed(() => {
  const byID = new Map(facts.value.map((fact) => [fact.id, fact]))
  return (coverage.value?.evidenceGapTargets ?? [])
    .map((target) => ({ target, fact: byID.get(target.refId) }))
    .filter((item): item is { target: CoverageTarget; fact: Fact } => Boolean(item.fact))
})
const evidenceGapFindings = computed(() => {
  const byID = new Map(vulnerabilities.value.map((item) => [item.id, item]))
  return (coverage.value?.evidenceGapTargets ?? [])
    .map((target) => ({ target, finding: byID.get(target.refId) }))
    .filter(
      (item): item is { target: CoverageTarget; finding: Vulnerability } => Boolean(item.finding),
    )
})
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
const pendingIntentEditOpen = ref(false)
const intentResultNode = ref<GraphNode | null>(null)

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
  const sequence = ++projectStatusSequence
  loading.value = true
  error.value = ''
  try {
    const [projectResponse, summary] = await Promise.all([
      apiGet<Project>(`/projects/${projectId}`),
      apiGet<{ counts: ProjectCounts }>(`/projects/${projectId}/summary`),
    ])
    if (sequence !== projectStatusSequence) {
      return
    }
    project.value = projectResponse
    counts.value = summary.counts
    void loadMissionBoards()
  } catch (err) {
    if (sequence === projectStatusSequence) {
      error.value = err instanceof Error ? err.message : t('message.readProjectsFailed')
    }
  } finally {
    if (sequence === projectStatusSequence) {
      loading.value = false
    }
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

async function loadGraphData(scope: 'chain' | 'full') {
  const requestId = ++graphRequestId
  const query = new URLSearchParams()
  if (graphAssetFilter.value) {
    query.set('assetId', graphAssetFilter.value)
  }
  if (scope === 'chain') {
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
}

async function loadMissionBoards() {
  await loadCoverage()
}

async function loadAssetOverview() {
  if (!projectId) {
    return
  }
  try {
    const offset = (assetOverviewPage.value - 1) * assetOverviewPageSize.value
    const query = new URLSearchParams({
      limit: String(assetOverviewPageSize.value),
      offset: String(offset),
    })
    if (assetOverviewFilter.state && assetOverviewFilter.state !== 'all') {
      query.set('state', assetOverviewFilter.state)
    }
    if (assetOverviewFilter.kind) {
      query.set('kind', assetOverviewFilter.kind)
    }
    if (assetOverviewFilter.search.trim()) {
      query.set('search', assetOverviewFilter.search.trim())
    }
    const response = await apiGet<PageResponse<AssetOverview>>(
      `/projects/${projectId}/asset-overview?${query.toString()}`,
    )
    assetOverviewItems.value = response.items ?? []
    assetOverviewTotal.value = response.total ?? 0
  } catch {
    assetOverviewItems.value = []
    assetOverviewTotal.value = 0
  }
}

function applyAssetOverviewFilters() {
  assetOverviewPage.value = 1
  void loadAssetOverview()
}

function changeAssetOverviewPage(page: number) {
  assetOverviewPage.value = page
  void loadAssetOverview()
}

function changeAssetOverviewPageSize(size: number) {
  assetOverviewPageSize.value = size
  assetOverviewPage.value = 1
  void loadAssetOverview()
}

async function reopenAssetWork(item: AssetOverview) {
  if (!window.confirm(t('project.assetWorkReopenConfirm', { name: item.name || item.value }))) {
    return
  }
  await run(async () => {
    await apiPost(`/projects/${projectId}/assets/${item.id}/reopen`, {})
    await Promise.all([loadAssetOverview(), loadCoverage()])
  }, t('project.assetWorkReopened'))
}

function assetPrimaryLabel(asset: AssetOverview) {
  const name = asset.name?.trim() ?? ''
  const value = asset.value?.trim() ?? ''
  if (!name) {
    return value || '-'
  }
  if (name === value) {
    return value
  }
  if (
    ['url', 'ip', 'domain'].includes(asset.kind) &&
    /^https?:\/\//i.test(name)
  ) {
    return value || name
  }
  return name
}

function assetSecondaryLabel(asset: AssetOverview) {
  const value = asset.value?.trim() ?? ''
  const primary = assetPrimaryLabel(asset)
  return value && value !== primary ? value : ''
}

async function loadIntentPage() {
  if (!projectId) {
    return
  }
  const offset = (intentPage.value - 1) * intentPageSize.value
  const query = new URLSearchParams({
    limit: String(intentPageSize.value),
    offset: String(offset),
  })
  if (intentSearchQuery.value) {
    query.set('query', intentSearchQuery.value)
  }
  if (intentStatusFilter.value) {
    query.set('status', intentStatusFilter.value)
  }
  if (intentAssetFilter.value) {
    query.set('assetId', intentAssetFilter.value)
  }
  const response = await apiGet<PageResponse<GraphNode>>(
    `/projects/${projectId}/intents?${query.toString()}`,
  )
  intentNodes.value = response.items ?? []
  intentTotal.value = response.total ?? 0
}

function applyIntentFilters() {
  intentPage.value = 1
  void loadIntentPage()
}

function changeIntentPage(page: number) {
  intentPage.value = page
  void loadIntentPage()
}

function changeIntentPageSize(size: number) {
  intentPageSize.value = size
  intentPage.value = 1
  void loadIntentPage()
}

async function loadFacts() {
  const offset = (factsPage.value - 1) * factsPageSize.value
  const query = new URLSearchParams({
    limit: String(factsPageSize.value),
    offset: String(offset),
  })
  if (factAssetFilter.value) {
    query.set('assetId', factAssetFilter.value)
  }
  if (factSearchQuery.value.trim()) {
    query.set('query', factSearchQuery.value.trim())
  }
  if (factTypeFilter.value.trim()) {
    query.set('factType', factTypeFilter.value.trim())
  }
  if (factStatusFilter.value) {
    query.set('status', factStatusFilter.value)
  }
  const response = await apiGet<PageResponse<Fact>>(
    `/projects/${projectId}/facts?${query.toString()}`,
  )
  facts.value = response.items ?? []
  factsTotal.value = response.total ?? facts.value.length
}

function applyFactFilters() {
  factsPage.value = 1
  void loadFacts()
}

function changeFactsPage(page: number) {
  factsPage.value = page
  void loadFacts()
}

function changeFactsPageSize(size: number) {
  factsPageSize.value = size
  factsPage.value = 1
  void loadFacts()
}

async function loadEvidenceGaps() {
  const offset = (evidenceGapPage.value - 1) * evidenceGapPageSize.value
  const query = new URLSearchParams({
    limit: String(evidenceGapPageSize.value),
    offset: String(offset),
  })
  if (evidenceGapFilter.assetId) {
    query.set('assetId', evidenceGapFilter.assetId)
  }
  if (evidenceGapFilter.kind) {
    query.set('kind', evidenceGapFilter.kind)
  }
  if (evidenceGapFilter.status) {
    query.set('status', evidenceGapFilter.status)
  }
  if (evidenceGapFilter.query.trim()) {
    query.set('query', evidenceGapFilter.query.trim())
  }
  const response = await apiGet<PageResponse<EvidenceGap>>(
    `/projects/${projectId}/evidence-gaps?${query.toString()}`,
  )
  evidenceGapItems.value = response.items ?? []
  evidenceGapResultTotal.value = response.total ?? 0
}

function applyEvidenceGapFilters() {
  evidenceGapPage.value = 1
  void loadEvidenceGaps()
}

function changeEvidenceGapPage(page: number) {
  evidenceGapPage.value = page
  void loadEvidenceGaps()
}

function changeEvidenceGapPageSize(size: number) {
  evidenceGapPageSize.value = size
  evidenceGapPage.value = 1
  void loadEvidenceGaps()
}

async function loadConversations() {
  const offset = (conversationsPage.value - 1) * conversationsPageSize.value
  const response = await apiGet<PageResponse<Conversation>>(
    `/projects/${projectId}/conversations?limit=${conversationsPageSize.value}&offset=${offset}`,
  )
  conversations.value = response.items ?? []
  conversationsTotal.value = response.total ?? 0
}

function changeConversationsPage(page: number) {
  conversationsPage.value = page
  void loadConversations()
}

function changeConversationsPageSize(size: number) {
  conversationsPageSize.value = size
  conversationsPage.value = 1
  void loadConversations()
}

async function loadVulnerabilities() {
  const offset = (vulnerabilitiesPage.value - 1) * vulnerabilitiesPageSize.value
  const draftsOffset = (vulnerabilityDraftsPage.value - 1) * vulnerabilityDraftsPageSize.value
  const [response, draftsResponse] = await Promise.all([
    apiGet<PageResponse<Vulnerability>>(
      `/projects/${projectId}/vulnerabilities?limit=${vulnerabilitiesPageSize.value}&offset=${offset}`,
    ),
    apiGet<PageResponse<VulnerabilityReportDraft>>(
      `/projects/${projectId}/vulnerability-drafts?limit=${vulnerabilityDraftsPageSize.value}&offset=${draftsOffset}`,
    ),
  ])
  vulnerabilities.value = response.items ?? []
  vulnerabilitiesTotal.value = response.total ?? 0
  vulnerabilityReportDrafts.value = draftsResponse.items ?? []
  vulnerabilityDraftsTotal.value = draftsResponse.total ?? 0
  const draftTotalPages = Math.max(
    1,
    Math.ceil(vulnerabilityDraftsTotal.value / vulnerabilityDraftsPageSize.value),
  )
  if (vulnerabilityDraftsPage.value > draftTotalPages) {
    vulnerabilityDraftsPage.value = draftTotalPages
    await loadVulnerabilities()
  }
}

function changeVulnerabilitiesPage(page: number) {
  vulnerabilitiesPage.value = page
  void loadVulnerabilities()
}

function changeVulnerabilitiesPageSize(size: number) {
  vulnerabilitiesPageSize.value = size
  vulnerabilitiesPage.value = 1
  void loadVulnerabilities()
}

function changeVulnerabilityDraftsPage(page: number) {
  vulnerabilityDraftsPage.value = page
  void loadVulnerabilities()
}

function changeVulnerabilityDraftsPageSize(size: number) {
  vulnerabilityDraftsPageSize.value = size
  vulnerabilityDraftsPage.value = 1
  void loadVulnerabilities()
}

async function loadTab() {
  if (!projectId) {
    return
  }
  try {
    if (
      ['facts', 'attack', 'evidence-gaps', 'pending-intents'].includes(activeTab.value) &&
      !assetsFullyLoaded.value
    ) {
      await loadAllProjectAssets()
    }
    if (activeTab.value === 'facts') {
      await loadFacts()
    } else if (activeTab.value === 'attack') {
      await loadGraphData(graphScope.value)
    } else if (activeTab.value === 'pending-intents') {
      await loadIntentPage()
    } else if (activeTab.value === 'evidence-gaps') {
      await loadEvidenceGaps()
    } else if (activeTab.value === 'assets') {
      await loadAssetOverview()
    } else if (activeTab.value === 'conversations') {
      await loadConversations()
    } else if (activeTab.value === 'vulnerabilities') {
      await loadVulnerabilities()
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
  assetsFullyLoaded.value = true
}

function switchTab(key: string) {
  showFactModal.value = false
  activeTab.value = key
  void loadTab()
}

function countValue(tab: (typeof TABS)[number]) {
  if (tab.key === 'pending-intents') {
    return intentTotal.value || counts.value?.totalIntents || 0
  }
  if (tab.key === 'evidence-gaps') {
    return evidenceGapResultTotal.value || evidenceGapTotal.value
  }
  if (tab.key === 'assets') {
    return assetOverviewTotal.value || counts.value?.assets || 0
  }
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

async function editEvidenceFact(fact: Fact) {
  activeTab.value = 'facts'
  await nextTick()
  editFact(fact)
  void loadTab()
}

async function openVulnerabilityEditor(item: Vulnerability) {
  vulnerabilityEditLoading.value = true
  error.value = ''
  try {
    const detail = await apiGet<VulnerabilityDetail>(`/vulnerabilities/${item.id}`)
    vulnerabilityDraft.value = {
      ...detail,
      evidenceRefs: detail.evidenceRefs ?? [],
    }
    vulnerabilityEditOpen.value = true
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readDataFailed')
  } finally {
    vulnerabilityEditLoading.value = false
  }
}

function closeVulnerabilityEditor() {
  vulnerabilityEditOpen.value = false
  vulnerabilityDraft.value = null
}

function saveVulnerabilityGap() {
  const draft = vulnerabilityDraft.value
  if (!draft) {
    return
  }
  void run(async () => {
    await apiPut(`/vulnerabilities/${draft.id}`, {
      projectId: draft.projectId,
      assetId: draft.assetId,
      title: draft.title,
      titleImpact: draft.title,
      severity: draft.severity,
      status: draft.status,
      vulnerabilityType: draft.vulnerabilityType,
      target: draft.target,
      parameter: draft.parameter,
      httpMethod: draft.httpMethod,
      preconditions: draft.preconditions,
      reproductionSteps: draft.reproductionSteps,
      description: draft.description,
      evidence: draft.evidence,
      evidenceRefs: draft.evidenceRefs,
      impact: draft.impact,
      recommendation: draft.recommendation,
      retestNotes: draft.retestNotes,
      verificationState: draft.verificationState,
      confidence: draft.confidence,
      exploitability: draft.exploitability,
      testTechnique: draft.testTechnique,
    })
    closeVulnerabilityEditor()
    await loadCoverage()
    await loadTab()
    await loadProject()
  }, t('project.savedVulnerability'))
}

function removeEvidenceFinding(item: Vulnerability) {
  if (!window.confirm(t('project.confirmDeleteVulnerability', { name: item.title }))) {
    return
  }
  void run(async () => {
    await apiDelete(`/vulnerabilities/${item.id}`)
    await loadCoverage()
    await loadTab()
    await loadProject()
  }, t('project.deletedVulnerability'))
}

function retryVulnerabilityReportDraft(item: VulnerabilityReportDraft) {
  void run(async () => {
    await apiPost(`/projects/${projectId}/vulnerability-drafts/${item.id}/retry`)
    await loadTab()
  }, t('project.vulnerabilityDraftRetryQueued'))
}

function confirmVulnerabilityDraft(item: VulnerabilityReportDraft) {
  if (!window.confirm(t('project.vulnerabilityDraftConfirmWarning', { name: item.title }))) {
    return
  }
  vulnerabilityDraftConfirmingId.value = item.id
  void run(async () => {
    await apiPost(`/projects/${projectId}/vulnerability-drafts/${item.id}/confirm`)
    vulnerabilitiesPage.value = 1
    await Promise.all([loadVulnerabilities(), loadProject(), loadCoverage()])
  }, t('project.vulnerabilityDraftConfirmed')).finally(() => {
    vulnerabilityDraftConfirmingId.value = ''
  })
}

function deleteVulnerabilityDraft(item: VulnerabilityReportDraft) {
  if (!window.confirm(t('project.vulnerabilityDraftDeleteWarning', { name: item.title }))) {
    return
  }
  vulnerabilityDraftDeletingId.value = item.id
  void run(async () => {
    await apiDelete(`/projects/${projectId}/vulnerability-drafts/${item.id}`)
    await Promise.all([loadVulnerabilities(), loadProject(), loadCoverage()])
  }, t('project.vulnerabilityDraftDeleted')).finally(() => {
    vulnerabilityDraftDeletingId.value = ''
  })
}

function retryVulnerabilityReview(item: Vulnerability) {
  if (reviewRetryingId.value) {
    return
  }
  reviewRetryingId.value = item.id
  void run(async () => {
    await apiPost(`/projects/${projectId}/vulnerabilities/${item.id}/review-retry`)
    await loadCoverage()
    await loadTab()
    await loadProject()
  }, t('project.vulnerabilityReviewRetried')).finally(() => {
    reviewRetryingId.value = ''
  })
}

function vulnerabilityDraftStatusLabel(status: string) {
  const key = `vulnDraftStatus.${status}`
  const translated = t(key)
  return translated === key ? status : translated
}

function canRetryVulnerabilityDraft(item: VulnerabilityReportDraft) {
  return ['needs_input', 'pending_retry', 'pending_review', 'needs_attention'].includes(item.status)
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

let factFilterTimer: number | undefined
watch([factAssetFilter, factStatusFilter, factTypeFilter, factSearchQuery], () => {
  if (activeTab.value !== 'facts') {
    return
  }
  if (factFilterTimer) {
    window.clearTimeout(factFilterTimer)
  }
  factFilterTimer = window.setTimeout(() => {
    applyFactFilters()
  }, 250)
})

let evidenceGapFilterTimer: number | undefined
watch(
  [
    () => evidenceGapFilter.assetId,
    () => evidenceGapFilter.kind,
    () => evidenceGapFilter.status,
    () => evidenceGapFilter.query,
  ],
  () => {
    if (activeTab.value !== 'evidence-gaps') {
      return
    }
    if (evidenceGapFilterTimer) {
      window.clearTimeout(evidenceGapFilterTimer)
    }
    evidenceGapFilterTimer = window.setTimeout(() => {
      applyEvidenceGapFilters()
    }, 250)
  },
)

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

let intentSearchTimer: number | undefined
watch([intentSearchQuery, intentStatusFilter, intentAssetFilter], () => {
  if (activeTab.value !== 'pending-intents') {
    return
  }
  if (intentSearchTimer) {
    window.clearTimeout(intentSearchTimer)
  }
  intentSearchTimer = window.setTimeout(() => {
    applyIntentFilters()
  }, 250)
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

function openPendingIntentEditor(node: GraphNode) {
  editNode(node)
  pendingIntentEditOpen.value = true
}

function closePendingIntentEditor() {
  pendingIntentEditOpen.value = false
  resetNodeDraft()
}

function openIntentResult(node: GraphNode) {
  intentResultNode.value = node
}

function closeIntentResult() {
  intentResultNode.value = null
}

function intentResultPreview(node: GraphNode) {
  return (
    node.result?.trim() ||
    node.stateReason?.trim() ||
    node.evidence?.trim() ||
    t('project.intentResultMissing')
  )
}

function savePendingIntent() {
  if (!editingNodeId.value || !nodeDraft.title.trim()) {
    error.value = t('graph.titleRequired')
    return
  }
  void run(async () => {
    await apiPut(`/projects/${projectId}/graph/nodes/${editingNodeId.value}`, {
      kind: 'intent',
      title: nodeDraft.title.trim(),
      detail: nodeDraft.detail.trim(),
      status: nodeDraft.status,
      confidence: Number(nodeDraft.confidence) || 0,
      severity: '',
      assetId: nodeDraft.assetId,
      parentId: '',
      relation: 'spawns',
    })
    closePendingIntentEditor()
    await loadTab()
    await loadProject()
  }, t('graph.saved'))
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
    await loadProject()
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

function isIntentFinished(status: string) {
  return ['done', 'blocked', 'exhausted', 'stopped'].includes(status)
}

function intentHasCompletion(node: GraphNode) {
  return Boolean(
    node.result ||
      node.stateReason ||
      node.evidence ||
      (node.evidenceRefs?.length ?? 0) > 0 ||
      node.findingId,
  )
}

function graphStatusLabel(status: string) {
  const key = GRAPH_STATUS_LABELS[status]
  return key ? t(key) : status
}

function assetName(assetId: string) {
  return assets.value.find((item) => item.id === assetId)?.name ?? assetId
}

function matchesProjectSearch(query: string, values: unknown[]) {
  const keyword = query.trim().toLocaleLowerCase()
  return (
    !keyword ||
    values.some((value) => String(value ?? '').toLocaleLowerCase().includes(keyword))
  )
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
  projectStatusTimer = window.setInterval(async () => {
    if (document.visibilityState !== 'visible' || loading.value || !projectId) {
      return
    }
    try {
      const sequence = ++projectStatusSequence
      const refreshed = await apiGet<Project>(`/projects/${projectId}`)
      if (sequence === projectStatusSequence) {
        project.value = refreshed
      }
    } catch {
      // 状态轮询失败不覆盖当前已加载的项目详情。
    }
  }, 5000)
})

onUnmounted(() => {
  if (intentSearchTimer) {
    window.clearTimeout(intentSearchTimer)
  }
  if (projectStatusTimer) {
    window.clearInterval(projectStatusTimer)
  }
  projectStatusSequence++
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
            <div v-if="project?.constraints">
              <dt>{{ t('project.constraintsLabel') }}</dt>
              <dd class="project-constraints">{{ project.constraints }}</dd>
            </div>
            <div>
              <dt>{{ t('project.scopeLabel') }}</dt>
              <dd class="project-scope">
                <span
                  class="project-scope-text"
                  :class="{ clamped: projectScopeNeedsToggle && !scopeExpanded }"
                >
                  {{ projectScope || t('project.briefEmpty') }}
                </span>
                <button
                  v-if="projectScopeNeedsToggle"
                  class="project-scope-toggle"
                  type="button"
                  :aria-expanded="scopeExpanded"
                  @click="scopeExpanded = !scopeExpanded"
                >
                  {{ scopeExpanded ? t('project.scopeCollapse') : t('project.scopeExpand') }}
                </button>
              </dd>
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
          <span :class="{ 'is-warning': intentCapacityWarning }">
            <small>{{ t('project.intentCapacityLabel') }}</small>
            <strong>{{ activeIntentTotal }} / {{ intentCapacity }}</strong>
          </span>
          <span>
            <small>{{ t('project.capacityBlockedLabel') }}</small>
            <strong>{{ counts?.capacityBlockedIntents ?? 0 }}</strong>
          </span>
          <span>
            <small>{{ t('project.assets') }}</small>
            <strong>{{ coverage.assetsTotal }}</strong>
          </span>
        </div>
      </div>
      <div v-if="false" class="mission-workboards">
        <section class="mission-workboard mission-workboard-intents">
          <header class="mission-workboard-head">
            <div>
              <span class="mission-workboard-code">INTENTS // FRONTIER</span>
              <h3>{{ t('project.pendingIntentLabel') }}</h3>
            </div>
            <span class="mission-workboard-total">{{ pendingIntentTotal }}</span>
          </header>
          <div v-if="pendingIntentCards.length" class="mission-gap-cards">
            <article
              v-for="item in pendingIntentCards"
              :key="`intent-${item.target.refId}`"
              class="mission-gap-card mission-intent-card"
            >
              <header>
                <span class="gap-status" :class="`is-${item.node.status}`">
                  {{ graphStatusLabel(item.node.status) }}
                </span>
                <strong :title="item.node.title">{{ item.node.title }}</strong>
                <span class="mission-workboard-score">{{ item.target.score }}</span>
              </header>
              <p :title="item.node.detail || item.target.reason">
                {{ item.node.detail || item.target.reason }}
              </p>
              <div class="mission-gap-meta">
                <span v-if="item.node.assetId">{{ assetName(item.node.assetId) }}</span>
                <span>{{ formatTime(item.node.updatedAt) }}</span>
              </div>
              <footer>
                <button class="button compact" type="button" @click="openPendingIntentEditor(item.node)">
                  {{ t('common.edit') }}
                </button>
                <button class="button compact danger" type="button" @click="removeNode(item.node)">
                  {{ t('common.delete') }}
                </button>
              </footer>
            </article>
          </div>
          <p v-else class="mission-workboard-empty">{{ t('project.pendingIntentBoardEmpty') }}</p>
          <button
            v-if="pendingIntentTotal > pendingIntentTargets.length"
            class="mission-workboard-more"
            type="button"
            @click="switchTab('attack')"
          >
            {{ t('project.workboardViewAll', { count: pendingIntentTotal }) }}
          </button>
        </section>

        <section class="mission-workboard mission-workboard-evidence">
          <header class="mission-workboard-head">
            <div>
              <span class="mission-workboard-code">EVIDENCE // GAPS</span>
              <h3>{{ t('project.evidenceGapLabel') }}</h3>
            </div>
            <span class="mission-workboard-total">{{ evidenceGapTotal }}</span>
          </header>
          <div
            v-if="evidenceGapFacts.length || evidenceGapFindings.length"
            class="mission-gap-cards"
          >
            <article
              v-for="item in evidenceGapFacts"
              :key="`fact-gap-${item.fact.id}`"
              class="mission-gap-card mission-evidence-card"
            >
              <header>
                <span class="mission-evidence-type">FACT GAP</span>
                <strong :title="item.fact.key">{{ item.fact.key }}</strong>
                <span class="mission-workboard-score">{{ item.target.score }}</span>
              </header>
              <p :title="item.fact.body || item.fact.summary">
                {{ item.fact.summary || item.fact.value || item.target.reason }}
              </p>
              <div class="mission-gap-meta">
                <span>{{ item.fact.factType || 'fact' }}</span>
                <span>{{ formatTime(item.fact.updatedAt) }}</span>
              </div>
              <footer>
                <button class="button compact" type="button" @click="editEvidenceFact(item.fact)">
                  {{ t('common.edit') }}
                </button>
                <button class="button compact danger" type="button" @click="removeFact(item.fact)">
                  {{ t('common.delete') }}
                </button>
              </footer>
            </article>
            <article
              v-for="item in evidenceGapFindings"
              :key="`finding-gap-${item.finding.id}`"
              class="mission-gap-card mission-evidence-card"
            >
              <header>
                <span class="chip" :class="`sev-${item.finding.severity}`">
                  {{ severityLabel(item.finding.severity) }}
                </span>
                <strong :title="item.finding.title">{{ item.finding.title }}</strong>
                <span class="mission-workboard-score">{{ item.target.score }}</span>
              </header>
              <p>{{ item.finding.target || item.target.reason }}</p>
              <div class="mission-gap-meta">
                <span>FINDING GAP</span>
                <span>{{ formatTime(item.finding.updatedAt) }}</span>
              </div>
              <footer>
                <button
                  class="button compact"
                  type="button"
                  :disabled="vulnerabilityEditLoading"
                  @click="openVulnerabilityEditor(item.finding)"
                >
                  {{ t('common.edit') }}
                </button>
                <button
                  class="button compact danger"
                  type="button"
                  @click="removeEvidenceFinding(item.finding)"
                >
                  {{ t('common.delete') }}
                </button>
              </footer>
            </article>
          </div>
          <p v-else class="mission-workboard-empty">{{ t('project.evidenceGapBoardEmpty') }}</p>
          <button
            v-if="evidenceGapTotal > evidenceGapTargets.length"
            class="mission-workboard-more"
            type="button"
            @click="switchTab('facts')"
          >
            {{ t('project.workboardViewAll', { count: evidenceGapTotal }) }}
          </button>
        </section>
      </div>
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
          <template v-if="tab.key === 'pending-intents'">
            <circle cx="5" cy="12" r="2" />
            <circle cx="12" cy="6" r="2" />
            <circle cx="19" cy="12" r="2" />
            <path d="M7 11l3-3M14 7l3 3M5 14v3M19 14v3" />
          </template>
          <template v-else-if="tab.key === 'facts'">
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
            <path d="M9 9h6M9 13h6M9 17h4" />
          </template>
        </svg>
        <small>{{ t(tab.labelKey) }}</small>
        <strong>{{ countValue(tab) }}</strong>
      </button>
    </div>

    <section v-if="activeTab === 'pending-intents'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabPendingIntents') }}</h2>
        <span class="panel-hint">{{ t('project.pendingIntentManageHint') }}</span>
      </header>
      <div class="project-filter-toolbar">
        <input
          v-model.trim="intentSearchQuery"
          class="project-search-input"
          type="search"
          :aria-label="t('project.intentSearchPlaceholder')"
          :placeholder="t('project.intentSearchPlaceholder')"
        />
        <select
          v-model="intentAssetFilter"
          class="asset-filter-select"
          :aria-label="t('project.factAsset')"
        >
          <option value="">{{ t('project.allAssets') }}</option>
          <option v-for="asset in assets" :key="asset.id" :value="asset.id">
            {{ asset.name || asset.value }}
          </option>
        </select>
        <select
          v-model="intentStatusFilter"
          class="asset-filter-select"
          :aria-label="t('project.intentStatusFilter')"
        >
          <option value="">{{ t('project.statusAll') }}</option>
          <option v-for="status in GRAPH_STATUS_OPTIONS.intent" :key="status" :value="status">
            {{ graphStatusLabel(status) }}
          </option>
        </select>
        <span class="project-filter-count">
          {{
            t('project.filterCount', {
              filtered: filteredIntentCards.length,
              total: intentTotal,
            })
          }}
        </span>
      </div>
      <div v-if="filteredIntentCards.length" class="fact-grid">
        <article
          v-for="item in filteredIntentCards"
          :key="`tab-intent-${item.node.id}`"
          class="fact-card intent-card"
        >
          <header>
            <span class="fact-type">
              {{ graphStatusLabel(item.node.status) }}
            </span>
            <strong class="fact-key" :title="item.node.title">{{ item.node.title }}</strong>
            <span v-if="item.score > 0" class="fact-confidence">{{ item.score }}</span>
          </header>
          <p class="fact-summary" :title="item.node.detail || item.reason">
            {{ item.node.detail || item.reason }}
          </p>
          <section
            v-if="isIntentFinished(item.node.status) || intentHasCompletion(item.node)"
            class="intent-result"
          >
            <strong>{{ t('project.intentExecutionResult') }}</strong>
            <p class="intent-result-preview" :title="intentResultPreview(item.node)">
              {{ intentResultPreview(item.node) }}
            </p>
            <button class="link-button intent-result-link" type="button" @click="openIntentResult(item.node)">
              {{ t('common.view') }}
            </button>
          </section>
          <p v-if="item.node.assetId" class="fact-scope">
            {{ t('project.factAsset') }}: {{ assetName(item.node.assetId) }}
          </p>
          <p v-else class="fact-scope">{{ t('project.factProjectScope') }}</p>
          <footer>
            <small>{{ formatTime(item.node.updatedAt) }}</small>
            <div class="fact-actions">
              <button class="button compact" type="button" @click="openPendingIntentEditor(item.node)">
                {{ t('common.edit') }}
              </button>
              <button class="button compact danger" type="button" @click="removeNode(item.node)">
                {{ t('common.delete') }}
              </button>
            </div>
          </footer>
        </article>
      </div>
      <p v-else class="empty-cell">
        {{
          intentSearchQuery || intentStatusFilter || intentAssetFilter
            ? t('project.intentNoMatch')
            : t('project.pendingIntentBoardEmpty')
        }}
      </p>
      <DataPagination
        :total="intentTotal"
        :page="intentPage"
        :page-size="intentPageSize"
        :total-pages="Math.ceil(intentTotal / intentPageSize)"
        @page-change="changeIntentPage"
        @page-size-change="changeIntentPageSize"
      />
    </section>

    <section v-if="activeTab === 'evidence-gaps'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabEvidenceGaps') }}</h2>
        <span class="panel-hint">{{ t('project.evidenceGapManageHint') }}</span>
      </header>
      <div class="project-filter-toolbar">
        <input
          v-model.trim="evidenceGapFilter.query"
          class="project-search-input"
          type="search"
          :placeholder="t('project.evidenceGapSearchPlaceholder')"
        />
        <select
          v-model="evidenceGapFilter.assetId"
          class="asset-filter-select"
          :aria-label="t('project.factAsset')"
        >
          <option value="">{{ t('project.allAssets') }}</option>
          <option v-for="asset in assets" :key="asset.id" :value="asset.id">
            {{ asset.name || asset.value }}
          </option>
        </select>
        <select
          v-model="evidenceGapFilter.kind"
          class="asset-filter-select"
          :aria-label="t('vulnerability.type')"
        >
          <option value="">{{ t('project.evidenceGapAllKinds') }}</option>
          <option value="fact">{{ t('project.factEvidenceGap') }}</option>
          <option value="finding">{{ t('project.findingEvidenceGap') }}</option>
        </select>
        <select
          v-model="evidenceGapFilter.status"
          class="asset-filter-select"
          :aria-label="t('project.factStatus')"
        >
          <option value="">{{ t('project.statusAll') }}</option>
          <option value="missing_evidence">{{ t('project.factStatusMissingEvidence') }}</option>
        </select>
        <span class="project-filter-count">
          {{ t('project.filterCount', { filtered: evidenceGapItems.length, total: evidenceGapResultTotal }) }}
        </span>
      </div>
      <div v-if="evidenceGapItems.length" class="fact-grid">
        <article
          v-for="item in evidenceGapItems"
          :key="`evidence-gap-${item.kind}-${item.id}`"
          class="fact-card"
        >
          <header>
            <span class="fact-type">
              {{ item.kind === 'finding' ? severityLabel(item.severity) : 'FACT GAP' }}
            </span>
            <strong class="fact-key" :title="item.title">{{ item.title }}</strong>
            <span class="fact-confidence">{{ item.status }}</span>
          </header>
          <p class="fact-summary">{{ item.summary || '-' }}</p>
          <p class="fact-scope">{{ item.factType || item.kind }}</p>
          <p v-if="item.assetId" class="fact-scope">
            {{ t('project.factAsset') }}: {{ assetName(item.assetId) }}
          </p>
          <footer>
            <small>{{ formatTime(item.updatedAt) }}</small>
          </footer>
        </article>
      </div>
      <p v-else class="empty-cell">{{ t('project.evidenceGapBoardEmpty') }}</p>
      <DataPagination
        :total="evidenceGapResultTotal"
        :page="evidenceGapPage"
        :page-size="evidenceGapPageSize"
        :total-pages="Math.ceil(evidenceGapResultTotal / evidenceGapPageSize)"
        @page-change="changeEvidenceGapPage"
        @page-size-change="changeEvidenceGapPageSize"
      />
    </section>

    <section v-if="activeTab === 'facts'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabFacts') }}</h2>
        <div class="header-actions">
          <span class="panel-hint">{{ t('project.factHint') }}</span>
          <button class="button compact" type="button" @click="openCreateFact">
            {{ t('project.addFact') }}
          </button>
        </div>
      </header>
      <div class="project-filter-toolbar">
        <input
          v-model.trim="factSearchQuery"
          class="project-search-input"
          type="search"
          :aria-label="t('project.factSearchPlaceholder')"
          :placeholder="t('project.factSearchPlaceholder')"
        />
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
        <select
          v-model="factTypeFilter"
          class="asset-filter-select"
          :aria-label="t('project.factType')"
        >
          <option value="">{{ t('project.allFactTypes') }}</option>
          <option value="general">general</option>
          <option value="scope">scope</option>
          <option value="credential">credential</option>
          <option value="asset">asset</option>
          <option value="finding">finding</option>
          <option value="topology">topology</option>
          <option value="constraint">constraint</option>
        </select>
        <select
          v-model="factStatusFilter"
          class="asset-filter-select"
          :aria-label="t('project.factStatus')"
        >
          <option value="">{{ t('project.factStatusAll') }}</option>
          <option value="with_evidence">{{ t('project.factStatusWithEvidence') }}</option>
          <option value="missing_evidence">{{ t('project.factStatusMissingEvidence') }}</option>
          <option value="tainted">{{ t('project.factStatusTainted') }}</option>
          <option value="conflict">{{ t('project.factStatusConflict') }}</option>
          <option value="pinned">{{ t('project.factStatusPinned') }}</option>
        </select>
        <span class="project-filter-count">
          {{
            t('project.filterCount', {
              filtered: filteredFacts.length,
              total: factsTotal,
            })
          }}
        </span>
      </div>
      <div v-if="filteredFacts.length" class="fact-grid">
        <article v-for="fact in filteredFacts" :key="fact.id" class="fact-card">
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
      <p v-else class="fact-empty">
        {{
          factSearchQuery || factAssetFilter || factTypeFilter || factStatusFilter
            ? t('project.factNoMatch')
            : t('project.factEmpty')
        }}
      </p>
      <DataPagination
        :total="factsTotal"
        :page="factsPage"
        :page-size="factsPageSize"
        :total-pages="Math.ceil(factsTotal / factsPageSize)"
        @page-change="changeFactsPage"
        @page-size-change="changeFactsPageSize"
      />

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
      <div class="project-filter-toolbar">
        <select
          v-model="assetOverviewFilter.state"
          class="asset-filter-select"
          :aria-label="t('project.assetWorkState')"
          @change="applyAssetOverviewFilters"
        >
          <option value="all">{{ t('project.assetFilterAll') }}</option>
          <option value="pending">{{ t('project.assetFilterPending') }}</option>
          <option value="active">{{ t('project.assetFilterActive') }}</option>
          <option value="blocked">{{ t('project.assetFilterBlocked') }}</option>
          <option value="complete">{{ t('project.assetFilterComplete') }}</option>
        </select>
        <select
          v-model="assetOverviewFilter.kind"
          class="asset-filter-select"
          :aria-label="t('vulnerability.type')"
          @change="applyAssetOverviewFilters"
        >
          <option value="">{{ t('project.assetFilterAllKinds') }}</option>
          <option value="domain">domain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
          <option value="source">source</option>
          <option value="host">host (legacy)</option>
        </select>
        <input
          v-model.trim="assetOverviewFilter.search"
          class="project-search-input"
          type="search"
          :placeholder="t('project.assetSearchPlaceholder')"
          @keyup.enter="applyAssetOverviewFilters"
        />
        <button class="button compact" type="button" @click="applyAssetOverviewFilters">
          {{ t('common.query') }}
        </button>
      </div>
      <div class="factory-table-scroll">
        <table class="data-list">
        <thead>
          <tr>
            <th>{{ t('project.assetName') }}</th>
            <th>{{ t('vulnerability.type') }}</th>
            <th>{{ t('asset.source') }}</th>
            <th>{{ t('project.assetAuthorization') }}</th>
            <th>{{ t('project.assetWorkState') }}</th>
            <th>{{ t('project.assetCoverage') }}</th>
            <th>{{ t('project.assetRiskPriority') }}</th>
            <th>{{ t('project.assetWorkReason') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="asset in assetOverviewItems" :key="asset.id">
            <td>
              <strong>{{ assetPrimaryLabel(asset) }}</strong>
              <small v-if="assetSecondaryLabel(asset)" class="wrap-cell">
                {{ assetSecondaryLabel(asset) }}
              </small>
            </td>
            <td>{{ asset.kind }}</td>
            <td>{{ asset.source || '-' }}</td>
            <td>{{ asset.authorizationState }}</td>
            <td>{{ asset.workState }}</td>
            <td>
              {{ asset.coverageStatus || '-' }}
              <small v-if="asset.testsTotal">{{ asset.testsCovered }}/{{ asset.testsTotal }}</small>
            </td>
            <td>{{ asset.riskScore }} / {{ asset.priority }}</td>
            <td class="wrap-cell">{{ asset.stateReason || '-' }}</td>
            <td>
              <button
                v-if="['complete', 'blocked', 'awaiting_user'].includes(asset.workState)"
                class="button compact"
                type="button"
                @click="reopenAssetWork(asset)"
              >
                {{ t('project.assetWorkReopen') }}
              </button>
            </td>
          </tr>
          <tr v-if="!assetOverviewItems.length">
            <td class="empty-cell" colspan="9">{{ t('project.assetEmpty') }}</td>
          </tr>
        </tbody>
        </table>
      </div>
      <DataPagination
        :total="assetOverviewTotal"
        :page="assetOverviewPage"
        :page-size="assetOverviewPageSize"
        :total-pages="Math.ceil(assetOverviewTotal / assetOverviewPageSize)"
        @page-change="changeAssetOverviewPage"
        @page-size-change="changeAssetOverviewPageSize"
      />
    </section>

    <section v-if="false" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabEvidenceGaps') }}</h2>
        <span class="panel-hint">{{ t('project.evidenceGapManageHint') }}</span>
      </header>
      <div
        v-if="evidenceGapFacts.length || evidenceGapFindings.length"
        class="evidence-gap-columns"
      >
        <section class="evidence-gap-group">
          <header>
            <strong>{{ t('project.factEvidenceGap') }}</strong>
            <span>{{ evidenceGapFacts.length }}</span>
          </header>
          <article v-for="item in evidenceGapFacts" :key="item.fact.id" class="gap-management-row">
            <div class="gap-management-main">
              <div class="gap-management-title">
                <span class="gap-status is-fact">{{ item.fact.factType || 'fact' }}</span>
                <strong>{{ item.fact.key }}</strong>
              </div>
              <p>{{ item.target.reason }} · {{ item.fact.summary || item.fact.value }}</p>
              <small>{{ formatTime(item.fact.updatedAt) }}</small>
            </div>
            <div class="gap-management-actions">
              <button class="button compact" type="button" @click="editEvidenceFact(item.fact)">
                {{ t('common.edit') }}
              </button>
              <button class="button compact danger" type="button" @click="removeFact(item.fact)">
                {{ t('common.delete') }}
              </button>
            </div>
          </article>
        </section>

        <section class="evidence-gap-group">
          <header>
            <strong>{{ t('project.findingEvidenceGap') }}</strong>
            <span>{{ evidenceGapFindings.length }}</span>
          </header>
          <article
            v-for="item in evidenceGapFindings"
            :key="item.finding.id"
            class="gap-management-row"
          >
            <div class="gap-management-main">
              <div class="gap-management-title">
                <span class="chip" :class="`sev-${item.finding.severity}`">
                  {{ severityLabel(item.finding.severity) }}
                </span>
                <strong>{{ item.finding.title }}</strong>
              </div>
              <p>{{ item.target.reason }} · {{ item.finding.target || '-' }}</p>
              <small>{{ formatTime(item.finding.updatedAt) }}</small>
            </div>
            <div class="gap-management-actions">
              <button
                class="button compact"
                type="button"
                :disabled="vulnerabilityEditLoading"
                @click="openVulnerabilityEditor(item.finding)"
              >
                {{ t('common.edit') }}
              </button>
              <button
                class="button compact danger"
                type="button"
                @click="removeEvidenceFinding(item.finding)"
              >
                {{ t('common.delete') }}
              </button>
            </div>
          </article>
        </section>
      </div>
      <p v-else class="empty-cell">{{ t('project.evidenceGapBoardEmpty') }}</p>

      <div
        v-if="vulnerabilityEditOpen && vulnerabilityDraft"
        class="fact-modal-backdrop"
        @click.self="closeVulnerabilityEditor"
      >
        <section class="fact-modal gap-edit-modal" role="dialog" aria-modal="true">
          <header class="fact-modal-head">
            <h3>{{ t('project.editEvidenceVulnerability') }}</h3>
            <button class="text-button dark" type="button" @click="closeVulnerabilityEditor">
              {{ t('common.close') }}
            </button>
          </header>
          <div class="gap-edit-form">
            <label>
              <span>{{ t('vulnerability.name') }}</span>
              <input v-model="vulnerabilityDraft.title" />
            </label>
            <div class="gap-edit-grid">
              <label>
                <span>{{ t('vulnerability.severity') }}</span>
                <select v-model="vulnerabilityDraft.severity">
                  <option v-for="severity in SEVERITY_OPTIONS" :key="severity" :value="severity">
                    {{ severityLabel(severity) }}
                  </option>
                </select>
              </label>
              <label>
                <span>{{ t('common.status') }}</span>
                <select v-model="vulnerabilityDraft.status">
                  <option
                    v-for="status in VULNERABILITY_STATUS_OPTIONS"
                    :key="status"
                    :value="status"
                  >
                    {{ vulnerabilityStatusLabel(status) }}
                  </option>
                </select>
              </label>
            </div>
            <label>
              <span>{{ t('vulnerability.target') }}</span>
              <input v-model="vulnerabilityDraft.target" />
            </label>
            <label>
              <span>{{ t('project.factEvidence') }}</span>
              <textarea v-model="vulnerabilityDraft.evidence" rows="6"></textarea>
            </label>
            <label>
              <span>{{ t('vulnerability.impact') }}</span>
              <textarea v-model="vulnerabilityDraft.impact" rows="5"></textarea>
            </label>
            <div class="gap-edit-actions">
              <button class="button compact" type="button" @click="saveVulnerabilityGap">
                {{ t('common.save') }}
              </button>
              <button class="button compact" type="button" @click="closeVulnerabilityEditor">
                {{ t('common.cancel') }}
              </button>
            </div>
          </div>
        </section>
      </div>
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
      <DataPagination
        :total="conversationsTotal"
        :page="conversationsPage"
        :page-size="conversationsPageSize"
        :total-pages="Math.ceil(conversationsTotal / conversationsPageSize)"
        @page-change="changeConversationsPage"
        @page-size-change="changeConversationsPageSize"
      />
    </section>

    <section v-if="activeTab === 'vulnerabilities'" class="panel">
      <header class="panel-header">
        <h2>{{ t('project.tabVulnerabilities') }}</h2>
        <RouterLink class="panel-link" to="/vulnerabilities">{{ t('project.goVulnerabilities') }}</RouterLink>
      </header>
      <section
        v-if="vulnerabilityReportDrafts.length"
        class="vulnerability-draft-section"
        :class="{ expanded: vulnerabilityDraftsExpanded }"
      >
        <header class="vulnerability-draft-section-head">
          <div>
            <strong>{{ t('project.pendingVulnerabilityDrafts') }}</strong>
            <p v-if="vulnerabilityDraftsExpanded">
              {{ t('project.pendingVulnerabilityDraftsHint') }}
            </p>
          </div>
          <div class="vulnerability-draft-summary">
            <span
              class="chip"
              :class="{ 'is-warning': vulnerabilityDraftAttentionCount > 0 }"
            >
              {{
                vulnerabilityDraftAttentionCount
                  ? t('project.pendingVulnerabilityDraftsAttention', {
                      count: vulnerabilityDraftAttentionCount,
                    })
                  : t('project.pendingVulnerabilityDraftsSummary', {
                      count: vulnerabilityDraftsTotal,
                    })
              }}
            </span>
            <button
              class="button compact"
              type="button"
              :aria-expanded="vulnerabilityDraftsExpanded"
              @click="vulnerabilityDraftsExpanded = !vulnerabilityDraftsExpanded"
            >
              {{
                vulnerabilityDraftsExpanded
                  ? t('project.pendingVulnerabilityDraftsCollapse')
                  : t('project.pendingVulnerabilityDraftsExpand')
              }}
            </button>
          </div>
        </header>
        <div v-if="vulnerabilityDraftsExpanded" class="mission-gap-cards">
          <article
            v-for="item in vulnerabilityReportDrafts"
            :key="item.id"
            class="mission-gap-card vulnerability-draft-card"
          >
            <header>
              <span class="chip" :class="`sev-${item.severity}`">
                {{ severityLabel(item.severity) }}
              </span>
              <strong>{{ item.title || item.vulnerabilityType || item.id }}</strong>
            </header>
            <p>{{ item.target || '-' }}</p>
            <p class="vulnerability-draft-error" :title="item.lastError">
              {{ item.lastError || t('project.vulnerabilityDraftProcessing') }}
            </p>
            <footer>
              <span>
                {{ vulnerabilityDraftStatusLabel(item.status) }}
                · {{ t('project.vulnerabilityDraftAttempts', { count: item.attempts }) }}
              </span>
              <div class="vulnerability-draft-actions">
                <button
                  v-if="canRetryVulnerabilityDraft(item)"
                  class="button compact"
                  type="button"
                  @click="retryVulnerabilityReportDraft(item)"
                >
                  {{ t('project.retryVulnerabilityDraft') }}
                </button>
                <button
                  class="button compact"
                  type="button"
                  :disabled="item.status === 'processing' || vulnerabilityDraftConfirmingId === item.id"
                  @click="confirmVulnerabilityDraft(item)"
                >
                  {{
                    vulnerabilityDraftConfirmingId === item.id
                      ? t('common.loading')
                      : t('project.confirmVulnerabilityDraft')
                  }}
                </button>
                <button
                  class="button compact danger"
                  type="button"
                  :disabled="item.status === 'processing' || vulnerabilityDraftDeletingId === item.id"
                  @click="deleteVulnerabilityDraft(item)"
                >
                  {{
                    vulnerabilityDraftDeletingId === item.id
                      ? t('common.loading')
                      : t('project.deleteVulnerabilityDraft')
                  }}
                </button>
              </div>
            </footer>
          </article>
        </div>
        <DataPagination
          :total="vulnerabilityDraftsTotal"
          :page="vulnerabilityDraftsPage"
          :page-size="vulnerabilityDraftsPageSize"
          :total-pages="Math.ceil(vulnerabilityDraftsTotal / vulnerabilityDraftsPageSize)"
          @page-change="changeVulnerabilityDraftsPage"
          @page-size-change="changeVulnerabilityDraftsPageSize"
        />
      </section>
      <div class="factory-table-scroll">
        <table class="data-list">
        <thead>
          <tr>
            <th>{{ t('vulnerability.severity') }}</th>
            <th>{{ t('vulnerability.name') }}</th>
            <th>{{ t('common.status') }}</th>
            <th>{{ t('vulnerability.target') }}</th>
            <th>{{ t('common.updatedAt') }}</th>
            <th>{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in vulnerabilities" :key="item.id">
            <td><span class="chip" :class="`sev-${item.severity}`">{{ severityLabel(item.severity) }}</span></td>
            <td>{{ item.title }}</td>
            <td>{{ vulnerabilityStatusLabel(item.status) }}</td>
            <td class="wrap-cell">{{ item.target || '-' }}</td>
            <td>{{ formatTime(item.updatedAt) }}</td>
            <td>
              <button
                v-if="item.status === 'pending_review'"
                class="button compact"
                type="button"
                :disabled="reviewRetryingId === item.id"
                @click="retryVulnerabilityReview(item)"
              >
                {{ reviewRetryingId === item.id ? t('common.loading') : t('project.retryVulnerabilityReview') }}
              </button>
            </td>
          </tr>
          <tr v-if="!vulnerabilities.length">
            <td class="empty-cell" colspan="6">{{ t('project.vulnerabilityEmpty') }}</td>
          </tr>
        </tbody>
        </table>
      </div>
      <DataPagination
        :total="vulnerabilitiesTotal"
        :page="vulnerabilitiesPage"
        :page-size="vulnerabilitiesPageSize"
        :total-pages="Math.ceil(vulnerabilitiesTotal / vulnerabilitiesPageSize)"
        @page-change="changeVulnerabilitiesPage"
        @page-size-change="changeVulnerabilitiesPageSize"
      />
    </section>

    <div
      v-if="vulnerabilityEditOpen && vulnerabilityDraft"
      class="fact-modal-backdrop"
      @click.self="closeVulnerabilityEditor"
    >
      <section class="fact-modal gap-edit-modal" role="dialog" aria-modal="true">
        <header class="fact-modal-head">
          <h3>{{ t('project.editEvidenceVulnerability') }}</h3>
          <button class="text-button dark" type="button" @click="closeVulnerabilityEditor">
            {{ t('common.close') }}
          </button>
        </header>
        <div class="gap-edit-form">
          <label>
            <span>{{ t('vulnerability.name') }}</span>
            <input v-model="vulnerabilityDraft.title" />
          </label>
          <div class="gap-edit-grid">
            <label>
              <span>{{ t('vulnerability.severity') }}</span>
              <select v-model="vulnerabilityDraft.severity">
                <option v-for="severity in SEVERITY_OPTIONS" :key="severity" :value="severity">
                  {{ severityLabel(severity) }}
                </option>
              </select>
            </label>
            <label>
              <span>{{ t('common.status') }}</span>
              <select v-model="vulnerabilityDraft.status">
                <option
                  v-for="status in VULNERABILITY_STATUS_OPTIONS"
                  :key="status"
                  :value="status"
                >
                  {{ vulnerabilityStatusLabel(status) }}
                </option>
              </select>
            </label>
          </div>
          <label>
            <span>{{ t('vulnerability.target') }}</span>
            <input v-model="vulnerabilityDraft.target" />
          </label>
          <label>
            <span>{{ t('project.factEvidence') }}</span>
            <textarea v-model="vulnerabilityDraft.evidence" rows="6"></textarea>
          </label>
          <label>
            <span>{{ t('vulnerability.impact') }}</span>
            <textarea v-model="vulnerabilityDraft.impact" rows="5"></textarea>
          </label>
          <div class="gap-edit-actions">
            <button class="button compact" type="button" @click="saveVulnerabilityGap">
              {{ t('common.save') }}
            </button>
            <button class="button compact" type="button" @click="closeVulnerabilityEditor">
              {{ t('common.cancel') }}
            </button>
          </div>
        </div>
      </section>
    </div>

    <div
      v-if="intentResultNode"
      class="fact-modal-backdrop"
      @click.self="closeIntentResult"
    >
      <section class="fact-modal intent-result-modal" role="dialog" aria-modal="true">
        <header class="fact-modal-head intent-result-modal-head">
          <div>
            <span class="intent-result-eyebrow">INTENT // RESULT</span>
            <h3>{{ intentResultNode.title }}</h3>
          </div>
          <button class="text-button dark" type="button" @click="closeIntentResult">
            {{ t('common.close') }}
          </button>
        </header>

        <div class="intent-result-meta">
          <span class="chip chip-plain">{{ graphStatusLabel(intentResultNode.status) }}</span>
          <span v-if="intentResultNode.assetId" class="chip chip-plain">
            {{ assetName(intentResultNode.assetId) }}
          </span>
          <span v-if="intentResultNode.confidence" class="chip chip-plain">
            {{ t('graph.confidenceShort', { value: intentResultNode.confidence }) }}
          </span>
          <span v-if="(intentResultNode.attempts ?? 0) > 0" class="chip chip-plain">
            {{ t('project.intentAttempts', { count: intentResultNode.attempts }) }}
          </span>
          <span class="chip chip-plain">
            {{ formatTime(intentResultNode.lastFinishedAt || intentResultNode.updatedAt) }}
          </span>
        </div>

        <section v-if="intentResultNode.detail" class="intent-result-block">
          <h4>{{ t('graph.detailLabel') }}</h4>
          <pre>{{ intentResultNode.detail }}</pre>
        </section>
        <section v-if="intentResultNode.result" class="intent-result-block">
          <h4>{{ t('project.intentCompletionResult') }}</h4>
          <pre>{{ intentResultNode.result }}</pre>
        </section>
        <section v-if="intentResultNode.stateReason" class="intent-result-block">
          <h4>{{ t('project.intentStateReason') }}</h4>
          <pre>{{ intentResultNode.stateReason }}</pre>
        </section>
        <section v-if="intentResultNode.evidence" class="intent-result-block">
          <h4>{{ t('project.intentEvidence') }}</h4>
          <pre>{{ intentResultNode.evidence }}</pre>
        </section>
        <section v-if="intentResultNode.evidenceRefs?.length" class="intent-result-block">
          <h4>{{ t('project.intentEvidenceRefs') }}</h4>
          <div class="intent-result-refs">
            <span v-for="ref in intentResultNode.evidenceRefs" :key="ref">{{ ref }}</span>
          </div>
        </section>
        <section v-if="intentResultNode.findingId" class="intent-result-block">
          <h4>{{ t('project.intentRelatedFinding') }}</h4>
          <pre>{{ intentResultNode.findingId }}</pre>
        </section>
        <p v-if="!intentHasCompletion(intentResultNode)" class="intent-result-missing">
          {{ t('project.intentResultMissing') }}
        </p>
      </section>
    </div>

    <div
      v-if="pendingIntentEditOpen"
      class="fact-modal-backdrop"
      @click.self="closePendingIntentEditor"
    >
      <section class="fact-modal gap-edit-modal" role="dialog" aria-modal="true">
        <header class="fact-modal-head">
          <h3>{{ t('project.editPendingIntent') }}</h3>
          <button class="text-button dark" type="button" @click="closePendingIntentEditor">
            {{ t('common.close') }}
          </button>
        </header>
        <div class="gap-edit-form">
          <label>
            <span>{{ t('graph.titleLabel') }}</span>
            <input v-model="nodeDraft.title" />
          </label>
          <label>
            <span>{{ t('graph.statusLabel') }}</span>
            <select v-model="nodeDraft.status">
              <option v-for="status in GRAPH_STATUS_OPTIONS.intent" :key="status" :value="status">
                {{ graphStatusLabel(status) }}
              </option>
            </select>
          </label>
          <label>
            <span>{{ t('graph.assetLabel') }}</span>
            <select v-model="nodeDraft.assetId">
              <option value="">{{ t('graph.assetNone') }}</option>
              <option v-for="asset in assets" :key="asset.id" :value="asset.id">
                {{ asset.name || asset.value }}
              </option>
            </select>
          </label>
          <label>
            <span>{{ t('graph.detailLabel') }}</span>
            <textarea v-model="nodeDraft.detail" rows="8"></textarea>
          </label>
          <div class="gap-edit-actions">
            <button class="button compact" type="button" @click="savePendingIntent">
              {{ t('common.save') }}
            </button>
            <button class="button compact" type="button" @click="closePendingIntentEditor">
              {{ t('common.cancel') }}
            </button>
          </div>
        </div>
      </section>
    </div>
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

.project-filter-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
}

.project-search-input {
  flex: 1 1 280px;
  min-width: 180px;
  max-width: 440px;
  padding: 7px 10px;
  color: var(--text-primary);
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.project-search-input:focus {
  border-color: var(--accent);
  outline: none;
}

.project-filter-count {
  margin-left: auto;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
  white-space: nowrap;
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

.project-brief .project-scope {
  display: grid;
  gap: 3px;
  justify-items: start;
  min-width: 0;
}

.project-scope-text {
  display: block;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.project-scope-text.clamped {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
}

.project-scope-toggle {
  padding: 0;
  border: 0;
  color: var(--accent);
  background: transparent;
  font-size: 11px;
  cursor: pointer;
}

.project-scope-toggle:hover,
.project-scope-toggle:focus-visible {
  color: color-mix(in srgb, var(--accent) 78%, white);
  outline: none;
  text-decoration: underline;
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

.intent-card {
  align-content: start;
}

.intent-card footer {
  margin-top: auto;
}

.intent-result {
  display: grid;
  gap: 3px;
  padding: 7px 0 7px 10px;
  border-left: 2px solid var(--accent-line);
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.intent-result > strong {
  color: var(--accent);
  font-size: 11px;
}

.intent-result p,
.intent-result small {
  margin: 0;
}

.intent-result-preview {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.intent-result-link {
  width: fit-content;
  padding: 0;
  font-size: 10px;
}

.intent-result p > span {
  margin-right: 4px;
  color: var(--text-muted);
}

.intent-result-missing {
  color: var(--warning, var(--text-muted));
}

.intent-result-modal {
  width: min(920px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}

.intent-result-modal-head {
  align-items: flex-start;
}

.intent-result-modal-head h3 {
  overflow-wrap: anywhere;
}

.intent-result-eyebrow {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
}

.intent-result-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.intent-result-modal > .intent-result-block,
.intent-result-modal > .intent-result-missing {
  min-height: 0;
}

.intent-result-block {
  display: grid;
  gap: 6px;
}

.intent-result-block h4 {
  margin: 0;
  color: var(--text-muted);
  font-size: 10px;
}

.intent-result-block pre {
  max-height: 220px;
  margin: 0;
  padding: 10px 12px;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--text-secondary);
  background: var(--field-bg);
  font: inherit;
  font-size: 12px;
  line-height: 1.65;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.intent-result-refs {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.intent-result-refs span {
  padding: 4px 7px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 10px;
  overflow-wrap: anywhere;
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
  --mission-evidence: #55c7e8;
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
  grid-template-columns: repeat(5, minmax(74px, 1fr));
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

.coverage-signals span.is-warning strong {
  color: var(--danger, #e05d44);
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

.mission-workboards {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1px;
  border-top: 1px solid var(--project-line);
  background: var(--project-line);
}

.mission-workboard {
  min-width: 0;
  padding: 10px 12px 0;
  background: var(--project-panel);
}

.mission-workboard-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.mission-workboard-head h3 {
  margin: 2px 0 0;
  color: var(--text);
  font-size: 12px;
  font-weight: 600;
}

.mission-workboard-code {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.08em;
}

.mission-workboard-total {
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 18px;
  line-height: 1;
}

.mission-workboard-evidence .mission-workboard-total {
  color: var(--mission-evidence);
}

.mission-gap-cards {
  display: grid;
  gap: 8px;
  padding-bottom: 10px;
}

.tab-gap-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 10px;
}

.evidence-gap-group .tab-gap-card-grid {
  grid-template-columns: 1fr;
}

.mission-gap-card {
  display: grid;
  gap: 7px;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid var(--project-line);
  border-radius: 4px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--project-accent) 4%, transparent), transparent 36px),
    var(--surface);
}

.mission-evidence-card {
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--mission-evidence) 5%, transparent), transparent 36px),
    var(--surface);
}

.mission-gap-card header {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 7px;
}

.mission-gap-card header strong {
  overflow: hidden;
  color: var(--text);
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mission-gap-card > p {
  display: -webkit-box;
  overflow: hidden;
  min-height: 26px;
  margin: 0;
  color: var(--text-muted);
  font-size: 9px;
  line-height: 1.45;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.mission-gap-meta,
.mission-gap-card footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.mission-gap-meta {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.mission-gap-meta span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mission-gap-card footer {
  justify-content: flex-end;
}

.mission-gap-card footer .button {
  min-height: 24px;
  padding: 4px 8px;
  font-size: 9px;
}

.vulnerability-draft-section {
  display: grid;
  gap: 8px;
  margin-bottom: 14px;
  padding: 9px 10px;
  border: 1px solid color-mix(in srgb, var(--project-accent) 24%, var(--project-line));
  border-radius: 4px;
  background: color-mix(in srgb, var(--project-accent) 3%, var(--surface));
}

.vulnerability-draft-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.vulnerability-draft-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
}

.vulnerability-draft-summary .chip.is-warning {
  border-color: color-mix(in srgb, var(--warning, #d49b3f) 45%, var(--project-line));
  color: var(--warning, #d49b3f);
  background: color-mix(in srgb, var(--warning, #d49b3f) 8%, var(--surface));
}

.vulnerability-draft-section-head strong {
  color: var(--text);
  font-size: 12px;
}

.vulnerability-draft-section-head p {
  margin: 3px 0 0;
  color: var(--text-muted);
  font-size: 9px;
}

.vulnerability-draft-card footer {
  justify-content: space-between;
}

.vulnerability-draft-card footer > span {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.vulnerability-draft-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 5px;
}

.vulnerability-draft-error {
  color: var(--warning, #d49b3f) !important;
}

.mission-workboard-rows {
  display: grid;
  gap: 1px;
}

.mission-workboard-row {
  display: grid;
  align-items: center;
  gap: 8px;
  min-width: 0;
  min-height: 42px;
  padding: 7px 8px;
  border-left: 2px solid var(--project-accent);
  background: color-mix(in srgb, var(--project-accent) 5%, var(--surface));
}

.mission-workboard-row + .mission-workboard-row {
  border-top: 1px solid var(--project-line);
}

.mission-intent-row {
  grid-template-columns: 12px minmax(0, 1fr) auto;
}

.mission-evidence-row {
  grid-template-columns: auto minmax(0, 1fr) auto;
  border-left-color: var(--mission-evidence);
  background: color-mix(in srgb, var(--mission-evidence) 5%, var(--surface));
}

.mission-intent-rail {
  position: relative;
  align-self: stretch;
  display: grid;
  place-items: center;
}

.mission-intent-rail::before {
  position: absolute;
  top: -7px;
  bottom: -7px;
  left: 5px;
  width: 1px;
  background: color-mix(in srgb, var(--project-accent) 34%, transparent);
  content: '';
}

.mission-intent-rail i {
  position: relative;
  z-index: 1;
  width: 7px;
  height: 7px;
  border: 1px solid var(--project-accent);
  border-radius: 50%;
  background: var(--surface);
}

.mission-evidence-type {
  padding: 2px 5px;
  border: 1px solid color-mix(in srgb, var(--mission-evidence) 38%, var(--border));
  border-radius: 2px;
  color: var(--mission-evidence);
  font-family: var(--mono);
  font-size: 7px;
  white-space: nowrap;
}

.mission-workboard-copy {
  display: grid;
  gap: 2px;
  min-width: 0;
}

.mission-workboard-copy strong {
  overflow: hidden;
  color: var(--text);
  font-size: 10px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mission-workboard-copy small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mission-workboard-score {
  min-width: 24px;
  color: var(--project-accent);
  font-family: var(--mono);
  font-size: 9px;
  text-align: right;
}

.mission-evidence-row .mission-workboard-score {
  color: var(--mission-evidence);
}

.mission-workboard-empty {
  min-height: 42px;
  margin: 0;
  padding: 12px 8px;
  border: 1px dashed var(--project-line);
  color: var(--text-muted);
  font-size: 9px;
}

.mission-workboard-more {
  display: block;
  margin: 6px 0 0 auto;
  padding: 4px 0 7px;
  border: 0;
  background: transparent;
  color: var(--project-accent);
  font-size: 9px;
  cursor: pointer;
}

.mission-workboard-evidence .mission-workboard-more {
  color: var(--mission-evidence);
}

.mission-workboard-more:hover {
  text-decoration: underline;
}

.project-mission-panel > .muted {
  margin: 0;
  padding: 10px 12px;
  border-top: 1px solid var(--border);
  font-size: 10px;
}

.project-module-nav {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
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

.gap-management-list,
.evidence-gap-group {
  display: grid;
  gap: 6px;
}

.gap-management-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-left: 3px solid var(--project-accent);
  border-radius: 4px;
  background: var(--surface-raised);
}

.gap-management-main {
  display: grid;
  gap: 5px;
  min-width: 0;
}

.gap-management-title {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}

.gap-management-title strong {
  overflow: hidden;
  color: var(--text);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.gap-management-main p {
  display: -webkit-box;
  overflow: hidden;
  margin: 0;
  color: var(--text-muted);
  font-size: 10px;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.gap-management-main small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.gap-management-actions {
  display: flex;
  gap: 6px;
}

.gap-status {
  flex: 0 0 auto;
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-style: normal;
}

.gap-status.is-open {
  border-color: color-mix(in srgb, var(--project-accent) 38%, var(--border));
  color: var(--project-accent);
}

.gap-status.is-running {
  border-color: color-mix(in srgb, var(--success) 44%, var(--border));
  color: var(--success);
}

.gap-status.is-fact {
  color: var(--mission-evidence);
}

.evidence-gap-columns {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.evidence-gap-group {
  align-content: start;
}

.evidence-gap-group > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 10px;
}

.evidence-gap-group > header span {
  color: var(--mission-evidence);
  font-family: var(--mono);
}

.evidence-gap-group .gap-management-row {
  grid-template-columns: minmax(0, 1fr);
}

.evidence-gap-group .gap-management-actions {
  justify-content: flex-end;
}

.gap-edit-modal {
  width: min(720px, calc(100vw - 24px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}

.gap-edit-form {
  display: grid;
  gap: 12px;
  padding: 14px;
}

.gap-edit-form label {
  display: grid;
  gap: 5px;
  color: var(--text-muted);
  font-size: 10px;
}

.gap-edit-form input,
.gap-edit-form select,
.gap-edit-form textarea {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text);
  background: var(--field-bg);
  font: inherit;
}

.gap-edit-form textarea {
  resize: vertical;
}

.gap-edit-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.gap-edit-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

@media (max-width: 980px) {
  .coverage-body {
    grid-template-columns: 1fr;
  }

  .mission-workboards {
    grid-template-columns: 1fr;
  }

  .evidence-gap-columns {
    grid-template-columns: 1fr;
  }

  .project-module-nav {
    grid-template-columns: repeat(4, minmax(0, 1fr));
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
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .gap-management-row {
    grid-template-columns: 1fr;
  }

  .gap-management-actions {
    justify-content: flex-end;
  }

  .gap-edit-grid {
    grid-template-columns: 1fr;
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

  .project-filter-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .project-search-input {
    width: 100%;
    max-width: none;
  }

  .project-filter-count {
    margin-left: 0;
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
