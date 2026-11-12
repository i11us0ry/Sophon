import { defineStore } from 'pinia'

import { apiDelete, apiGet, apiPost, apiPut, apiStream, apiUpload } from '../api/client'
import { translate } from '../i18n'

const MESSAGE_WINDOW_SIZE = 80
const MESSAGE_PAGE_SIZE = 50
const LIVE_STEP_WINDOW_SIZE = 500
// The API caps each response at 512 KiB, so keep the default page below that limit.
const PROCESS_DETAIL_PAGE_SIZE = 100
const AGENT_MODE_STORAGE_KEY = 'sophon.agentMode'
const CONVERSATION_AGENT_MODE_STORAGE_KEY = 'sophon.agentModeByConversation'
const CONVERSATION_AGENT_MODE_LIMIT = 200

export type AgentMode = 'auto' | 'fast' | 'deep'

function isAgentMode(value: unknown): value is AgentMode {
  return value === 'auto' || value === 'fast' || value === 'deep'
}

function normalizeAgentMode(value: unknown): AgentMode {
  return value === 'fast' || value === 'deep' ? value : 'deep'
}

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((item) => String(item || '').trim()).filter(Boolean)
    : []
}

function readStoredAgentMode(): AgentMode {
  try {
    const mode = window.localStorage.getItem(AGENT_MODE_STORAGE_KEY)
    if (mode === 'fast' || mode === 'deep') {
      return mode
    }
    return 'deep'
  } catch {
    return 'deep'
  }
}

function readConversationAgentModes(): Record<string, AgentMode> {
  try {
    const raw = window.localStorage.getItem(CONVERSATION_AGENT_MODE_STORAGE_KEY)
    if (!raw) {
      return {}
    }
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {}
    }
    const result: Record<string, AgentMode> = {}
    for (const [conversationId, mode] of Object.entries(parsed).slice(
      -CONVERSATION_AGENT_MODE_LIMIT,
    )) {
      if (conversationId && isAgentMode(mode)) {
        result[conversationId] = mode
      }
    }
    return result
  } catch {
    return {}
  }
}

function persistConversationAgentModes(modes: Record<string, AgentMode>) {
  try {
    window.localStorage.setItem(CONVERSATION_AGENT_MODE_STORAGE_KEY, JSON.stringify(modes))
  } catch {
    // 本地存储不可用时仍保留当前页面内的会话模式。
  }
}

export interface Conversation {
  id: string
  title: string
  projectId?: string
  assetId?: string
  kind?: 'normal' | 'batch_parent' | 'batch_child'
  parentConversationId?: string
  batchId?: string
  childCount?: number
  agentRoleId?: string
  lastUserMessage?: string
  status?: 'idle' | 'queued' | 'running' | 'waiting'
  createdAt: string
  updatedAt: string
}

export interface ConversationPage {
  items: Conversation[]
  hasMore: boolean
  nextCursor?: string
}

export interface ConversationBatchResult {
  parent: Conversation
  created: number
  reused: number
  invalid: number
  items: Array<{ conversationId: string; assetId: string; target: string }>
}

export interface CampaignStatus {
  id: string
  status: 'draft' | 'running' | 'paused' | 'completed' | 'failed'
  totalGroups: number
  totalAssets: number
  totalEndpoints: number
  queuedTasks: number
  runningTasks: number
  completedTasks: number
  failedTasks: number
  pausedTasks: number
  coverageTotal: number
  coverageCompleted: number
  pendingFrontier: number
  pendingVerification: number
  linkCount: number
  chainCount: number
  hotMemoryCount: number
  coldMemoryCount: number
  campaignMode: 'single' | 'continuous'
  campaignRound: number
  maxRounds: number
  campaignToolCallBudget: number
  campaignToolCalls: number
}

export interface CampaignGroup {
  id: string
  groupKey: string
  label: string
  status: string
  totalAssets: number
  completedAssets: number
  failedAssets: number
  businessSystem: string
  businessPriority: number
  priorityScore: number
  priorityReason: string
}

export interface CampaignFrontierItem {
  id: string
  assetId: string
  taskId: string
  kind: string
  priority: number
  expectedValue: number
  estimatedCost: number
  roi: number
  reason: string
  status: string
  sourceType?: string
  sourceRef?: string
}

export interface CampaignVerification {
  id: string
  findingId: string
  taskId: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  attempts: number
  maxAttempts: number
  result?: string
}

export interface CampaignChainStep {
  id: string
  stepOrder: number
  kind: string
  assetId: string
  sourceRef?: string
  summary: string
}

export interface CampaignChain {
  id: string
  title: string
  kind: string
  status: 'candidate' | 'testing' | 'verified' | 'failed'
  priority: number
  confidence: number
  entryAssetId: string
  targetAssetId: string
  steps: CampaignChainStep[]
}

export interface CampaignMemoryDigest {
  id: string
  scopeType: string
  scopeId: string
  tier: 'hot' | 'cold'
  kind: string
  summary: string
  sourceCount: number
  freshness: number
}

export interface CampaignLink {
  id: string
  srcAssetId: string
  dstAssetId: string
  kind: string
  summary: string
  confidence: number
}

export interface AgentRun {
  id: string
  conversationId: string
  assistantMessageId: string
  agentMode?: AgentMode
  status: 'running' | 'completed' | 'failed' | 'interrupted' | 'cancelled'
  segmentCount: number
  interruptionReason?: string
  startedAt: string
  updatedAt: string
}

export interface AgentRoleOption {
  id: string
  name: string
  icon: string
  prompt?: string
  defaultMode?: AgentMode
  enabled: boolean
}

export interface ChatMessage {
  id: string
  conversationId: string
  role: string
  content: string
  reasoningContent?: string
  reasoningTruncated?: boolean
  processDetailCount?: number
  createdAt: string
}

export interface MessagePage {
  items: ChatMessage[]
  hasMore: boolean
  nextCursor?: string
}

export interface AgentStep {
  id: string
  type:
    | 'reasoning'
    | 'thinking'
    | 'tool_call'
    | 'tool_result'
    | 'agent_started'
    | 'agent_completed'
    | 'agent_failed'
  toolName?: string
  toolCallId?: string
  content: string
  agentId?: string
  agentName?: string
  agentKind?: string
  parentAgentId?: string
  intentId?: string
  hypothesisId?: string
  capabilityMode?: string
  workerFocus?: string
  allowedSkills?: string[]
  task?: string
  status?: string
  durationMs?: number
  resultSummary?: string
  errorMessage?: string
}

export interface ProcessDetail {
  id: string
  eventType: string
  message: string
  data?: Record<string, unknown>
  messageId?: string
  createdAt: string
}

export interface AgentTraceEntry {
  agentId: string
  agentName: string
  agentKind: string
  workerFocus: string
  allowedSkills: string[]
  task: string
  status: string
  durationMs: number
  result: string
  error: string
}

export interface AgentTraceSummary {
  main: number
  planner: number
  worker: number
  subagent: number
  agents: AgentTraceEntry[]
  agentsTruncated?: boolean
}

export interface Attachment {
  id: string
  conversationId: string
  messageId: string
  fileName: string
  mimeType: string
  sizeBytes: number
  createdAt: string
}

export interface HITLRequest {
  id: string
  conversationId: string
  toolName: string
  arguments: Record<string, unknown>
}

export interface Project {
  id: string
  name: string
  status: string
}

export const useChatStore = defineStore('chat', {
  state: () => ({
    conversations: [] as Conversation[],
    conversationsHasMore: false,
    conversationsNextCursor: '',
    loadingOlderConversations: false,
    projects: [] as Project[],
    roles: [] as AgentRoleOption[],
    rolesLoaded: false,
    selectedProjectId: '',
    selectedRoleId: '',
    agentMode: readStoredAgentMode() as AgentMode,
    agentModeByConversation: readConversationAgentModes(),
    messages: [] as ChatMessage[],
    processDetails: [] as ProcessDetail[],
    processDetailMeta: {} as Record<
      string,
      {
        loaded: boolean
        loading: boolean
        hasMore: boolean
        nextOffset: number
        loadedStart: number
        total: number
        pageStart?: number
        pageEnd?: number
        agentSummary?: AgentTraceSummary
      }
    >,
    liveSteps: [] as AgentStep[],
    reasoningText: '',
    liveReasoningByAgent: {} as Record<string, AgentStep>,
    attachments: [] as Attachment[],
    pendingAttachments: [] as Attachment[],
    uploading: false,
    creatingConversation: false,
    batchCreating: false,
    campaignLoading: false,
    currentCampaignStatus: null as CampaignStatus | null,
    campaignGroups: [] as CampaignGroup[],
    campaignFrontier: [] as CampaignFrontierItem[],
    campaignVerifications: [] as CampaignVerification[],
    campaignLinks: [] as CampaignLink[],
    campaignChains: [] as CampaignChain[],
    campaignMemory: [] as CampaignMemoryDigest[],
    conversationChildren: {} as Record<string, Conversation[]>,
    conversationChildrenTotal: {} as Record<string, number>,
    loadingConversationChildren: {} as Record<string, boolean>,
    hitlEnabled: false,
    hitlOverridden: false,
    hitlLoading: false,
    hitlUpdating: false,
    autoContinue: true,
    autoContinueLoading: false,
    autoContinueUpdating: false,
    currentConversationId: '',
    streamConversationId: '',
    taskId: '',
    messagesHasMore: false,
    messagesNextCursor: '',
    messagesHasNewer: false,
    messagesNextNewerCursor: '',
    messagesNeedsLatestRefresh: false,
    loadingOlderMessages: false,
    loadingNewerMessages: false,
    responseText: '',
    pendingHITL: [] as HITLRequest[],
    loading: false,
    streaming: false,
    currentResumableRun: null as AgentRun | null,
    resumableRunLoading: false,
    error: '',
  }),
  actions: {
    async loadConversations() {
      const [projects, response] = await Promise.all([
        apiGet<{ items: Project[] }>('/projects'),
        apiGet<ConversationPage>('/conversations?limit=100'),
      ])
      this.projects = projects.items
      this.conversations = response.items
      this.conversationChildren = {}
      this.conversationChildrenTotal = {}
      this.loadingConversationChildren = {}
      this.conversationsHasMore = Boolean(response.hasMore)
      this.conversationsNextCursor = response.nextCursor || ''
      try {
        const roles = await apiGet<{ items: AgentRoleOption[] }>('/agent-roles?enabled=true')
        this.roles = (roles.items ?? []).filter(
          (role) => role.prompt === undefined || role.prompt.trim() !== '',
        )
        this.rolesLoaded = true
        if (
          this.selectedRoleId &&
          !this.roles.some((role) => role.id === this.selectedRoleId)
        ) {
          this.selectedRoleId = ''
        }
      } catch {
        this.roles = []
        this.rolesLoaded = false
      }
      if (!this.currentConversationId && this.conversations.length > 0) {
        await this.selectConversation(this.conversations[0].id)
      }
    },
    roleRequestPayload() {
      return this.rolesLoaded ? { roleId: this.selectedRoleId } : {}
    },
    agentModeRequestPayload() {
      return { agentMode: this.agentMode }
    },
    rememberAgentMode(conversationId: string, mode: AgentMode) {
      if (!conversationId) {
        return
      }
      this.agentModeByConversation[conversationId] = normalizeAgentMode(mode)
      const conversationIds = Object.keys(this.agentModeByConversation)
      if (conversationIds.length > CONVERSATION_AGENT_MODE_LIMIT) {
        for (const staleId of conversationIds.slice(
          0,
          conversationIds.length - CONVERSATION_AGENT_MODE_LIMIT,
        )) {
          delete this.agentModeByConversation[staleId]
        }
      }
      persistConversationAgentModes(this.agentModeByConversation)
    },
    setAgentMode(mode: AgentMode) {
      this.agentMode = normalizeAgentMode(mode)
      if (this.currentConversationId) {
        this.rememberAgentMode(this.currentConversationId, this.agentMode)
      }
      try {
        window.localStorage.setItem(AGENT_MODE_STORAGE_KEY, this.agentMode)
      } catch {
        // 本地存储不可用时仍保留本次页面会话内的选择。
      }
    },
    selectRole(roleId: string) {
      this.selectedRoleId = roleId
      const role = this.roles.find((item) => item.id === roleId)
      this.setAgentMode(role?.defaultMode || 'auto')
    },
    async loadOlderConversations() {
      const cursor = this.conversationsNextCursor
      if (
        !cursor ||
        !this.conversationsHasMore ||
        this.loadingOlderConversations
      ) {
        return 0
      }
      this.loadingOlderConversations = true
      try {
        const response = await apiGet<ConversationPage>(
          `/conversations?limit=100&before=${encodeURIComponent(cursor)}`,
        )
        const existing = new Set(this.conversations.map((item) => item.id))
        const older = response.items.filter((item) => !existing.has(item.id))
        this.conversations.push(...older)
        this.conversationsHasMore = Boolean(response.hasMore)
        this.conversationsNextCursor = response.nextCursor || ''
        return older.length
      } catch (error) {
        this.error = error instanceof Error ? error.message : '加载更多对话失败'
        return 0
      } finally {
        this.loadingOlderConversations = false
      }
    },
    projectAllowsWork(projectId: string) {
      const project = this.projects.find((item) => item.id === projectId)
      if (project?.status === 'active') {
        return true
      }
      const statusKey = project?.status ? `projectStatus.${project.status}` : 'projectStatus.archived'
      this.error = translate('chat.projectInactive', {
        status: translate(statusKey),
      })
      return false
    },
    async refreshConversationStatuses() {
      try {
        const response = await apiGet<ConversationPage>('/conversations?limit=100')
        const existing = new Map(this.conversations.map((item) => [item.id, item]))
        const recentIDs = new Set(response.items.map((item) => item.id))
        const recent = response.items.map((item) => {
          const previous = existing.get(item.id)
          let status: Conversation['status'] = item.status ?? 'idle'
          if (
            item.id === this.streamConversationId &&
            this.streamConversationId !== '' &&
            status === 'running' &&
            this.pendingHITL.some(
              (request) => request.conversationId === this.streamConversationId,
            )
          ) {
            status = 'waiting'
          }
          return { ...(previous ?? {}), ...item, status }
        })
        const older = this.conversations.filter((item) => !recentIDs.has(item.id))
        this.conversations = [...recent, ...older]
        if (older.length === 0) {
          this.conversationsHasMore = Boolean(response.hasMore)
          this.conversationsNextCursor = response.nextCursor || ''
        }
      } catch {
        // 状态轮询失败不影响对话
      }
    },
    setConversationStatus(
      conversationId: string,
      status: Conversation['status'],
    ) {
      const conversation = this.conversations.find((item) => item.id === conversationId)
      if (conversation) {
        conversation.status = status
        return
      }
      for (const children of Object.values(this.conversationChildren)) {
        const child = children.find((item) => item.id === conversationId)
        if (child) {
          child.status = status
          return
        }
      }
    },
    async selectConversation(conversationId: string) {
      let conversation = this.conversations.find((item) => item.id === conversationId)
      if (!conversation) {
        try {
          conversation = await apiGet<Conversation>(`/conversations/${conversationId}`)
          if (conversation.kind === 'batch_child' && conversation.parentConversationId) {
            const parentID = conversation.parentConversationId
            const children = this.conversationChildren[parentID] ?? []
            if (!children.some((item) => item.id === conversation?.id)) {
              this.conversationChildren[parentID] = [...children, conversation]
            }
          } else {
            this.conversations.unshift(conversation)
          }
        } catch (error) {
          this.error = error instanceof Error ? error.message : '读取对话失败'
          return
        }
      }
      this.currentConversationId = conversationId
      this.error = ''
      this.selectedRoleId = conversation?.agentRoleId ?? ''
      const role = this.roles.find((item) => item.id === this.selectedRoleId)
      this.agentMode =
        this.agentModeByConversation[conversationId] ??
        normalizeAgentMode(role?.defaultMode)
      this.selectedProjectId = conversation?.projectId ?? ''
      this.responseText = ''
      this.liveSteps = []
      this.reasoningText = ''
      this.liveReasoningByAgent = {}
      this.pendingAttachments = []
      this.hitlEnabled = false
      this.hitlOverridden = false
      this.autoContinue = true
      this.currentResumableRun = null
      this.messages = []
      this.processDetails = []
      this.processDetailMeta = {}
      this.messagesHasMore = false
      this.messagesNextCursor = ''
      this.messagesHasNewer = false
      this.messagesNextNewerCursor = ''
      this.messagesNeedsLatestRefresh = false
      await this.loadLatestMessages()
      await this.loadAttachments()
      await this.loadConversationHITL()
      await this.loadConversationAgentSettings()
      await this.loadPendingHITL()
      await this.loadResumableRun(conversationId)
      if (conversation?.kind === 'batch_parent' && conversation.batchId) {
        await this.loadCampaignOverview(conversation.batchId)
      } else {
        this.currentCampaignStatus = null
        this.campaignGroups = []
        this.campaignFrontier = []
        this.campaignVerifications = []
        this.campaignLinks = []
        this.campaignChains = []
        this.campaignMemory = []
      }
    },
    async loadResumableRun(conversationId: string) {
      if (!conversationId) {
        this.currentResumableRun = null
        return
      }
      this.resumableRunLoading = true
      try {
        const response = await apiGet<{ run: AgentRun | null }>(
          `/conversations/${conversationId}/resumable-run`,
        )
        if (this.currentConversationId === conversationId) {
          this.currentResumableRun = response.run ?? null
        }
      } catch {
        if (this.currentConversationId === conversationId) {
          this.currentResumableRun = null
        }
      } finally {
        this.resumableRunLoading = false
      }
    },
    async resumeConversation(conversationId: string) {
      if (!conversationId || this.streaming) {
        return
      }
      this.currentConversationId = conversationId
      await this.runStream(`/conversations/${conversationId}/resume`, {})
      await this.loadResumableRun(conversationId)
    },
    async loadLatestMessages(): Promise<ChatMessage[]> {
      const conversationId = this.currentConversationId
      if (!conversationId) {
        this.messages = []
        this.processDetails = []
        this.processDetailMeta = {}
        this.messagesHasMore = false
        this.messagesNextCursor = ''
        this.messagesHasNewer = false
        this.messagesNextNewerCursor = ''
        this.messagesNeedsLatestRefresh = false
        return []
      }
      const response = await apiGet<MessagePage>(
        `/conversations/${conversationId}/messages?limit=${MESSAGE_PAGE_SIZE}&includeReasoning=summary`,
      )
      if (this.currentConversationId !== conversationId) {
        return []
      }
      // 流式生成期间服务端会先创建一个空 assistant 占位消息。
      // 实时流式时过滤占位，避免与实时区域重复；刷新后如果该占位已写入
      // process_details，则保留它，用于展示后台任务的最新思考和执行过程。
      const filtered = response.items.filter((item) => {
        if (item.role !== 'assistant' || item.content.trim()) {
          return true
        }
        if (
          this.streamConversationId !== '' &&
          this.streamConversationId === conversationId
        ) {
          return false
        }
        return (item.processDetailCount ?? 0) > 0
      })
      this.messages = filtered.slice(-MESSAGE_WINDOW_SIZE)
      this.messagesHasMore = Boolean(response.hasMore) || filtered.length > MESSAGE_WINDOW_SIZE
      this.messagesNextCursor = this.messages[0]?.id || response.nextCursor || ''
      this.messagesHasNewer = false
      this.messagesNextNewerCursor = this.messages.at(-1)?.id || ''
      this.messagesNeedsLatestRefresh = false
      this.pruneProcessDetailsToMessageWindow()
      const latestAssistant = [...this.messages]
        .reverse()
        .find((item) => item.role === 'assistant')
      if (
        latestAssistant &&
        (latestAssistant.processDetailCount ?? 0) > 0 &&
        !this.processDetailMeta[latestAssistant.id]?.loaded &&
        !this.processDetailMeta[latestAssistant.id]?.loading
      ) {
        await this.loadProcessDetailsForMessage(
          latestAssistant.id,
          true,
          latestAssistant.processDetailCount ?? 0,
        )
      }
      return this.messages
    },
    async loadOlderMessages(): Promise<number> {
      const conversationId = this.currentConversationId
      const cursor = this.messagesNextCursor
      if (
        !conversationId ||
        !cursor ||
        !this.messagesHasMore ||
        this.loadingOlderMessages ||
        this.loadingNewerMessages
      ) {
        return 0
      }
      this.loadingOlderMessages = true
      try {
        const response = await apiGet<MessagePage>(
          `/conversations/${conversationId}/messages?limit=${MESSAGE_PAGE_SIZE}&includeReasoning=0&before=${encodeURIComponent(cursor)}`,
        )
        if (this.currentConversationId !== conversationId) {
          return 0
        }
        const existing = new Set(this.messages.map((item) => item.id))
        const older = response.items.filter((item) => !existing.has(item.id))
        const combined = [...older, ...this.messages]
        const hasOverflow = combined.length > MESSAGE_WINDOW_SIZE
        this.messages = hasOverflow
          ? combined.slice(0, MESSAGE_WINDOW_SIZE)
          : combined
        this.messagesHasMore = Boolean(response.hasMore)
        this.messagesNextCursor =
          this.messages[0]?.id || response.nextCursor || ''
        this.messagesNextNewerCursor =
          this.messages.at(-1)?.id || cursor
        if (hasOverflow) {
          this.messagesHasNewer = true
        }
        this.pruneProcessDetailsToMessageWindow()
        return older.length
      } finally {
        if (this.currentConversationId === conversationId) {
          this.loadingOlderMessages = false
        }
      }
    },
    async loadNewerMessages(): Promise<number> {
      const conversationId = this.currentConversationId
      const cursor = this.messagesNextNewerCursor
      if (
        !conversationId ||
        !cursor ||
        !this.messagesHasNewer ||
        this.loadingNewerMessages ||
        this.loadingOlderMessages
      ) {
        return 0
      }
      this.loadingNewerMessages = true
      try {
        const response = await apiGet<MessagePage>(
          `/conversations/${conversationId}/messages?limit=${MESSAGE_PAGE_SIZE}&includeReasoning=0&after=${encodeURIComponent(cursor)}`,
        )
        if (this.currentConversationId !== conversationId) {
          return 0
        }
        const existing = new Set(this.messages.map((item) => item.id))
        const newer = response.items.filter((item) => !existing.has(item.id))
        const combined = [...this.messages, ...newer]
        const hasOverflow = combined.length > MESSAGE_WINDOW_SIZE
        this.messages = hasOverflow
          ? combined.slice(-MESSAGE_WINDOW_SIZE)
          : combined
        this.messagesHasNewer = Boolean(response.hasMore)
        this.messagesNextNewerCursor =
          this.messages.at(-1)?.id || cursor
        this.messagesNextCursor =
          this.messages[0]?.id || this.messagesNextCursor
        if (hasOverflow) {
          this.messagesHasMore = true
        }
        this.pruneProcessDetailsToMessageWindow()
        return newer.length
      } finally {
        if (this.currentConversationId === conversationId) {
          this.loadingNewerMessages = false
        }
      }
    },
    pruneProcessDetailsToMessageWindow() {
      const visibleMessageIDs = new Set(this.messages.map((item) => item.id))
      this.processDetails = this.processDetails.filter(
        (item) => !item.messageId || visibleMessageIDs.has(item.messageId),
      )
      for (const messageID of Object.keys(this.processDetailMeta)) {
        if (!visibleMessageIDs.has(messageID)) {
          delete this.processDetailMeta[messageID]
        }
      }
    },
    async loadProcessDetailsForMessage(
      messageId: string,
      refresh = false,
      totalHint = 0,
    ) {
      const conversationId = this.currentConversationId
      messageId = messageId.trim()
      if (!conversationId || !messageId) {
        return
      }
      const meta = this.processDetailMeta[messageId] ?? {
        loaded: false,
        loading: false,
        hasMore: true,
        nextOffset: 0,
        loadedStart: 0,
        total: 0,
      }
      if (meta.loading || (!refresh && meta.loaded && !meta.hasMore)) {
        return
      }
      this.processDetailMeta[messageId] = { ...meta, loading: true }
      try {
        const knownTotal = Math.max(meta.total || 0, totalHint)
        const pendingPage =
          typeof meta.pageEnd === 'number' && meta.nextOffset < meta.pageEnd
        const pageStart = pendingPage
          ? meta.pageStart ?? meta.nextOffset
          : refresh
            ? Math.max(0, knownTotal - PROCESS_DETAIL_PAGE_SIZE)
            : Math.max(0, meta.nextOffset - PROCESS_DETAIL_PAGE_SIZE)
        const pageEnd = pendingPage ? meta.pageEnd! : refresh ? knownTotal : meta.nextOffset
        const offset = pendingPage ? meta.nextOffset : pageStart
        const response = await apiGet<{
          items: ProcessDetail[]
          total: number
          hasMore: boolean
          nextOffset: number
          truncated?: boolean
          agentSummary?: AgentTraceSummary
        }>(
          `/conversations/${conversationId}/process-details?messageId=${encodeURIComponent(messageId)}&limit=${PROCESS_DETAIL_PAGE_SIZE}&offset=${offset}`,
        )
        if (this.currentConversationId !== conversationId) {
          return
        }
        const otherMessages = this.processDetails.filter(
          (item) => item.messageId !== messageId,
        )
        const existing = this.processDetails.filter(
          (item) => item.messageId === messageId,
        )
        const seen = new Set(existing.map((item) => item.id))
        const incoming = (response.items ?? []).filter((item) => !seen.has(item.id))
        const mergedByID = new Map<string, ProcessDetail>()
        for (const item of [...existing, ...incoming]) {
          mergedByID.set(item.id, item)
        }
        const merged = [...mergedByID.values()].sort(
          (left, right) =>
            left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id),
        )
        this.processDetails = [...otherMessages, ...merged]
        const fetchedCount = response.items?.length ?? 0
        const nextCursor = response.nextOffset || offset + fetchedCount
        const resolvedPageEnd = refresh
          ? Math.max(pageEnd, response.total || 0)
          : pageEnd
        const pageComplete =
          fetchedCount === 0 || nextCursor <= offset || nextCursor >= resolvedPageEnd
        const loadedStart = meta.loaded
          ? Math.min(meta.loadedStart, pageStart)
          : pageStart
        this.processDetailMeta[messageId] = {
          loaded: true,
          loading: false,
          hasMore: loadedStart > 0 || !pageComplete,
          nextOffset: pageComplete ? loadedStart : nextCursor,
          loadedStart,
          total: response.total || knownTotal || merged.length,
          pageStart: pageComplete ? undefined : pageStart,
          pageEnd: pageComplete ? undefined : resolvedPageEnd,
          agentSummary: response.agentSummary ?? meta.agentSummary,
        }
      } catch {
        this.processDetailMeta[messageId] = {
          ...meta,
          loading: false,
          loaded: true,
        }
      }
    },
    async loadAttachments() {
      if (!this.currentConversationId) {
        this.attachments = []
        return
      }
      try {
        const response = await apiGet<{ items: Attachment[] }>(
          `/conversations/${this.currentConversationId}/attachments`,
        )
        this.attachments = response.items
      } catch {
        this.attachments = []
      }
    },
    async uploadAttachment(file: File) {
      if (!this.currentConversationId) {
        return
      }
      this.uploading = true
      this.error = ''
      try {
        const item = await apiUpload<Attachment>(
          `/conversations/${this.currentConversationId}/attachments`,
          file,
        )
        this.pendingAttachments.push(item)
        this.attachments.push(item)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '附件上传失败'
      } finally {
        this.uploading = false
      }
    },
    async removePendingAttachment(id: string) {
      try {
        await apiDelete(`/attachments/${id}`)
        this.pendingAttachments = this.pendingAttachments.filter((item) => item.id !== id)
        this.attachments = this.attachments.filter((item) => item.id !== id)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '删除附件失败'
      }
    },
    syncPendingAttachments() {
      this.pendingAttachments = this.pendingAttachments.filter(
        (item) =>
          !this.attachments.some((linked) => linked.id === item.id && linked.messageId !== ''),
      )
    },
    async loadPendingHITL() {
      try {
        const response = await apiGet<{ items: HITLRequest[] }>('/hitl/pending')
        this.pendingHITL = response.items.filter(
          (item) => item.conversationId === this.currentConversationId,
        )
      } catch {
        // 待审批列表加载失败不影响对话主流程
      }
    },
    async loadConversationHITL() {
      const conversationId = this.currentConversationId
      if (!conversationId) {
        this.hitlEnabled = false
        this.hitlOverridden = false
        return
      }
      this.hitlLoading = true
      try {
        const response = await apiGet<{ enabled: boolean; overridden: boolean }>(
          `/conversations/${conversationId}/hitl`,
        )
        if (this.currentConversationId !== conversationId) {
          return
        }
        this.hitlEnabled = response.enabled
        this.hitlOverridden = response.overridden
      } catch {
        // 读取失败时保持当前 UI 状态，不影响对话主流程
      } finally {
        if (this.currentConversationId === conversationId) {
          this.hitlLoading = false
        }
      }
    },
    async setConversationHITL(enabled: boolean) {
      const conversationId = this.currentConversationId
      if (!conversationId || this.hitlUpdating) {
        return
      }
      const previous = this.hitlEnabled
      const previousOverridden = this.hitlOverridden
      this.hitlUpdating = true
      this.hitlEnabled = enabled
      this.hitlOverridden = true
      try {
        const response = await apiPut<{ enabled: boolean; overridden: boolean }>(
          `/conversations/${conversationId}/hitl`,
          { enabled },
        )
        if (this.currentConversationId === conversationId) {
          this.hitlEnabled = response.enabled
          this.hitlOverridden = response.overridden
        }
      } catch (error) {
        this.hitlEnabled = previous
        this.hitlOverridden = previousOverridden
        this.error = error instanceof Error ? error.message : '保存会话审批设置失败'
      } finally {
        this.hitlUpdating = false
      }
    },
    async loadConversationAgentSettings() {
      const conversationId = this.currentConversationId
      if (!conversationId) {
        this.autoContinue = true
        return
      }
      this.autoContinueLoading = true
      try {
        const response = await apiGet<{ autoContinue: boolean }>(
          `/conversations/${conversationId}/agent-settings`,
        )
        if (this.currentConversationId === conversationId) {
          this.autoContinue = response.autoContinue
        }
      } catch {
        // 读取失败时保持默认自动继续，不影响对话主流程
      } finally {
        if (this.currentConversationId === conversationId) {
          this.autoContinueLoading = false
        }
      }
    },
    async setAutoContinue(enabled: boolean) {
      const conversationId = this.currentConversationId
      if (!conversationId || this.autoContinueUpdating) {
        return
      }
      const previous = this.autoContinue
      this.autoContinueUpdating = true
      this.autoContinue = enabled
      try {
        const response = await apiPut<{ autoContinue: boolean }>(
          `/conversations/${conversationId}/agent-settings`,
          { autoContinue: enabled },
        )
        if (this.currentConversationId === conversationId) {
          this.autoContinue = response.autoContinue
        }
      } catch (error) {
        this.autoContinue = previous
        this.error = error instanceof Error ? error.message : '保存自动继续设置失败'
      } finally {
        this.autoContinueUpdating = false
      }
    },
    async stopConversation(conversationId = this.currentConversationId) {
      const targetID = conversationId || this.currentConversationId
      if (!targetID) {
        return 0
      }
      const response = await apiPost<{ cancelled: number }>(
        `/conversations/${targetID}/stop`,
        {},
      )
      await this.refreshConversationStatuses()
      await this.loadResumableRun(targetID)
      return response.cancelled ?? 0
    },
    async createConversation() {
      if (!this.selectedProjectId) {
        this.error = translate('chat.projectRequired')
        return
      }
      if (!this.projectAllowsWork(this.selectedProjectId)) {
        return
      }
      if (this.creatingConversation) {
        return
      }
      this.creatingConversation = true
      this.error = ''
      try {
        const initialAgentMode = this.agentMode
        const conversation = await apiPost<Conversation>('/conversations', {
          title: '新对话',
          projectId: this.selectedProjectId,
          ...this.roleRequestPayload(),
        })
        this.rememberAgentMode(conversation.id, initialAgentMode)
        this.conversations.unshift(conversation)
        await this.selectConversation(conversation.id)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '创建对话失败'
      } finally {
        this.creatingConversation = false
      }
    },
    async createConversationBatch(payload: {
      projectId: string
      title: string
      instruction: string
      assets: string
      roleId?: string
      maxConcurrency?: number
      maxAttemptsPerTask?: number
      maxSegmentsPerTask?: number
      maxToolCallsPerTask?: number
      campaignMode?: 'single' | 'continuous'
      maxRounds?: number
      campaignToolCallBudget?: number
    }) {
      if (!payload.projectId) {
        this.error = translate('chat.projectRequired')
        return null
      }
      if (!this.projectAllowsWork(payload.projectId)) {
        return null
      }
      if (this.batchCreating) {
        return null
      }
      this.batchCreating = true
      this.error = ''
      try {
        const result = await apiPost<ConversationBatchResult>('/conversations/batch', {
          ...payload,
          roleId: payload.roleId ?? '',
        })
        this.conversations.unshift(result.parent)
        await this.selectConversation(result.parent.id)
        await this.loadConversationChildren(result.parent.id, true)
        return result
      } catch (error) {
        this.error = error instanceof Error ? error.message : '创建批量对话失败'
        return null
      } finally {
        this.batchCreating = false
      }
    },
    async loadConversationChildren(parentId: string, force = false) {
      if (!parentId || this.loadingConversationChildren[parentId]) {
        return this.conversationChildren[parentId] ?? []
      }
      if (!force && Object.prototype.hasOwnProperty.call(this.conversationChildren, parentId)) {
        return this.conversationChildren[parentId]
      }
      this.loadingConversationChildren[parentId] = true
      try {
        const response = await apiGet<{
          items: Conversation[]
          total: number
          hasMore: boolean
          nextOffset: number
        }>(`/conversations/${parentId}/children?limit=500`)
        this.conversationChildren[parentId] = response.items ?? []
        this.conversationChildrenTotal[parentId] = response.total || 0
        return this.conversationChildren[parentId]
      } catch (error) {
        this.error = error instanceof Error ? error.message : '读取子对话失败'
        return []
      } finally {
        this.loadingConversationChildren[parentId] = false
      }
    },
    async loadCampaignOverview(campaignId: string) {
      if (!campaignId) {
        this.currentCampaignStatus = null
        this.campaignGroups = []
        this.campaignFrontier = []
        this.campaignVerifications = []
        this.campaignLinks = []
        this.campaignChains = []
        this.campaignMemory = []
        return
      }
      this.campaignLoading = true
      try {
        const [
          statusResponse,
          groupsResponse,
          frontierResponse,
          verificationResponse,
          linkResponse,
          chainResponse,
          memoryResponse,
        ] = await Promise.all([
          apiGet<{ status: CampaignStatus }>(
            `/conversation-batches/${campaignId}/status`,
          ),
          apiGet<{ items: CampaignGroup[] }>(
            `/conversation-batches/${campaignId}/groups`,
          ),
          apiGet<{ items: CampaignFrontierItem[] }>(
            `/conversation-batches/${campaignId}/frontier?limit=10`,
          ),
          apiGet<{ items: CampaignVerification[] }>(
            `/conversation-batches/${campaignId}/verifications?limit=10`,
          ),
          apiGet<{ items: CampaignLink[] }>(
            `/conversation-batches/${campaignId}/links?limit=10`,
          ),
          apiGet<{ items: CampaignChain[] }>(
            `/conversation-batches/${campaignId}/chains?limit=10`,
          ),
          apiGet<{ items: CampaignMemoryDigest[] }>(
            `/conversation-batches/${campaignId}/memory?limit=20`,
          ),
        ])
        this.currentCampaignStatus = statusResponse.status
        this.campaignGroups = groupsResponse.items ?? []
        this.campaignFrontier = frontierResponse.items ?? []
        this.campaignVerifications = verificationResponse.items ?? []
        this.campaignLinks = linkResponse.items ?? []
        this.campaignChains = chainResponse.items ?? []
        this.campaignMemory = memoryResponse.items ?? []
      } catch (error) {
        this.error = error instanceof Error ? error.message : '读取批量任务状态失败'
      } finally {
        this.campaignLoading = false
      }
    },
    async startCampaign(campaignId: string) {
      await apiPost(`/conversation-batches/${campaignId}/start`, {})
      await this.loadCampaignOverview(campaignId)
    },
    async pauseCampaign(campaignId: string) {
      await apiPost(`/conversation-batches/${campaignId}/pause`, {})
      await this.loadCampaignOverview(campaignId)
    },
    async resumeCampaign(campaignId: string) {
      await apiPost(`/conversation-batches/${campaignId}/resume`, {})
      await this.loadCampaignOverview(campaignId)
    },
    async recomputeCampaignPriorities(campaignId: string) {
      await apiPost(`/conversation-batches/${campaignId}/priority/recompute`, {})
      await this.loadCampaignOverview(campaignId)
    },
    async stopCampaign(campaignId: string) {
      await apiPost(`/conversation-batches/${campaignId}/stop`, {})
      await this.loadCampaignOverview(campaignId)
    },
    async setCampaignGroupPriority(
      campaignId: string,
      groupId: string,
      businessSystem: string,
      businessPriority: number,
    ) {
      await apiPut(`/conversation-batches/${campaignId}/groups/${groupId}/priority`, {
        businessSystem,
        businessPriority,
      })
      await this.loadCampaignOverview(campaignId)
    },
    async ensureConversationForProject() {
      if (this.currentConversationId || !this.selectedProjectId) {
        return
      }
      await this.createConversation()
    },
    appendLiveStep(step: AgentStep) {
      this.liveSteps.push(step)
      if (this.liveSteps.length > LIVE_STEP_WINDOW_SIZE) {
        this.liveSteps.splice(0, this.liveSteps.length - LIVE_STEP_WINDOW_SIZE)
      }
    },
    async runStream(path: string, body: Record<string, unknown>) {
      if (this.streaming) {
        return
      }
      const streamConversationID = String(
        body.conversationId || this.currentConversationId || '',
      )
      if (!streamConversationID) {
        this.error = translate('chat.projectRequired')
        return
      }
      this.streaming = true
      this.streamConversationId = streamConversationID
      this.taskId = ''
      this.error = ''
      this.setConversationStatus(streamConversationID, 'running')
      this.responseText = ''
      this.liveSteps = []
      this.reasoningText = ''
      this.liveReasoningByAgent = {}
      const viewingStream = () => this.currentConversationId === streamConversationID
      try {
        for await (const event of apiStream(path, body)) {
          const data = event.data || {}
          const eventConversationID = String(
            data.conversationId || streamConversationID,
          )
          if (eventConversationID !== streamConversationID) {
            continue
          }
          if (event.type === 'conversation') {
            this.taskId = String(data.taskId || '')
          } else if (event.type === 'response_delta') {
            const agentKind = String(data.agentKind || 'mainagent')
            if (agentKind === 'mainagent' && viewingStream()) {
              this.responseText += event.message
            }
          } else if (event.type === 'reasoning_delta') {
            if (!viewingStream()) {
              continue
            }
            const agentKind = String(data.agentKind || 'mainagent')
            if (agentKind === 'mainagent') {
              this.reasoningText += event.message
            } else {
              const agentId = String(data.agentId || agentKind)
              const existing = this.liveReasoningByAgent[agentId]
              this.liveReasoningByAgent[agentId] = {
                id: existing?.id || `live-reasoning-${agentId}`,
                type: 'reasoning',
                content: `${existing?.content || ''}${event.message}`,
                agentId,
                agentName: String(data.agentName || ''),
                agentKind,
                parentAgentId: String(data.parentAgentId || ''),
                intentId: String(data.intentId || ''),
                hypothesisId: String(data.hypothesisId || ''),
                capabilityMode: String(data.capabilityMode || ''),
              }
            }
          } else if (event.type === 'reasoning') {
            if (!viewingStream()) {
              continue
            }
            const content = String(
              data.reasoning || event.message || this.reasoningText,
            )
            if (content.trim()) {
              this.appendLiveStep({
                id: `reasoning-${this.liveSteps.length}-${Date.now()}`,
                type: 'reasoning',
                content,
                agentId: String(data.agentId || 'mainagent'),
                agentName: String(data.agentName || 'Sophon'),
                agentKind: String(data.agentKind || 'mainagent'),
                parentAgentId: String(data.parentAgentId || ''),
                intentId: String(data.intentId || ''),
                hypothesisId: String(data.hypothesisId || ''),
                capabilityMode: String(data.capabilityMode || ''),
              })
            }
            const agentId = String(data.agentId || 'mainagent')
            if (String(data.agentKind || 'mainagent') === 'mainagent') {
              this.reasoningText = ''
            } else {
              delete this.liveReasoningByAgent[agentId]
            }
          } else if (event.type === 'thinking') {
            if (!viewingStream()) {
              continue
            }
            const agentKind = String(data.agentKind || 'mainagent')
            this.appendLiveStep({
              id: `thinking-${this.liveSteps.length}-${Date.now()}`,
              type: 'thinking',
              content: event.message,
              agentId: String(data.agentId || 'mainagent'),
              agentName: String(data.agentName || 'Sophon'),
              agentKind: String(data.agentKind || 'mainagent'),
              parentAgentId: String(data.parentAgentId || ''),
              intentId: String(data.intentId || ''),
              hypothesisId: String(data.hypothesisId || ''),
              capabilityMode: String(data.capabilityMode || ''),
            })
            // 中间思考文本已实时写入回答缓冲，这里移除，避免污染最终回答。
            if (
              agentKind === 'mainagent' &&
              event.message &&
              this.responseText.endsWith(event.message)
            ) {
              this.responseText = this.responseText.slice(0, -event.message.length)
            }
          } else if (event.type === 'tool_call') {
            if (!viewingStream()) {
              continue
            }
            this.appendLiveStep({
              id: `call-${String(data.toolCallId || this.liveSteps.length)}`,
              type: 'tool_call',
              toolName: String(data.toolName || ''),
              toolCallId: String(data.toolCallId || ''),
              content: String(data.arguments || ''),
              agentId: String(data.agentId || 'mainagent'),
              agentName: String(data.agentName || 'Sophon'),
              agentKind: String(data.agentKind || 'mainagent'),
              parentAgentId: String(data.parentAgentId || ''),
              intentId: String(data.intentId || ''),
              hypothesisId: String(data.hypothesisId || ''),
              capabilityMode: String(data.capabilityMode || ''),
            })
          } else if (event.type === 'tool_result') {
            if (!viewingStream()) {
              continue
            }
            this.appendLiveStep({
              id: `result-${String(data.toolCallId || this.liveSteps.length)}`,
              type: 'tool_result',
              toolName: String(data.toolName || ''),
              toolCallId: String(data.toolCallId || ''),
              content: String(data.result || ''),
              agentId: String(data.agentId || 'mainagent'),
              agentName: String(data.agentName || 'Sophon'),
              agentKind: String(data.agentKind || 'mainagent'),
              parentAgentId: String(data.parentAgentId || ''),
              intentId: String(data.intentId || ''),
              hypothesisId: String(data.hypothesisId || ''),
              capabilityMode: String(data.capabilityMode || ''),
            })
          } else if (
            event.type === 'subagent.started' ||
            event.type === 'subagent.completed' ||
            event.type === 'subagent.failed'
          ) {
            if (!viewingStream()) {
              continue
            }
            const stepType =
              event.type === 'subagent.started'
                ? 'agent_started'
                : event.type === 'subagent.failed'
                  ? 'agent_failed'
                  : 'agent_completed'
            this.appendLiveStep({
              id: `${stepType}-${this.liveSteps.length}-${Date.now()}`,
              type: stepType,
              content: event.message,
              agentId: String(data.agentId || 'mainagent'),
              agentName: String(data.agentName || 'Sophon'),
              agentKind: String(data.agentKind || 'mainagent'),
              parentAgentId: String(data.parentAgentId || ''),
              intentId: String(data.intentId || ''),
              hypothesisId: String(data.hypothesisId || ''),
              capabilityMode: String(data.capabilityMode || ''),
              workerFocus: String(data.workerFocus || ''),
              allowedSkills: stringList(data.allowedSkills),
              task: String(data.task || ''),
              status: String(data.status || ''),
              durationMs: Number(data.durationMs || 0),
              resultSummary: String(data.result || ''),
              errorMessage: String(data.error || ''),
            })
          } else if (event.type === 'response') {
            if (viewingStream()) {
              this.responseText = event.message
            }
          } else if (event.type === 'error') {
            if (viewingStream()) {
              this.error = event.message
            }
          } else if (event.type === 'done') {
            this.streaming = false
            this.taskId = ''
            if (this.streamConversationId === streamConversationID) {
              this.streamConversationId = ''
            }
            this.setConversationStatus(streamConversationID, 'idle')
          } else if (event.type === 'hitl_request') {
            const requestID = String(data.requestId || '')
            if (requestID && !this.pendingHITL.some((item) => item.id === requestID)) {
              this.pendingHITL.push({
                id: requestID,
                conversationId: String(data.conversationId || this.currentConversationId),
                toolName: String(data.toolName || ''),
                arguments: (data.arguments as Record<string, unknown>) || {},
              })
              this.setConversationStatus(streamConversationID, 'waiting')
            }
          } else if (event.type === 'hitl_decision') {
            this.pendingHITL = this.pendingHITL.filter(
              (item) => item.id !== String(data.requestId || ''),
            )
            this.setConversationStatus(streamConversationID, 'running')
          }
        }
      } catch (error) {
        if (viewingStream()) {
          this.error = error instanceof Error ? error.message : '发送失败'
        }
      } finally {
        this.streaming = false
        if (this.streamConversationId === streamConversationID) {
          this.streamConversationId = ''
          this.taskId = ''
        }
        this.setConversationStatus(streamConversationID, 'idle')
        try {
          await this.refreshConversationStatuses()
        } catch {
          // 列表刷新失败不影响本次对话结果
        }
        if (this.currentConversationId === streamConversationID) {
          try {
            const messages = await this.loadLatestMessages()
            // 取消时后端可能仍在落盘：只有助手消息已有内容才清空流式缓冲。
            const lastAssistant = [...messages]
              .reverse()
              .find((item) => item.role === 'assistant')
            if (lastAssistant?.content.trim()) {
              this.responseText = ''
            }
          } catch {
            // 刷新失败时保留当前显示
          }
          await this.loadAttachments()
          await this.loadPendingHITL()
          await this.loadResumableRun(streamConversationID)
        }
      }
    },
    async sendMessage(message: string) {
      if (!message.trim() || this.streaming) {
        return
      }
      const current = this.conversations.find((item) => item.id === this.currentConversationId)
      if (!current?.projectId) {
        this.error = translate('chat.projectRequired')
        return
      }
      if (!this.projectAllowsWork(current.projectId)) {
        return
      }
      const optimistic: ChatMessage = {
        id: `local-${Date.now()}`,
        conversationId: this.currentConversationId,
        role: 'user',
        content: message.trim(),
        createdAt: new Date().toISOString(),
      }
      this.messages.push(optimistic)
      if (this.messages.length > MESSAGE_WINDOW_SIZE) {
        this.messages = this.messages.slice(-MESSAGE_WINDOW_SIZE)
        this.messagesHasMore = true
        this.messagesNextCursor = this.messages[0]?.id || this.messagesNextCursor
        this.pruneProcessDetailsToMessageWindow()
      }
      await this.runStream('/chat/stream', {
        conversationId: this.currentConversationId,
        projectId: this.selectedProjectId,
        ...this.roleRequestPayload(),
        ...this.agentModeRequestPayload(),
        message: message.trim(),
        attachmentIds: this.pendingAttachments.map((item) => item.id),
      })
      this.syncPendingAttachments()
    },
    async editAndResend(messageId: string, message: string) {
      if (!message.trim() || this.streaming) {
        return
      }
      const current = this.conversations.find((item) => item.id === this.currentConversationId)
      if (!current?.projectId || !this.projectAllowsWork(current.projectId)) {
        return
      }
      await this.runStream('/chat/stream', {
        conversationId: this.currentConversationId,
        projectId: this.selectedProjectId,
        ...this.roleRequestPayload(),
        ...this.agentModeRequestPayload(),
        message: message.trim(),
        editMessageId: messageId,
        attachmentIds: this.pendingAttachments.map((item) => item.id),
      })
      this.syncPendingAttachments()
    },
    async regenerateLast() {
      if (this.streaming || !this.currentConversationId) {
        return
      }
      const current = this.conversations.find((item) => item.id === this.currentConversationId)
      if (!current?.projectId || !this.projectAllowsWork(current.projectId)) {
        return
      }
      const lastAssistant = [...this.messages].reverse().find((item) => item.role === 'assistant')
      if (lastAssistant) {
        lastAssistant.content = ''
      }
      await this.runStream(`/conversations/${this.currentConversationId}/regenerate`, {})
    },
    async cancelTask() {
      if (!this.taskId) {
        return
      }
      try {
        await apiPost<void>(`/tasks/${this.taskId}/cancel`)
      } catch (error) {
        this.error = error instanceof Error ? error.message : '停止失败'
      }
    },
    async decideHITL(requestId: string, approved: boolean, comment = '') {
      await apiPost<void>(`/hitl/${requestId}/decision`, {
        approved,
        comment,
      })
      this.pendingHITL = this.pendingHITL.filter((item) => item.id !== requestId)
    },
    async deleteConversation(conversationId: string) {
      await apiDelete(`/conversations/${conversationId}`)
      if (this.currentConversationId === conversationId) {
        this.currentConversationId = ''
        this.messages = []
        this.processDetails = []
        this.hitlEnabled = false
        this.hitlOverridden = false
        this.messagesHasMore = false
        this.messagesNextCursor = ''
        this.messagesHasNewer = false
        this.messagesNextNewerCursor = ''
        this.messagesNeedsLatestRefresh = false
        this.attachments = []
        this.pendingAttachments = []
        this.responseText = ''
      }
      for (const [parentID, children] of Object.entries(this.conversationChildren)) {
        this.conversationChildren[parentID] = children.filter(
          (item) => item.id !== conversationId,
        )
      }
      await this.loadConversations()
    },
    async deleteConversations(ids: string[]) {
      if (!ids.length) {
        return { deleted: 0 }
      }
      const result = await apiPost<{ deleted: number }>('/conversations/batch-delete', {
        ids,
      })
      if (ids.includes(this.currentConversationId)) {
        this.currentConversationId = ''
        this.messages = []
        this.processDetails = []
        this.hitlEnabled = false
        this.hitlOverridden = false
        this.messagesHasMore = false
        this.messagesNextCursor = ''
        this.messagesHasNewer = false
        this.messagesNextNewerCursor = ''
        this.messagesNeedsLatestRefresh = false
        this.attachments = []
        this.pendingAttachments = []
        this.responseText = ''
      }
      const deleted = new Set(ids)
      for (const [parentID, children] of Object.entries(this.conversationChildren)) {
        this.conversationChildren[parentID] = children.filter(
          (item) => !deleted.has(item.id),
        )
      }
      await this.loadConversations()
      return result
    },
  },
})
