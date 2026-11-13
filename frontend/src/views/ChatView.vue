<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { apiUrl } from '../api/client'
import AgentRunSteps from '../components/AgentRunSteps.vue'
import MarkdownContent from '../components/MarkdownContent.vue'
import { useAuthStore } from '../stores/auth'
import {
  useChatStore,
  type AgentStep,
  type ChatMessage,
  type Conversation,
  type ProcessDetail,
} from '../stores/chat'
import { useI18n } from '../i18n'
import { copyText } from '../utils/clipboard'
import brandIcon from '../../img/icon.png'

const { t } = useI18n()
const chat = useChatStore()
const auth = useAuthStore()
const route = useRoute()
const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024 * 1024
const input = ref('')
const composerComposing = ref(false)
const selected = ref<string[]>([])
const notice = ref('')
const showInternalTools = ref(false)
const showRunSettings = ref(false)
const runSettingsRef = ref<HTMLElement | null>(null)
const expandedBatchIds = ref<string[]>([])
const editingMessageId = ref('')
const editingText = ref('')
const copyingMessageId = ref('')
const copyFailedMessageId = ref('')
let copyResetTimer: number | undefined
const messageListRef = ref<HTMLElement | null>(null)
const stickToBottom = ref(true)
const chatFullscreen = ref(false)
const conversationListCollapsed = ref(
  typeof window !== 'undefined' && window.matchMedia('(max-width: 760px)').matches,
)
const priorityGroupId = ref('')
const priorityBusinessSystem = ref('')
const priorityBusinessPriority = ref(50)
const activeQuestionId = ref('')
const userDisplayName = computed(
  () => auth.user?.displayName?.trim() || auth.user?.username || t('chat.roleUser'),
)
const userInitial = computed(() => userDisplayName.value.slice(0, 1).toUpperCase() || 'U')
const userAvatarSrc = computed(() => auth.user?.userAvatar?.trim() || '')
const assistantDisplayName = computed(
  () => auth.user?.assistantName?.trim() || t('app.title'),
)
const assistantAvatarSrc = computed(
  () => auth.user?.assistantAvatar?.trim() || brandIcon,
)
let refreshTimer: number | undefined
let refreshInFlight = false
let refreshConversationId = ''
let wasConversationRunning = false

const projectRequired = computed(() => !chat.selectedProjectId)
const selectedProject = computed(
  () => chat.projects.find((project) => project.id === chat.selectedProjectId),
)
const currentConversation = computed(() => {
  const direct = chat.conversations.find((item) => item.id === chat.currentConversationId)
  if (direct) {
    return direct
  }
  for (const children of Object.values(chat.conversationChildren)) {
    const child = children.find((item) => item.id === chat.currentConversationId)
    if (child) {
      return child
    }
  }
  return null
})
const batchParentSelected = computed(() => currentConversation.value?.kind === 'batch_parent')
const currentConversationRunning = computed(
  () => currentConversation.value?.status === 'running',
)
const currentStreaming = computed(
  () =>
    chat.streaming &&
    chat.streamConversationId !== '' &&
    chat.streamConversationId === chat.currentConversationId,
)
const currentPendingHITL = computed(() =>
  chat.pendingHITL.filter(
    (request) => request.conversationId === chat.currentConversationId,
  ),
)
const currentBatchCampaignId = computed(() =>
  batchParentSelected.value ? currentConversation.value?.batchId || '' : '',
)
const userQuestionRail = computed(() =>
  chat.messages
    .filter((message) => message.role === 'user')
    .map((message) => ({
      id: message.id,
      preview: compactQuestionPreview(message.content),
      time: formatTime(message.createdAt),
    })),
)
const projectInactive = computed(
  () => Boolean(chat.selectedProjectId) && selectedProject.value?.status !== 'active',
)
const projectBlocked = computed(() => projectRequired.value || projectInactive.value)
const composerBlocked = computed(() => projectBlocked.value || batchParentSelected.value)
const selectedProjectStatus = computed(() =>
  selectedProject.value ? t(`projectStatus.${selectedProject.value.status}`) : '',
)
const selectableConversations = computed(() =>
  chat.conversations.filter((conversation) => conversation.kind !== 'batch_parent'),
)
const conversationGroups = computed(() => {
  const queued: Conversation[] = []
  const running: Conversation[] = []
  const completed: Conversation[] = []
  for (const conversation of chat.conversations) {
    switch (conversation.status) {
      case 'queued':
        queued.push(conversation)
        break
      case 'running':
      case 'waiting':
        running.push(conversation)
        break
      default:
        completed.push(conversation)
    }
  }
  return [
    { key: 'queued', label: t('chat.statusQueued'), items: queued },
    { key: 'running', label: t('chat.statusRunning'), items: running },
    { key: 'completed', label: t('chat.statusCompleted'), items: completed },
  ]
})
const allSelected = computed(
  () =>
    selectableConversations.value.length > 0 &&
    selectableConversations.value.every((conversation) => selected.value.includes(conversation.id)),
)
const lastUserId = computed(
  () => [...chat.messages].reverse().find((item) => item.role === 'user')?.id ?? '',
)
const lastAssistantId = computed(
  () => [...chat.messages].reverse().find((item) => item.role === 'assistant')?.id ?? '',
)
function isMessageRunning(message: ChatMessage) {
  return (
    message.role === 'assistant' &&
    currentConversationRunning.value &&
    !currentStreaming.value &&
    message.id === lastAssistantId.value
  )
}

watch(
  () => chat.campaignGroups,
  (groups) => {
    const current = groups.find((group) => group.id === priorityGroupId.value)
    if (!current && groups.length) {
      selectPriorityGroup(groups[0].id)
    }
  },
)

function selectPriorityGroup(groupId: string) {
  const group = chat.campaignGroups.find((item) => item.id === groupId)
  priorityGroupId.value = groupId
  priorityBusinessSystem.value = group?.businessSystem || ''
  priorityBusinessPriority.value = group?.businessPriority || group?.priorityScore || 50
}

function onPriorityGroupChange(event: Event) {
  const target = event.target as HTMLSelectElement | null
  if (target?.value) {
    selectPriorityGroup(target.value)
  }
}

async function saveGroupPriority() {
  const campaignId = currentBatchCampaignId.value
  if (!campaignId || !priorityGroupId.value) {
    return
  }
  try {
    await chat.setCampaignGroupPriority(
      campaignId,
      priorityGroupId.value,
      priorityBusinessSystem.value.trim(),
      priorityBusinessPriority.value,
    )
  } catch (error) {
    chat.error = error instanceof Error ? error.message : '保存业务优先级失败'
  }
}

async function stopCampaign() {
  const campaignId = currentBatchCampaignId.value
  if (!campaignId || !window.confirm(t('chat.campaignStopConfirm'))) {
    return
  }
  try {
    await chat.stopCampaign(campaignId)
  } catch (error) {
    chat.error = error instanceof Error ? error.message : '停止战役失败'
  }
}

function roleLabel(role: string) {
  return role === 'user' ? userDisplayName.value : assistantDisplayName.value
}

function statusLabel(status?: string) {
  if (status === 'running') {
    return t('chat.statusRunning')
  }
  if (status === 'waiting') {
    return t('chat.statusWaiting')
  }
  if (status === 'queued') {
    return t('chat.statusQueued')
  }
  return ''
}

function compactQuestionPreview(content: string) {
  const text = content.replace(/\s+/g, ' ').trim()
  const runes = Array.from(text)
  return runes.length > 100 ? `${runes.slice(0, 100).join('')}…` : text
}

function updateActiveQuestionBar(list = messageListRef.value) {
  if (!list || !userQuestionRail.value.length) {
    activeQuestionId.value = ''
    return
  }
  const listRect = list.getBoundingClientRect()
  const threshold = listRect.top + Math.min(92, list.clientHeight * 0.25)
  const nodes = new Map(
    Array.from(list.querySelectorAll<HTMLElement>('[data-message-id]')).map((node) => [
      node.dataset.messageId || '',
      node,
    ]),
  )
  let active = userQuestionRail.value[0]?.id || ''
  for (const item of userQuestionRail.value) {
    const node = nodes.get(item.id)
    if (node && node.getBoundingClientRect().top <= threshold) {
      active = item.id
    }
  }
  activeQuestionId.value = active
}

function scrollToUserQuestion(messageId: string) {
  const list = messageListRef.value
  if (!list) {
    return
  }
  const target = Array.from(
    list.querySelectorAll<HTMLElement>('[data-message-id]'),
  ).find((node) => node.dataset.messageId === messageId)
  if (!target) {
    return
  }
  const listRect = list.getBoundingClientRect()
  const targetRect = target.getBoundingClientRect()
  const top = list.scrollTop + targetRect.top - listRect.top - 14
  stickToBottom.value = false
  activeQuestionId.value = messageId
  list.scrollTo({
    top: Math.max(0, top),
    behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches
      ? 'auto'
      : 'smooth',
  })
}

function projectStatusLabel(status: string) {
  return t(`projectStatus.${status}`)
}

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function toggleSelect(id: string) {
  if (selected.value.includes(id)) {
    selected.value = selected.value.filter((item) => item !== id)
    return
  }
  selected.value = [...selected.value, id]
}

function toggleAll() {
  if (allSelected.value) {
    selected.value = []
    return
  }
  selected.value = selectableConversations.value.map((item) => item.id)
}

async function createConversation() {
  notice.value = ''
  await chat.createConversation()
}

function isBatchExpanded(conversationId: string) {
  return expandedBatchIds.value.includes(conversationId)
}

function childConversations(conversationId: string) {
  return chat.conversationChildren[conversationId] ?? []
}

async function toggleBatchConversation(conversation: Conversation) {
  if (!conversation.id) {
    return
  }
  if (isBatchExpanded(conversation.id)) {
    expandedBatchIds.value = expandedBatchIds.value.filter((id) => id !== conversation.id)
    return
  }
  expandedBatchIds.value = [...expandedBatchIds.value, conversation.id]
  await chat.loadConversationChildren(conversation.id)
}

async function removeConversation(conversation: Conversation) {
  if (!window.confirm(t('chat.confirmDelete', { title: conversation.title }))) {
    return
  }
  notice.value = ''
  try {
    await chat.deleteConversation(conversation.id)
    selected.value = selected.value.filter((item) => item !== conversation.id)
  } catch (err) {
    chat.error = err instanceof Error ? err.message : '删除失败'
  }
}

async function removeSelected() {
  if (!selected.value.length) {
    return
  }
  if (!window.confirm(t('chat.confirmBatchDelete', { count: selected.value.length }))) {
    return
  }
  try {
    const result = await chat.deleteConversations([...selected.value])
    notice.value = t('chat.deletedCount', { count: result.deleted })
    selected.value = []
  } catch (err) {
    chat.error = err instanceof Error ? err.message : '批量删除失败'
  }
}

async function send() {
  const message = input.value
  if (!message.trim() || chat.uploading || chat.streaming || composerBlocked.value) {
    return
  }
  if (projectBlocked.value) {
    chat.error = projectInactive.value
      ? t('chat.projectInactive', { status: selectedProjectStatus.value })
      : t('chat.projectRequired')
    return
  }
  if (currentConversationRunning.value) {
    chat.error = t('chat.backgroundRunning')
    return
  }
  input.value = ''
  stickToBottom.value = true
  await chat.sendMessage(message)
}

function onComposerKeydown(event: KeyboardEvent) {
  if (
    event.key !== 'Enter' ||
    event.shiftKey ||
    event.altKey ||
    composerComposing.value ||
    event.isComposing ||
    event.keyCode === 229
  ) {
    return
  }
  event.preventDefault()
  void send()
}

function startEdit(message: ChatMessage) {
  editingMessageId.value = message.id
  editingText.value = message.content
}

function cancelEdit() {
  editingMessageId.value = ''
  editingText.value = ''
}

async function saveEdit(messageId: string) {
  const text = editingText.value.trim()
  if (!text || !window.confirm(t('chat.editConfirm'))) {
    return
  }
  cancelEdit()
  stickToBottom.value = true
  await chat.editAndResend(messageId, text)
}

async function copyMessage(message: ChatMessage) {
  const failed = () => {
    copyFailedMessageId.value = message.id
    window.setTimeout(() => {
      copyFailedMessageId.value = ''
    }, 2000)
  }
  try {
    const copied = await copyText(message.content)
    if (!copied) {
      failed()
      return
    }
    copyingMessageId.value = message.id
    if (copyResetTimer) {
      window.clearTimeout(copyResetTimer)
    }
    copyResetTimer = window.setTimeout(() => {
      copyingMessageId.value = ''
    }, 2000)
  } catch {
    failed()
  }
}

function copyTitle(message: ChatMessage) {
  if (copyingMessageId.value === message.id) {
    return t('common.copied')
  }
  if (copyFailedMessageId.value === message.id) {
    return t('common.copyFailed')
  }
  return t('common.copy')
}

function onHITLToggle(event: Event) {
  const enabled = (event.target as HTMLInputElement).checked
  void chat.setConversationHITL(enabled)
}

function onAutoContinueToggle(event: Event) {
  const enabled = (event.target as HTMLInputElement).checked
  void chat.setAutoContinue(enabled)
}

function onAssetRestrictionToggle(event: Event) {
  const enabled = (event.target as HTMLInputElement).checked
  void chat.setAssetRestriction(enabled)
}

function onZhiziToggle(event: Event) {
  const enabled = (event.target as HTMLInputElement).checked
  void chat.setZhiziEnabled(enabled)
}

function onAgentModeChange(event: Event) {
  const mode = (event.target as HTMLSelectElement).value
  if (mode === 'fast' || mode === 'deep') {
    chat.setAgentMode(mode)
  }
}

function onRoleChange(event: Event) {
  chat.selectRole((event.target as HTMLSelectElement).value)
}

async function stopCurrentTask() {
  if (currentStreaming.value) {
    await chat.cancelTask()
    return
  }
  if (!currentConversation.value?.id) {
    return
  }
  await chat.stopConversation(currentConversation.value.id)
  await chat.loadLatestMessages()
}

function toggleChatFullscreen() {
  showRunSettings.value = false
  chatFullscreen.value = !chatFullscreen.value
  void nextTick(scrollToBottom)
}

function toggleRunSettings() {
  showRunSettings.value = !showRunSettings.value
}

function onDocumentPointerDown(event: PointerEvent) {
  if (!showRunSettings.value) {
    return
  }
  const target = event.target
  if (target instanceof Node && runSettingsRef.value?.contains(target)) {
    return
  }
  showRunSettings.value = false
}

function toggleConversationList() {
  conversationListCollapsed.value = !conversationListCollapsed.value
  void nextTick(() => {
    updateActiveQuestionBar()
    if (stickToBottom.value) {
      scrollToBottom()
    }
  })
}

async function runCampaignAction(action: 'start' | 'pause' | 'resume') {
  const campaignId = currentBatchCampaignId.value
  if (!campaignId) {
    return
  }
  try {
    if (action === 'start') {
      await chat.startCampaign(campaignId)
    } else if (action === 'pause') {
      await chat.pauseCampaign(campaignId)
    } else {
      await chat.resumeCampaign(campaignId)
    }
  } catch (error) {
    chat.error = error instanceof Error ? error.message : '操作失败'
  }
}

async function recomputeCampaignPriorities() {
  const campaignId = currentBatchCampaignId.value
  if (!campaignId) {
    return
  }
  try {
    await chat.recomputeCampaignPriorities(campaignId)
  } catch (error) {
    chat.error = error instanceof Error ? error.message : '操作失败'
  }
}

function campaignKindLabel(kind: string) {
  const key = `chat.campaignKind.${kind}`
  const label = t(key)
  return label === key ? kind : label
}

function onGlobalKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape' && showRunSettings.value) {
    showRunSettings.value = false
    return
  }
  if (event.key === 'Escape' && chatFullscreen.value) {
    chatFullscreen.value = false
    void nextTick(scrollToBottom)
  }
}

async function regenerate() {
  if (!window.confirm(t('chat.regenerateConfirm'))) {
    return
  }
  stickToBottom.value = true
  await chat.regenerateLast()
}

async function onFilePicked(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  target.value = ''
  if (file) {
    if (file.size > MAX_ATTACHMENT_BYTES) {
      chat.error = t('chat.attachmentTooLarge', {
        size: formatSize(MAX_ATTACHMENT_BYTES),
      })
      return
    }
    await chat.uploadAttachment(file)
  }
}

function onAttachClick(event: MouseEvent) {
  if (chat.uploading || !chat.currentConversationId) {
    event.preventDefault()
    chat.error = t('chat.selectConversationFirst')
  }
}

function formatSize(size: number): string {
  if (size >= 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1)}MB`
  }
  if (size >= 1024) {
    return `${(size / 1024).toFixed(1)}KB`
  }
  return `${size}B`
}

function messageAttachments(messageId: string) {
  return chat.attachments.filter((item) => item.messageId === messageId)
}

const processDetailsByMessage = computed(() => {
  const groups = new Map<string, ProcessDetail[]>()
  for (const detail of chat.processDetails) {
    if (!detail.messageId) {
      continue
    }
    const items = groups.get(detail.messageId)
    if (items) {
      items.push(detail)
    } else {
      groups.set(detail.messageId, [detail])
    }
  }
  return groups
})

// 平台内部记账类工具（写事实/查漏洞等）默认不出现在执行时间线，
// 仍完整保留在右侧「过程详情」里；勾选「内部工具」可临时展开。
const INTERNAL_TOOL_PREFIXES = ['project_']
const INTERNAL_TOOLS = ['read_skill']

function isInternalTool(name: string) {
  const tool = name.trim()
  if (!tool) {
    return false
  }
  if (INTERNAL_TOOLS.includes(tool)) {
    return true
  }
  return INTERNAL_TOOL_PREFIXES.some((prefix) => tool.startsWith(prefix))
}

function visibleSteps(steps: AgentStep[]) {
  if (showInternalTools.value) {
    return steps
  }
  return steps.filter(
    (step) =>
      (step.type !== 'tool_call' && step.type !== 'tool_result') ||
      !isInternalTool(step.toolName || ''),
  )
}

function agentMeta(data: Record<string, unknown> = {}) {
  return {
    agentId: String(data.agentId || 'mainagent'),
    agentName: String(data.agentName || 'Sophon'),
    agentKind: String(data.agentKind || 'mainagent'),
    parentAgentId: String(data.parentAgentId || ''),
    intentId: String(data.intentId || ''),
    hypothesisId: String(data.hypothesisId || ''),
    workerFocus: String(data.workerFocus || ''),
    allowedSkills: Array.isArray(data.allowedSkills)
      ? data.allowedSkills.map((item) => String(item || '')).filter(Boolean)
      : [],
  }
}

function messageSteps(message: ChatMessage): AgentStep[] {
  const steps: AgentStep[] = []
  const details = processDetailsByMessage.value.get(message.id) || []
  const hasReasoningDetail = details.some((detail) => detail.eventType === 'reasoning')
  if (
    message.role === 'assistant' &&
    !hasReasoningDetail &&
    message.reasoningContent?.trim()
  ) {
    steps.push({
      id: `reasoning-${message.id}`,
      type: 'reasoning',
      ...agentMeta(),
      content:
        message.reasoningContent +
        (message.reasoningTruncated ? `\n\n${t('chat.reasoningTruncated')}` : ''),
    })
  }
  for (const detail of details) {
    const data = detail.data || {}
    if (detail.eventType === 'reasoning') {
      steps.push({
        id: detail.id,
        type: 'reasoning',
        ...agentMeta(data),
        content: String(data.reasoning || detail.message),
      })
    } else if (detail.eventType === 'thinking') {
      steps.push({
        id: detail.id,
        type: 'thinking',
        ...agentMeta(data),
        content: detail.message,
      })
    } else if (detail.eventType === 'tool_call') {
      steps.push({
        id: detail.id,
        type: 'tool_call',
        ...agentMeta(data),
        toolName: detail.message,
        toolCallId: String(data.toolCallId || ''),
        content: String(data.arguments || ''),
      })
    } else if (detail.eventType === 'tool_result') {
      steps.push({
        id: detail.id,
        type: 'tool_result',
        ...agentMeta(data),
        toolName: detail.message,
        toolCallId: String(data.toolCallId || ''),
        content: String(data.result || ''),
      })
    } else if (
      detail.eventType === 'subagent.started' ||
      detail.eventType === 'subagent.completed' ||
      detail.eventType === 'subagent.failed'
    ) {
      steps.push({
        id: detail.id,
        type:
          detail.eventType === 'subagent.started'
            ? 'agent_started'
            : detail.eventType === 'subagent.failed'
              ? 'agent_failed'
              : 'agent_completed',
        ...agentMeta(data),
        content: detail.message,
        task: String(data.task || ''),
        status: String(data.status || ''),
        durationMs: Number(data.durationMs || 0),
        resultSummary: String(data.result || ''),
        errorMessage: String(data.error || ''),
      })
    }
  }
  return visibleSteps(steps)
}

function scrollToBottom() {
  const list = messageListRef.value
  if (list) {
    list.scrollTop = list.scrollHeight
  }
}

async function jumpToBottom() {
  try {
    if (chat.messagesHasNewer || chat.messagesNeedsLatestRefresh) {
      await chat.loadLatestMessages()
    }
  } catch (err) {
    chat.error = err instanceof Error ? err.message : t('message.operationFailed')
  }
  await nextTick()
  stickToBottom.value = true
  scrollToBottom()
}

async function onMessageScroll() {
  const list = messageListRef.value
  if (!list) {
    return
  }
  updateActiveQuestionBar(list)
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80
  stickToBottom.value = nearBottom

  if (
    list.scrollTop <= 40 &&
    chat.messagesHasMore &&
    !chat.loadingOlderMessages
  ) {
    const previousHeight = list.scrollHeight
    const previousTop = list.scrollTop
    await chat.loadOlderMessages()
    await nextTick()
    const updated = messageListRef.value
    if (updated) {
      updated.scrollTop = updated.scrollHeight - previousHeight + previousTop
    }
    return
  }

  if (
    nearBottom &&
    (chat.messagesHasNewer || chat.messagesNeedsLatestRefresh) &&
    !chat.loadingNewerMessages
  ) {
    await loadNewerHistory()
  }
}

async function loadNewerHistory() {
  const list = messageListRef.value
  if (!list) {
    return
  }
  const wasAtBottom =
    list.scrollHeight - list.scrollTop - list.clientHeight < 80
  const previousHeight = list.scrollHeight
  const previousTop = list.scrollTop
  if (chat.messagesNeedsLatestRefresh) {
    await chat.loadLatestMessages()
  } else {
    await chat.loadNewerMessages()
  }
  await nextTick()
  const updated = messageListRef.value
  if (updated) {
    if (wasAtBottom) {
      updated.scrollTop = updated.scrollHeight
    } else {
      updated.scrollTop = updated.scrollHeight - previousHeight + previousTop
    }
  }
}

async function refreshChatPage() {
  if (document.visibilityState !== 'visible' || refreshInFlight) {
    return
  }
  refreshInFlight = true
  try {
    await chat.refreshConversationStatuses()
    if (currentBatchCampaignId.value) {
      await chat.loadCampaignOverview(currentBatchCampaignId.value)
    }
    if (!chat.currentConversationId || editingMessageId.value) {
      return
    }
    const conversationID = chat.currentConversationId
    if (refreshConversationId !== conversationID) {
      refreshConversationId = conversationID
      wasConversationRunning = currentConversationRunning.value
    }
    const isRunning = currentConversationRunning.value || currentStreaming.value
    const justFinished = wasConversationRunning && !isRunning
    wasConversationRunning = isRunning
    if (!isRunning && !justFinished) {
      return
    }
    const list = messageListRef.value
    const preserveScroll = !stickToBottom.value
    const previousHeight = list?.scrollHeight ?? 0
    const previousTop = list?.scrollTop ?? 0
    await Promise.all([
      preserveScroll ? Promise.resolve([]) : chat.loadLatestMessages(),
      chat.loadAttachments(),
      chat.loadPendingHITL(),
    ])
    if (preserveScroll && justFinished) {
      chat.messagesHasNewer = true
      chat.messagesNeedsLatestRefresh = true
    }
    if (isRunning && !preserveScroll) {
      const latestAssistant = [...chat.messages]
        .reverse()
        .find((item) => item.role === 'assistant')
      if (latestAssistant && (latestAssistant.processDetailCount ?? 0) > 0) {
        await chat.loadProcessDetailsForMessage(
          latestAssistant.id,
          true,
          latestAssistant.processDetailCount ?? 0,
        )
      }
    }
    await nextTick()
    if (preserveScroll && messageListRef.value) {
      messageListRef.value.scrollTop =
        messageListRef.value.scrollHeight - previousHeight + previousTop
    } else if (stickToBottom.value) {
      scrollToBottom()
    }
  } finally {
    refreshInFlight = false
  }
}

const liveSteps = computed<AgentStep[]>(() => {
  const steps = [...chat.liveSteps]
  if (chat.reasoningText.trim()) {
    steps.push({
      id: 'live-reasoning',
      type: 'reasoning',
      ...agentMeta(),
      content: chat.reasoningText,
    })
  }
  for (const step of Object.values(chat.liveReasoningByAgent)) {
    steps.push(step)
  }
  return visibleSteps(steps)
})

watch(
  () => chat.currentConversationId,
  async () => {
    cancelEdit()
    showRunSettings.value = false
    stickToBottom.value = true
    await nextTick()
    scrollToBottom()
    updateActiveQuestionBar()
  },
)

watch(
  () => userQuestionRail.value.map((item) => item.id).join('|'),
  async () => {
    await nextTick()
    updateActiveQuestionBar()
  },
)

watch(
  () => chat.messages.at(-1)?.id,
  async () => {
    await nextTick()
    if (stickToBottom.value) {
      scrollToBottom()
    }
  },
)

watch(
  () => chat.responseText,
  async () => {
    await nextTick()
    if (stickToBottom.value) {
      scrollToBottom()
    }
  },
)

watch(
  () => chat.selectedProjectId,
  (projectId) => {
    if (!projectId || chat.creatingConversation || chat.streaming) {
      return
    }
    const current = chat.conversations.find(
      (conversation) => conversation.id === chat.currentConversationId,
    )
    if (current?.projectId === projectId) {
      return
    }
    void chat.createConversation()
  },
)

onMounted(async () => {
  await chat.loadConversations()
  const conversationId = String(route.query.conversationId ?? '')
  if (conversationId && conversationId !== chat.currentConversationId) {
    await chat.selectConversation(conversationId)
  }
  refreshTimer = window.setInterval(() => {
    void refreshChatPage()
  }, 5000)
  window.addEventListener('keydown', onGlobalKeydown)
  document.addEventListener('pointerdown', onDocumentPointerDown)
})

onUnmounted(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
  if (copyResetTimer) {
    window.clearTimeout(copyResetTimer)
  }
  window.removeEventListener('keydown', onGlobalKeydown)
  document.removeEventListener('pointerdown', onDocumentPointerDown)
})
</script>

<template>
  <section
    class="chat-layout"
    :class="{
      'chat-layout-fullscreen': chatFullscreen,
      'chat-layout-conversation-collapsed': conversationListCollapsed,
    }"
  >
    <aside class="conversation-list">
      <div class="conversation-list-header">
        <div class="conversation-list-title">
          <div class="conversation-list-title-copy">
            <span>INPUT / HISTORY</span>
            <strong>{{ t('nav.chat') }}</strong>
          </div>
        </div>
        <div class="conversation-header-actions">
          <span class="conversation-count">{{ chat.conversations.length }}</span>
          <button
            class="button compact"
            type="button"
            :disabled="projectBlocked || chat.creatingConversation"
            @click="createConversation"
          >
            {{ t('chat.newConversation') }}
          </button>
        </div>
      </div>

      <label class="select-all">
        <input
          type="checkbox"
          :checked="allSelected"
          :disabled="!chat.conversations.length"
          @change="toggleAll"
        />
        <span>{{ t('common.selectAll') }}</span>
        <small v-if="selected.length">{{ t('common.selected', { count: selected.length }) }}</small>
      </label>

      <div class="conversation-items" @scroll.passive="hideConversationPreview(true)">
        <template v-if="chat.conversations.length">
          <section
            v-for="group in conversationGroups"
            :key="group.key"
            class="conversation-group"
            :class="group.key"
          >
            <header class="conversation-group-header">
              <span class="conversation-group-dot" aria-hidden="true"></span>
              <strong>{{ group.label }}</strong>
              <em>{{ group.items.length }}</em>
            </header>
            <div v-if="group.items.length" class="conversation-group-list">
              <div
                v-for="conversation in group.items"
                :key="conversation.id"
                class="conversation-row"
                :class="{ active: conversation.id === chat.currentConversationId }"
              >
                <button
                  v-if="conversation.kind === 'batch_parent'"
                  class="batch-toggle"
                  type="button"
                  :aria-label="t('chat.batchExpand')"
                  @click="toggleBatchConversation(conversation)"
                >
                  {{ isBatchExpanded(conversation.id) ? '−' : '+' }}
                </button>
                <input
                  v-if="conversation.kind !== 'batch_parent'"
                  type="checkbox"
                  :aria-label="conversation.title"
                  :checked="selected.includes(conversation.id)"
                  @change="toggleSelect(conversation.id)"
                />
                <button
                  class="conversation-item"
                  type="button"
                  @click="chat.selectConversation(conversation.id)"
                >
                  <span class="conversation-title">{{ conversation.title }}</span>
                  <span class="conversation-meta">
                    <span v-if="conversation.kind === 'batch_parent'" class="batch-count">
                      {{ t('chat.batchChildren', { count: conversation.childCount || 0 }) }}
                    </span>
                    <span
                      v-if="conversation.status && conversation.status !== 'idle'"
                      class="conversation-status"
                      :class="conversation.status"
                    >
                      <i></i>{{ statusLabel(conversation.status) }}
                    </span>
                    <span class="conversation-time">{{ formatTime(conversation.updatedAt) }}</span>
                  </span>
                </button>
                <button
                  class="row-delete"
                  type="button"
                  :title="t('common.delete')"
                  :aria-label="t('common.delete')"
                  @click="removeConversation(conversation)"
                >
                  ×
                </button>
                <div
                  v-if="conversation.kind === 'batch_parent' && isBatchExpanded(conversation.id)"
                  class="batch-children"
                >
                  <button
                    v-for="child in childConversations(conversation.id)"
                    :key="child.id"
                    class="batch-child-row"
                    :class="{ active: child.id === chat.currentConversationId }"
                    type="button"
                    @click="chat.selectConversation(child.id)"
                  >
                    <span>{{ child.title }}</span>
                    <small v-if="child.status && child.status !== 'idle'">
                      {{ statusLabel(child.status) }}
                    </small>
                  </button>
                  <p
                    v-if="chat.loadingConversationChildren[conversation.id]"
                    class="batch-child-loading"
                  >
                    {{ t('common.loading') }}
                  </p>
                </div>
              </div>
            </div>
            <p v-else class="conversation-group-empty">—</p>
          </section>
        </template>
        <p v-if="!chat.conversations.length" class="empty-hint">{{ t('chat.empty') }}</p>
        <button
          v-if="chat.conversationsHasMore"
          class="load-more-conversations"
          type="button"
          :disabled="chat.loadingOlderConversations"
          @click="chat.loadOlderConversations"
        >
          {{ chat.loadingOlderConversations ? t('common.loading') : t('common.loadMore') }}
        </button>
      </div>

      <div v-if="selected.length" class="bulk-bar">
        <span>{{ t('common.selected', { count: selected.length }) }}</span>
        <button class="button compact danger" type="button" @click="removeSelected">
          {{ t('common.batchDelete') }}
        </button>
      </div>
    </aside>

    <button
      class="conversation-toggle-rail"
      :class="{ collapsed: conversationListCollapsed }"
      type="button"
      :title="
        conversationListCollapsed
          ? t('chat.expandConversationList')
          : t('chat.collapseConversationList')
      "
      :aria-label="
        conversationListCollapsed
          ? t('chat.expandConversationList')
          : t('chat.collapseConversationList')
      "
      :aria-expanded="!conversationListCollapsed"
      @click="toggleConversationList"
    >
      <svg v-if="conversationListCollapsed" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M9 6l6 6-6 6" />
      </svg>
      <svg v-else viewBox="0 0 24 24" aria-hidden="true">
        <path d="M15 6l-6 6 6 6" />
      </svg>
    </button>

    <div class="chat-panel">
      <div v-if="chat.error" class="alert error">{{ chat.error }}</div>
      <div v-if="notice" class="alert ok">{{ notice }}</div>
      <div v-if="projectInactive" class="alert warn">
        {{ t('chat.projectInactiveHint', { status: selectedProjectStatus }) }}
      </div>

      <div v-if="currentPendingHITL.length" class="hitl-panel">
        <article v-for="request in currentPendingHITL" :key="request.id" class="hitl-request">
          <div>
            <strong>{{ t('chat.pendingApproval', { tool: request.toolName }) }}</strong>
            <pre>{{ JSON.stringify(request.arguments, null, 2) }}</pre>
          </div>
          <div class="hitl-actions">
            <button
              class="button"
              type="button"
              :disabled="projectBlocked"
              @click="chat.decideHITL(request.id, true, '已审批')"
            >
              {{ t('chat.approve') }}
            </button>
            <button
              class="button danger"
              type="button"
              :disabled="projectBlocked"
              @click="chat.decideHITL(request.id, false, '用户拒绝')"
            >
              {{ t('chat.reject') }}
            </button>
          </div>
        </article>
      </div>

      <div v-if="chat.currentResumableRun && !currentStreaming" class="resume-panel">
        <div>
          <strong>{{ t('chat.resumeTitle') }}</strong>
          <p>
            {{
              t('chat.resumeHint', {
                count: chat.currentResumableRun.segmentCount,
              })
            }}
          </p>
        </div>
        <button
          class="button compact"
          type="button"
          :disabled="projectBlocked || chat.resumableRunLoading"
          @click="chat.resumeConversation(chat.currentConversationId)"
        >
          {{ t('chat.resumeAction') }}
        </button>
      </div>

      <section
        v-if="batchParentSelected && chat.currentCampaignStatus"
        class="campaign-panel"
      >
        <header class="campaign-panel-head">
          <div>
            <strong>{{ t('chat.campaignTitle') }}</strong>
            <span class="campaign-status" :class="chat.currentCampaignStatus.status">
              {{ t(`chat.campaignStatus.${chat.currentCampaignStatus.status}`) }}
            </span>
          </div>
          <div class="campaign-actions">
            <button
              v-if="chat.currentCampaignStatus.status === 'draft' || chat.currentCampaignStatus.status === 'paused'"
              class="button compact"
              type="button"
              :disabled="chat.campaignLoading || projectBlocked"
              @click="runCampaignAction(chat.currentCampaignStatus.status === 'draft' ? 'start' : 'resume')"
            >
              {{ chat.currentCampaignStatus.status === 'draft' ? t('chat.campaignStart') : t('chat.campaignResume') }}
            </button>
            <button
              v-if="chat.currentCampaignStatus.status === 'running'"
              class="button compact danger"
              type="button"
              :disabled="chat.campaignLoading"
              @click="runCampaignAction('pause')"
            >
              {{ t('chat.campaignPause') }}
            </button>
            <button
              v-if="chat.currentCampaignStatus.campaignMode === 'continuous' && chat.currentCampaignStatus.status !== 'completed' && chat.currentCampaignStatus.status !== 'stopped'"
              class="button compact danger"
              type="button"
              :disabled="chat.campaignLoading"
              @click="stopCampaign"
            >
              {{ t('chat.campaignStop') }}
            </button>
          </div>
        </header>
        <div class="campaign-metrics">
          <span><strong>{{ chat.currentCampaignStatus.totalAssets }}</strong>{{ t('chat.campaignAssets') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.totalGroups }}</strong>{{ t('chat.campaignGroups') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.runningTasks }}</strong>{{ t('chat.campaignRunning') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.completedTasks }}</strong>{{ t('chat.campaignCompleted') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.failedTasks }}</strong>{{ t('chat.campaignFailed') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.pendingFrontier }}</strong>{{ t('chat.campaignPendingFrontier') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.pendingVerification }}</strong>{{ t('chat.campaignPendingVerification') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.linkCount }}</strong>{{ t('chat.campaignLinks') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.chainCount }}</strong>{{ t('chat.campaignChains') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.campaignRound }}/{{ chat.currentCampaignStatus.maxRounds }}</strong>{{ t('chat.campaignRound') }}</span>
          <span><strong>{{ chat.currentCampaignStatus.campaignToolCalls }}/{{ chat.currentCampaignStatus.campaignToolCallBudget }}</strong>{{ t('chat.campaignBudget') }}</span>
        </div>
        <div class="campaign-progress">
          <span
            :style="{
              width: `${chat.currentCampaignStatus.totalAssets
                ? Math.round(
                    (chat.currentCampaignStatus.completedTasks +
                      chat.currentCampaignStatus.failedTasks) /
                      chat.currentCampaignStatus.totalAssets *
                      100,
                  )
                : 0}%`,
            }"
          ></span>
        </div>
        <div v-if="chat.campaignGroups.length" class="campaign-group-list">
          <article
            v-for="group in chat.campaignGroups.slice(0, 8)"
            :key="group.id"
            class="campaign-group-row"
          >
            <span :title="group.label">{{ group.label }}</span>
            <small>{{ group.completedAssets }}/{{ group.totalAssets }}</small>
            <em v-if="group.failedAssets">{{ group.failedAssets }} failed</em>
          </article>
        </div>
        <div class="campaign-p1-grid">
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignFrontier') }}</span>
              <button
                class="button compact"
                type="button"
                :disabled="chat.campaignLoading"
                @click="recomputeCampaignPriorities"
              >
                {{ t('chat.campaignRecompute') }}
              </button>
            </header>
            <p v-if="!chat.campaignFrontier.length">{{ t('chat.campaignEmpty') }}</p>
            <article
              v-for="item in chat.campaignFrontier.slice(0, 6)"
              :key="item.id"
            >
              <span class="campaign-priority">{{ item.roi }}</span>
              <div>
                <strong>{{ campaignKindLabel(item.kind) }}</strong>
                <small :title="item.reason">
                  {{ item.reason }} · V{{ item.expectedValue }}/C{{ item.estimatedCost }}
                </small>
              </div>
              <em :class="item.status">{{ item.status }}</em>
            </article>
          </section>
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignVerifications') }}</span>
            </header>
            <p v-if="!chat.campaignVerifications.length">{{ t('chat.campaignEmpty') }}</p>
            <article
              v-for="item in chat.campaignVerifications.slice(0, 6)"
              :key="item.id"
            >
              <span class="campaign-priority">{{ item.attempts }}/{{ item.maxAttempts }}</span>
              <div>
                <strong>{{ item.findingId.slice(0, 10) }}</strong>
                <small :title="item.result">{{ item.result || item.findingId }}</small>
              </div>
              <em :class="item.status">{{ item.status }}</em>
            </article>
          </section>
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignCrossLinks') }}</span>
            </header>
            <p v-if="!chat.campaignLinks.length">{{ t('chat.campaignEmpty') }}</p>
            <article
              v-for="item in chat.campaignLinks.slice(0, 6)"
              :key="item.id"
            >
              <span class="campaign-priority">{{ item.confidence }}</span>
              <div>
                <strong>{{ campaignKindLabel(item.kind) }}</strong>
                <small :title="`${item.srcAssetId} -> ${item.dstAssetId}`">
                  {{ item.srcAssetId.slice(0, 8) }} → {{ item.dstAssetId.slice(0, 8) }}
                </small>
              </div>
              <em>{{ item.summary }}</em>
            </article>
          </section>
        </div>
        <div class="campaign-p1-grid">
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignBusinessPriority') }}</span>
            </header>
            <form class="campaign-priority-form" @submit.prevent="saveGroupPriority">
              <select
                :value="priorityGroupId"
                :aria-label="t('chat.campaignGroups')"
                @change="onPriorityGroupChange"
              >
                <option
                  v-for="group in chat.campaignGroups"
                  :key="group.id"
                  :value="group.id"
                >
                  {{ group.label }}
                </option>
              </select>
              <input
                v-model="priorityBusinessSystem"
                maxlength="80"
                :aria-label="t('chat.campaignBusinessSystem')"
                :placeholder="t('chat.campaignBusinessSystem')"
              />
              <input
                v-model.number="priorityBusinessPriority"
                type="number"
                min="1"
                max="100"
                :aria-label="t('chat.campaignBusinessPriorityValue')"
              />
              <button class="button compact" type="submit">
                {{ t('common.save') }}
              </button>
            </form>
            <p v-if="chat.campaignGroups.length">
              {{ t('chat.campaignPriorityScore') }}:
              {{ chat.campaignGroups.find((group) => group.id === priorityGroupId)?.priorityScore ?? 0 }}
            </p>
          </section>
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignAttackChains') }}</span>
            </header>
            <p v-if="!chat.campaignChains.length">{{ t('chat.campaignEmpty') }}</p>
            <article
              v-for="chain in chat.campaignChains.slice(0, 6)"
              :key="chain.id"
            >
              <span class="campaign-priority">{{ chain.priority }}</span>
              <div>
                <strong :title="chain.title">{{ chain.title }}</strong>
                <small>
                  {{ chain.entryAssetId.slice(0, 8) }} → {{ chain.targetAssetId.slice(0, 8) }}
                  · {{ chain.steps.length }} steps
                </small>
              </div>
              <em :class="chain.status">{{ chain.status }}</em>
            </article>
          </section>
          <section class="campaign-p1-card">
            <header>
              <span>{{ t('chat.campaignLongTermMemory') }}</span>
            </header>
            <p v-if="!chat.campaignMemory.length">{{ t('chat.campaignEmpty') }}</p>
            <article
              v-for="memory in chat.campaignMemory.slice(0, 6)"
              :key="memory.id"
            >
              <span class="campaign-priority">{{ memory.tier === 'hot' ? 'H' : 'C' }}</span>
              <div>
                <strong>{{ memory.kind }}</strong>
                <small :title="memory.summary">{{ memory.summary }}</small>
              </div>
              <em>{{ memory.sourceCount }}</em>
            </article>
          </section>
        </div>
      </section>

      <div class="message-list-shell">
        <div ref="messageListRef" class="message-list" @scroll.passive="onMessageScroll">
          <p v-if="chat.loadingOlderMessages" class="message-history-loading">
            {{ t('common.loading') }}
          </p>
        <p v-if="!chat.messages.length && !chat.responseText" class="message-empty">
          {{ t('chat.emptyMessages') }}
        </p>
        <article
          v-for="message in chat.messages"
          :key="message.id"
          :data-message-id="message.id"
          class="message"
          :class="message.role"
        >
          <div class="message-head">
            <span v-if="message.role === 'user'" class="message-avatar user-avatar">
              <img v-if="userAvatarSrc" :src="userAvatarSrc" alt="" aria-hidden="true" />
              <template v-else>{{ userInitial }}</template>
            </span>
            <span v-else class="message-avatar assistant-avatar">
              <img :src="assistantAvatarSrc" alt="" aria-hidden="true" />
            </span>
            <span class="message-role">{{ roleLabel(message.role) }}</span>
            <span class="message-time">{{ formatTime(message.createdAt) }}</span>
          </div>
          <div class="message-body">
            <template v-if="editingMessageId === message.id">
              <textarea
                v-model="editingText"
                rows="3"
                maxlength="65536"
                :aria-label="t('chat.editMessage')"
              ></textarea>
              <div class="message-actions">
                <button class="button compact" type="button" @click="saveEdit(message.id)">
                  {{ t('common.save') }}
                </button>
                <button class="button compact" type="button" @click="cancelEdit">
                  {{ t('common.cancel') }}
                </button>
              </div>
            </template>
            <template v-else>
              <div
                v-if="isMessageRunning(message)"
                class="message-running-state"
                role="status"
              >
                <span class="message-running-pulse" aria-hidden="true"></span>
                <span>{{ t('chat.intermediateResult') }}</span>
              </div>
              <AgentRunSteps
                v-if="message.role === 'assistant'"
                :steps="messageSteps(message)"
                :live="isMessageRunning(message)"
                :total-count="message.processDetailCount || 0"
                :loaded="chat.processDetailMeta[message.id]?.loaded || false"
                :loading="chat.processDetailMeta[message.id]?.loading || false"
                :has-more="chat.processDetailMeta[message.id]?.hasMore || false"
                :agent-summary="chat.processDetailMeta[message.id]?.agentSummary"
                @load-more="chat.loadProcessDetailsForMessage(message.id)"
              />
              <MarkdownContent
                v-if="message.role === 'assistant'"
                :content="message.content"
              />
              <p v-else>{{ message.content }}</p>
              <div v-if="messageAttachments(message.id).length" class="message-attachments">
                <a
                  v-for="item in messageAttachments(message.id)"
                  :key="item.id"
                  class="attachment-chip"
                  :href="apiUrl(`/attachments/${item.id}/content`)"
                >
                  {{ item.fileName }} · {{ formatSize(item.sizeBytes) }}
                </a>
              </div>
              <div v-if="!currentStreaming && !isMessageRunning(message)" class="message-actions">
                <button
                  v-if="message.id === lastUserId"
                  class="message-icon-button"
                  type="button"
                  :disabled="projectBlocked"
                  :title="t('common.edit')"
                  :aria-label="t('common.edit')"
                  @click="startEdit(message)"
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3z" />
                    <path d="M14.5 6.5l3 3" />
                  </svg>
                </button>
                <button
                  v-if="message.id === lastAssistantId"
                  class="message-icon-button"
                  type="button"
                  :disabled="projectBlocked"
                  :title="t('chat.regenerate')"
                  :aria-label="t('chat.regenerate')"
                  @click="regenerate"
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M20 11a8 8 0 0 0-14.5-4.5L4 8" />
                    <path d="M4 4v4h4" />
                    <path d="M4 13a8 8 0 0 0 14.5 4.5L20 16" />
                    <path d="M20 20v-4h-4" />
                  </svg>
                </button>
                <button
                  class="message-icon-button"
                  :class="{ copied: copyingMessageId === message.id, failed: copyFailedMessageId === message.id }"
                  type="button"
                  :title="copyTitle(message)"
                  :aria-label="copyTitle(message)"
                  @click="copyMessage(message)"
                >
                  <svg v-if="copyingMessageId === message.id" viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M5 13l4 4L19 7" />
                  </svg>
                  <svg v-else viewBox="0 0 24 24" aria-hidden="true">
                    <rect x="9" y="9" width="11" height="11" rx="2" />
                    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
                  </svg>
                </button>
              </div>
            </template>
          </div>
        </article>

        <button
          v-if="chat.messagesHasNewer"
          class="button compact message-history-more"
          type="button"
          :disabled="chat.loadingNewerMessages"
          @click="loadNewerHistory"
        >
          {{ chat.loadingNewerMessages ? t('common.loading') : t('chat.loadNewerMessages') }}
        </button>

        <article
          v-if="currentStreaming && (chat.responseText || liveSteps.length)"
          class="message assistant streaming"
        >
          <div class="message-head">
            <span class="message-avatar assistant-avatar">
              <img :src="assistantAvatarSrc" alt="" aria-hidden="true" />
            </span>
            <span class="message-role">{{ assistantDisplayName }}</span>
            <span class="message-time">{{ t('chat.generating') }}</span>
          </div>
          <AgentRunSteps :steps="liveSteps" live />
          <p v-if="chat.responseText">
            {{ chat.responseText }}<span class="streaming-cursor"></span>
          </p>
          </article>
        </div>
        <nav
          v-if="userQuestionRail.length"
          class="message-question-rail"
          :aria-label="t('chat.questionNavigation')"
        >
          <button
            v-for="(item, index) in userQuestionRail"
            :key="item.id"
            class="message-question-button"
            :class="{ active: activeQuestionId === item.id }"
            type="button"
            :aria-label="`${index + 1}. ${item.preview} ${item.time}`"
            @click="scrollToUserQuestion(item.id)"
          >
            <span class="message-question-bar" aria-hidden="true"></span>
            <span class="message-question-tooltip" aria-hidden="true">
              <span class="message-question-index">{{ index + 1 }}</span>
              <span class="message-question-copy">{{ item.preview || t('chat.previewEmpty') }}</span>
              <small>{{ item.time }}</small>
            </span>
          </button>
        </nav>
        <button
          v-if="!stickToBottom && (chat.messages.length || chat.responseText)"
          class="scroll-to-bottom-button"
          type="button"
          :title="t('chat.scrollToBottom')"
          :aria-label="t('chat.scrollToBottom')"
          @click="void jumpToBottom()"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 5v14" />
            <path d="m6 13 6 6 6-6" />
          </svg>
        </button>
      </div>

      <div class="chat-composer">
        <div class="command-bus-head">
          <span>COMMAND BUS</span>
          <span>03 / INPUT</span>
        </div>
        <div class="chat-composer-context">
          <div class="chat-context-group">
            <label class="composer-selector" :title="t('chat.agentModeHint')">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" />
              </svg>
              <span>{{ t('chat.agentMode') }}</span>
              <select
                :value="chat.agentMode"
                :aria-label="t('chat.agentMode')"
                :disabled="chat.creatingConversation || chat.streaming"
                @change="onAgentModeChange"
              >
                <option value="fast">{{ t('chat.fastPath') }}</option>
                <option value="deep">{{ t('chat.deepPath') }}</option>
              </select>
              <svg class="composer-selector-arrow" viewBox="0 0 24 24" aria-hidden="true">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </label>

            <label class="composer-selector">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z" />
                <path d="M4 20c0-3.5 3.6-6 8-6s8 2.5 8 6" />
              </svg>
              <span>{{ t('chat.role') }}</span>
              <select
                :value="chat.selectedRoleId"
                :aria-label="t('chat.role')"
                :disabled="
                  !chat.rolesLoaded ||
                  chat.creatingConversation ||
                  chat.streaming
                "
                @change="onRoleChange"
              >
                <option value="">{{ t('chat.noRole') }}</option>
                <option v-for="role in chat.roles" :key="role.id" :value="role.id">
                  {{ role.name }}
                </option>
              </select>
              <svg class="composer-selector-arrow" viewBox="0 0 24 24" aria-hidden="true">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </label>

            <label class="composer-selector">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M3.5 6.5A2.5 2.5 0 0 1 6 4h4l2 2h6a2.5 2.5 0 0 1 2.5 2.5v8A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5v-10Z" />
              </svg>
              <span>{{ t('chat.project') }}</span>
              <select
                v-model="chat.selectedProjectId"
                :aria-label="t('chat.project')"
                :disabled="chat.creatingConversation || chat.streaming"
              >
                <option value="">{{ t('chat.noProject') }}</option>
                <option
                  v-for="project in chat.projects"
                  :key="project.id"
                  :value="project.id"
                  :disabled="project.status !== 'active'"
                >
                  {{ project.name }} · {{ projectStatusLabel(project.status) }}
                </option>
              </select>
              <svg class="composer-selector-arrow" viewBox="0 0 24 24" aria-hidden="true">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </label>

            <div ref="runSettingsRef" class="chat-context-actions">
              <div class="run-settings-wrap">
                <button
                  class="composer-icon-button run-settings-toggle"
                  :class="{ active: showRunSettings }"
                  type="button"
                  :title="t('chat.runSettings')"
                  :aria-label="t('chat.runSettings')"
                  :aria-expanded="showRunSettings"
                  aria-controls="chat-run-settings"
                  @click="toggleRunSettings"
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M4 7h10" />
                    <path d="M18 7h2" />
                    <path d="M4 12h4" />
                    <path d="M12 12h8" />
                    <path d="M4 17h8" />
                    <path d="M16 17h4" />
                    <circle cx="16" cy="7" r="2" />
                    <circle cx="10" cy="12" r="2" />
                    <circle cx="14" cy="17" r="2" />
                  </svg>
                </button>
                <div
                  v-if="showRunSettings"
                  id="chat-run-settings"
                  class="run-settings-popover"
                  role="dialog"
                  :aria-label="t('chat.runSettings')"
                >
                  <header>
                    <strong>{{ t('chat.runSettings') }}</strong>
                  </header>
                  <label
                    class="composer-toggle run-setting"
                    :class="{
                      active: chat.hitlEnabled,
                      disabled:
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.creatingConversation ||
                        chat.hitlLoading ||
                        chat.hitlUpdating,
                    }"
                    :title="t('chat.manualApprovalHint')"
                  >
                    <input
                      type="checkbox"
                      :checked="chat.hitlEnabled"
                      :disabled="
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.creatingConversation ||
                        chat.hitlLoading ||
                        chat.hitlUpdating
                      "
                      @change="onHITLToggle"
                    />
                    <span class="composer-toggle-track" aria-hidden="true">
                      <span class="composer-toggle-knob"></span>
                    </span>
                    <span>{{ t('chat.manualApproval') }}</span>
                  </label>
                  <label
                    class="composer-toggle run-setting"
                    :class="{
                      active: chat.assetRestrictionEnabled,
                      disabled:
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.streaming ||
                        chat.creatingConversation ||
                        chat.assetRestrictionLoading ||
                        chat.assetRestrictionUpdating,
                    }"
                    :title="t('chat.assetRestrictionHint')"
                  >
                    <input
                      type="checkbox"
                      :checked="chat.assetRestrictionEnabled"
                      :disabled="
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.streaming ||
                        chat.creatingConversation ||
                        chat.assetRestrictionLoading ||
                        chat.assetRestrictionUpdating
                      "
                      @change="onAssetRestrictionToggle"
                    />
                    <span class="composer-toggle-track" aria-hidden="true">
                      <span class="composer-toggle-knob"></span>
                    </span>
                    <span>{{ t('chat.assetRestriction') }}</span>
                  </label>
                  <label
                    class="composer-toggle run-setting"
                    :class="{
                      active: chat.autoContinue,
                      disabled:
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.creatingConversation ||
                        chat.autoContinueLoading ||
                        chat.autoContinueUpdating,
                    }"
                    :title="t('chat.autoContinueHint')"
                  >
                    <input
                      type="checkbox"
                      :checked="chat.autoContinue"
                      :disabled="
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.creatingConversation ||
                        chat.autoContinueLoading ||
                        chat.autoContinueUpdating
                      "
                      @change="onAutoContinueToggle"
                    />
                    <span class="composer-toggle-track" aria-hidden="true">
                      <span class="composer-toggle-knob"></span>
                    </span>
                    <span>
                      {{ chat.autoContinue ? t('chat.autoContinue') : t('chat.pauseOnQuestion') }}
                    </span>
                  </label>
                  <label
                    class="composer-toggle run-setting"
                    :class="{
                      active: chat.zhiziEnabled,
                      disabled:
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.streaming ||
                        chat.zhiziLoading ||
                        chat.zhiziUpdating ||
                        (!chat.zhiziEnabled && chat.zhiziAvailability.available <= 0),
                    }"
                    :title="
                      chat.zhiziLeaseNodeName
                        ? t('chat.zhiziBound', { name: chat.zhiziLeaseNodeName })
                        : t('chat.zhiziAvailable', {
                            available: chat.zhiziAvailability.available,
                            total: chat.zhiziAvailability.totalSlots,
                          })
                    "
                  >
                    <input
                      type="checkbox"
                      :checked="chat.zhiziEnabled"
                      :disabled="
                        !chat.currentConversationId ||
                        projectBlocked ||
                        chat.streaming ||
                        chat.zhiziLoading ||
                        chat.zhiziUpdating ||
                        (!chat.zhiziEnabled && chat.zhiziAvailability.available <= 0)
                      "
                      @change="onZhiziToggle"
                    />
                    <span class="composer-toggle-track" aria-hidden="true">
                      <span class="composer-toggle-knob"></span>
                    </span>
                    <span>{{ t('chat.zhizi') }}</span>
                  </label>
                  <label class="composer-toggle run-setting" :class="{ active: showInternalTools }">
                    <input v-model="showInternalTools" type="checkbox" />
                    <span class="composer-toggle-track" aria-hidden="true">
                      <span class="composer-toggle-knob"></span>
                    </span>
                    <span>{{ t('chat.showInternalTools') }}</span>
                  </label>
                </div>
              </div>
              <button
                class="composer-icon-button fullscreen-toggle"
                type="button"
                :class="{ active: chatFullscreen }"
                :title="chatFullscreen ? t('chat.exitFullscreen') : t('chat.enterFullscreen')"
                :aria-label="chatFullscreen ? t('chat.exitFullscreen') : t('chat.enterFullscreen')"
                @click="toggleChatFullscreen"
              >
                <svg v-if="chatFullscreen" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M9 4v5H4" />
                  <path d="M15 4v5h5" />
                  <path d="M9 20v-5H4" />
                  <path d="M15 20v-5h5" />
                </svg>
                <svg v-else viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M9 4H4v5" />
                  <path d="M15 4h5v5" />
                  <path d="M9 20H4v-5" />
                  <path d="M15 20h5v-5" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div v-if="chat.pendingAttachments.length" class="chat-attachment-bar">
          <span v-for="item in chat.pendingAttachments" :key="item.id" class="attachment-chip">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="m21.4 11.1-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 1 1 5.7 5.7l-9.2 9.2a2 2 0 1 1-2.8-2.8l8.5-8.5" />
            </svg>
            <span class="attachment-name">{{ item.fileName }}</span>
            <small>{{ formatSize(item.sizeBytes) }}</small>
            <button
              type="button"
              :aria-label="t('common.delete')"
              @click="chat.removePendingAttachment(item.id)"
            >
              ×
            </button>
          </span>
        </div>

        <form class="chat-input" @submit.prevent="send">
          <textarea
            v-model="input"
            rows="5"
            maxlength="65536"
            :aria-label="t('chat.placeholder')"
            :placeholder="
              currentConversationRunning
                ? t('chat.backgroundRunning')
                : projectInactive
                ? t('chat.projectInactiveHint', { status: selectedProjectStatus })
                : projectRequired
                  ? t('chat.projectRequiredHint')
                  : batchParentSelected
                    ? t('chat.batchParentHint')
                    : t('chat.placeholder')
            "
            :disabled="composerBlocked || currentConversationRunning"
            @compositionstart="composerComposing = true"
            @compositionend="composerComposing = false"
            @keydown="onComposerKeydown"
          ></textarea>

          <div class="chat-input-footer">
            <label
              class="composer-icon-button attach-button"
              :class="{ disabled: composerBlocked || currentConversationRunning || chat.uploading || !chat.currentConversationId }"
              :title="chat.uploading ? t('chat.uploading') : t('chat.attach')"
              :aria-label="chat.uploading ? t('chat.uploading') : t('chat.attach')"
              @click="onAttachClick"
            >
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="m21.4 11.1-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 1 1 5.7 5.7l-9.2 9.2a2 2 0 1 1-2.8-2.8l8.5-8.5" />
              </svg>
              <input
                class="file-input"
                type="file"
                :disabled="composerBlocked || currentConversationRunning || chat.uploading || !chat.currentConversationId"
                @change="onFilePicked"
              />
            </label>

            <div class="chat-input-actions">
              <button
                v-if="currentStreaming || currentConversationRunning"
                class="composer-icon-button danger"
                type="button"
                :title="t('chat.stop')"
                :aria-label="t('chat.stop')"
                @click="stopCurrentTask"
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <rect x="7" y="7" width="10" height="10" rx="1.5" />
                </svg>
              </button>
              <button
                v-else
                class="composer-icon-button send"
                type="submit"
                :disabled="
                  chat.uploading ||
                  chat.streaming ||
                  !input.trim() ||
                  composerBlocked ||
                  currentConversationRunning
                "
                :title="t('chat.send')"
                :aria-label="t('chat.send')"
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 19V5" />
                  <path d="m5 12 7-7 7 7" />
                </svg>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>

  </section>
</template>

<style scoped>
.conversation-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.chat-composer-context {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px 12px 8px;
  border-bottom: 1px solid var(--border);
}

.chat-context-group {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.chat-context-actions {
  position: relative;
  display: flex;
  flex: 0 0 auto;
  flex-wrap: nowrap;
  gap: 6px;
  align-items: center;
  justify-content: flex-end;
}

.composer-selector {
  position: relative;
  display: grid;
  grid-template-columns: auto auto minmax(0, 1fr);
  align-items: center;
  gap: 7px;
  min-width: 0;
  height: 34px;
  padding: 0 24px 0 9px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: var(--field-bg);
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.composer-selector:focus-within {
  border-color: var(--accent);
  box-shadow: none;
}

.composer-selector > svg:first-child {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 1.7;
}

.composer-selector > span {
  color: var(--text-muted);
  font-size: 11px;
  white-space: nowrap;
}

.composer-selector select {
  width: 118px;
  min-width: 0;
  height: 30px;
  padding: 0;
  overflow: hidden;
  border: 0;
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: transparent;
  box-shadow: none;
  font-size: 12px;
  font-weight: 600;
  text-overflow: ellipsis;
  appearance: none;
  cursor: pointer;
}

.composer-selector select:focus {
  border: 0;
  box-shadow: none;
}

.composer-selector-arrow {
  position: absolute;
  right: 8px;
  width: 12px;
  height: 12px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2;
  pointer-events: none;
}

.composer-toggle {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  height: 34px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: transparent;
  font-size: 12px;
  white-space: nowrap;
  cursor: pointer;
  transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
}

.composer-toggle:hover {
  border-color: var(--border-strong);
  color: var(--text-secondary);
  background: var(--field-bg);
}

.composer-toggle.disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.composer-toggle.active {
  border-color: var(--accent-line);
  color: var(--accent);
  background: var(--accent-soft);
}

.composer-toggle input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}

.composer-toggle-track {
  position: relative;
  width: 28px;
  height: 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--border-strong);
  transition: background 0.15s ease;
}

.composer-toggle-knob {
  position: absolute;
  top: 1px;
  left: 1px;
  width: 12px;
  height: 12px;
  border-radius: var(--radius);
  background: var(--text-muted);
  transition: transform 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
}

.composer-toggle.active .composer-toggle-track {
  background: var(--accent-soft);
}

.composer-toggle.active .composer-toggle-knob {
  background: var(--accent);
  box-shadow: none;
  transform: translateX(12px);
}

.run-settings-wrap {
  position: relative;
  display: flex;
}

.run-settings-toggle.active,
.fullscreen-toggle.active {
  border-color: var(--accent-line);
  color: var(--accent);
  background: var(--accent-soft);
}

.run-settings-popover {
  position: absolute;
  right: 0;
  bottom: calc(100% + 8px);
  z-index: 20;
  display: grid;
  width: min(300px, calc(100vw - 24px));
  gap: 7px;
  padding: 10px;
  border: 1px solid var(--border-strong);
  border-radius: 5px;
  background: var(--surface);
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.32);
}

.run-settings-popover header {
  display: flex;
  align-items: center;
  min-height: 24px;
  padding: 0 2px 6px;
  border-bottom: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 11px;
}

.run-settings-popover .run-setting {
  justify-content: flex-start;
  width: 100%;
  height: 34px;
}

.chat-attachment-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 8px 12px 0;
}

.attach-button {
  cursor: pointer;
}

.attach-button.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.file-input {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  opacity: 0;
}

.attachment-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  padding: 3px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--field-bg);
  font-size: 12px;
  text-decoration: none;
}

.attachment-chip svg {
  width: 12px;
  height: 12px;
  flex: 0 0 auto;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 1.8;
}

.attachment-name {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.attachment-chip small {
  color: var(--text-muted);
}

.attachment-chip button {
  padding: 0 2px;
  border: 0;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
}

.chat-input-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  min-height: 36px;
}

.chat-input-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.composer-icon-button {
  display: inline-grid;
  place-items: center;
  width: 36px;
  height: 36px;
  padding: 0;
  border: 1px solid transparent;
  border-radius: var(--radius);
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
  transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
}

.composer-icon-button:hover {
  border-color: var(--border);
  color: var(--text-primary);
  background: var(--field-bg);
}

.fullscreen-toggle.active {
  border-color: var(--accent-line);
  color: var(--accent);
  background: var(--accent-soft);
}

.composer-icon-button svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 1.9;
}

.composer-icon-button.send {
  border-color: var(--line);
  color: #ffffff;
  background: var(--accent-lime);
  box-shadow: none;
}

.composer-icon-button.send:hover {
  border-color: var(--line);
  color: #ffffff;
  background: var(--accent-lime);
  transform: translate(-1px, -1px);
  box-shadow: none;
  filter: none;
}

.composer-icon-button.send:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  box-shadow: none;
  filter: none;
}

.composer-icon-button.danger {
  border-color: rgba(251, 113, 133, 0.35);
  color: var(--danger);
  background: rgba(251, 113, 133, 0.1);
}

.composer-icon-button.danger:hover {
  border-color: var(--danger);
  color: var(--danger);
  background: rgba(251, 113, 133, 0.16);
}

.message-attachments {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 6px;
}

.message-history-loading {
  margin: 0;
  color: var(--text-muted);
  font-size: 12px;
  text-align: center;
}

.message-history-more {
  justify-self: center;
}

.message-running-state {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
  padding: 7px 10px;
  border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
  border-radius: var(--radius);
  color: var(--accent-strong);
  background: color-mix(in srgb, var(--accent) 9%, var(--surface-soft));
  font-size: 12px;
}

.message-running-pulse {
  width: 8px;
  height: 8px;
  flex: 0 0 auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--accent);
  box-shadow: 0 0 10px color-mix(in srgb, var(--accent) 75%, transparent);
  animation: message-running-pulse 1.6s ease-in-out infinite;
}

@keyframes message-running-pulse {
  0%,
  100% {
    opacity: 0.45;
    transform: scale(0.85);
  }

  50% {
    opacity: 1;
    transform: scale(1.15);
  }
}

.message-actions {
  display: flex;
  gap: 6px;
  align-items: center;
  margin-top: 6px;
}

.message-icon-button {
  display: inline-grid;
  place-items: center;
  width: 26px;
  height: 26px;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface-soft);
  cursor: pointer;
  transition: color 0.15s ease, border-color 0.15s ease, background 0.15s ease;
}

.message-icon-button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.message-icon-button:hover:not(:disabled) {
  color: var(--accent);
  border-color: var(--accent-line);
  background: var(--accent-soft);
}

.message-icon-button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.message-icon-button.copied {
  color: var(--success);
  border-color: var(--success);
  background: rgba(52, 211, 153, 0.12);
}

.message-icon-button.failed {
  color: var(--danger);
  border-color: var(--danger);
  background: color-mix(in srgb, var(--danger) 10%, var(--surface));
}

.message textarea {
  width: 100%;
  min-height: 180px;
}

.alert.ok {
  color: var(--success);
  background: rgba(52, 211, 153, 0.12);
}

.alert.warn {
  color: var(--warning);
  background: rgba(251, 191, 36, 0.12);
}

.resume-panel {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 14px;
  border: 1px solid var(--warning);
  border-radius: var(--radius);
  color: var(--text-primary);
  background: rgba(251, 191, 36, 0.1);
}

.resume-panel p {
  margin: 4px 0 0;
  color: var(--text-secondary);
  font-size: 12px;
}

.campaign-panel {
  display: grid;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--accent-line);
  border-radius: var(--radius);
  background: var(--surface);
}

.campaign-panel-head,
.campaign-panel-head > div,
.campaign-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.campaign-panel-head {
  justify-content: space-between;
}

.campaign-status {
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  font-size: 11px;
}

.campaign-status.running {
  border-color: var(--accent-line);
  color: var(--accent);
}

.campaign-status.completed {
  color: var(--success);
}

.campaign-status.failed {
  color: var(--danger);
}

.campaign-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(92px, 1fr));
  gap: 8px;
}

.campaign-metrics span {
  display: grid;
  gap: 2px;
  padding: 7px 9px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  font-size: 11px;
}

.campaign-metrics strong {
  color: var(--text-primary);
  font-size: 15px;
}

.campaign-progress {
  height: 5px;
  overflow: hidden;
  border-radius: var(--radius);
  background: var(--field-bg);
}

.campaign-progress span {
  display: block;
  height: 100%;
  border-radius: var(--radius);
  background: var(--accent);
  transition: width 0.25s ease;
}

.campaign-group-list {
  display: grid;
  gap: 4px;
}

.campaign-group-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  gap: 10px;
  align-items: center;
  padding: 6px 8px;
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--field-bg);
  font-size: 12px;
}

.campaign-group-row > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.campaign-group-row small,
.campaign-group-row em {
  color: var(--text-muted);
  font-style: normal;
}

.campaign-group-row em {
  color: var(--danger);
}

.campaign-p1-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px;
}

.campaign-p1-card {
  display: grid;
  gap: 5px;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.campaign-p1-card header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.campaign-p1-card p {
  margin: 2px 0;
  color: var(--text-muted);
  font-size: 11px;
}

.campaign-p1-card article {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 7px;
  align-items: center;
  min-width: 0;
  padding: 4px 5px;
  border-radius: var(--radius);
  background: var(--surface);
}

.campaign-p1-card article > div {
  display: grid;
  min-width: 0;
}

.campaign-p1-card strong,
.campaign-p1-card small,
.campaign-p1-card em {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.campaign-p1-card strong {
  color: var(--text-primary);
  font-size: 11px;
}

.campaign-p1-card small {
  color: var(--text-muted);
  font-size: 10px;
}

.campaign-p1-card em {
  max-width: 96px;
  color: var(--text-muted);
  font-size: 10px;
  font-style: normal;
}

.campaign-p1-card em.completed {
  color: var(--success);
}

.campaign-p1-card em.failed {
  color: var(--danger);
}

.campaign-p1-card em.running,
.campaign-p1-card em.pending {
  color: var(--accent);
}

.campaign-priority {
  min-width: 26px;
  padding: 1px 4px;
  border-radius: var(--radius);
  color: var(--accent);
  background: var(--accent-soft);
  font-size: 10px;
  text-align: center;
}

.conversation-list {
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto;
  gap: 10px;
  max-height: calc(100vh - 120px);
}

.select-all {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted);
  font-size: 12px;
}

.select-all small {
  margin-left: auto;
  color: var(--accent);
}

.conversation-items {
  display: grid;
  gap: 6px;
  align-content: start;
  overflow: auto;
}

.load-more-conversations {
  width: 100%;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface-soft);
  font-size: 12px;
  cursor: pointer;
}

.load-more-conversations:hover:not(:disabled) {
  border-color: var(--accent-line);
  color: var(--accent);
}

.conversation-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  padding: 4px 6px;
  border: 1px solid transparent;
  border-radius: var(--radius);
  background: var(--field-bg);
}

.conversation-row:hover {
  border-color: var(--border-strong);
}

.conversation-row.active {
  border-color: var(--accent-line);
  background: var(--accent-soft);
}

.conversation-row .conversation-item {
  margin: 0;
  border: 0;
  background: transparent;
  padding: 6px 2px;
}

.conversation-row.active .conversation-item {
  color: var(--accent);
  background: transparent;
}

.row-delete {
  padding: 2px 6px;
  border: 0;
  color: var(--text-muted);
  background: transparent;
  font-size: 15px;
  line-height: 1;
  cursor: pointer;
}

.row-delete:hover {
  color: var(--danger);
}

.batch-toggle {
  width: 22px;
  height: 22px;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--accent);
  background: var(--surface-soft);
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
}

.batch-count {
  color: var(--accent);
}

.batch-children {
  grid-column: 1 / -1;
  display: grid;
  gap: 4px;
  padding: 4px 0 6px 28px;
}

.batch-child-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  padding: 6px 8px;
  border: 1px solid transparent;
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface-soft);
  text-align: left;
  cursor: pointer;
}

.batch-child-row:hover,
.batch-child-row.active {
  border-color: var(--accent-line);
  color: var(--accent);
}

.batch-child-row small,
.batch-child-loading {
  color: var(--text-muted);
  font-size: 11px;
}

.batch-child-loading {
  margin: 0;
  padding: 4px 8px;
}

.campaign-priority-form {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1.2fr) 74px auto;
  gap: 6px;
  align-items: center;
}

.campaign-priority-form select,
.campaign-priority-form input {
  min-width: 0;
  padding: 5px 7px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-primary);
  background: var(--surface);
  font-size: 11px;
}

.empty-hint {
  margin: 0;
  padding: 16px 6px;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
}

.bulk-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface-soft);
  font-size: 12px;
}

@media (max-width: 760px) {
  .message {
    max-width: 100%;
  }

  .conversation-list {
    max-height: none;
  }

  .chat-composer-context {
    align-items: center;
    flex-direction: row;
    gap: 6px;
    padding: 8px 10px;
  }

  .chat-context-group {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    width: 100%;
    gap: 6px;
  }

  .chat-context-actions {
    grid-column: 1 / -1;
    width: 100%;
    justify-content: flex-end;
  }

  .composer-selector {
    width: 100%;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 4px;
    height: 32px;
    padding: 0 18px 0 7px;
  }

  .composer-selector > span {
    display: none;
  }

  .composer-selector select {
    width: 100%;
    font-size: 11px;
  }

  .composer-toggle {
    width: 100%;
  }

  .command-bus-head {
    display: none;
  }

  .run-settings-popover {
    width: min(320px, calc(100vw - 24px));
  }

  .attachment-name {
    max-width: 150px;
  }
}

/* Factory console skin */
.chat-layout {
  --chat-input: #f0a43a;
  --chat-work: #55c7e8;
  --chat-output: var(--success);
  --chat-panel: color-mix(in srgb, var(--surface) 94%, #0b0b10);
  --chat-line: color-mix(in srgb, var(--border-strong) 72%, transparent);
  position: relative;
  grid-template-columns: 270px minmax(0, 1fr);
  grid-template-rows: minmax(0, 1fr);
  gap: 10px;
}

.chat-command-header {
  position: relative;
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: minmax(220px, 1fr) auto minmax(220px, auto);
  align-items: center;
  gap: 20px;
  min-height: 78px;
  padding: 13px 16px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 7px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--chat-input) 7%, transparent), transparent 28%),
    var(--chat-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--text-primary) 5%, transparent),
    0 7px 20px rgba(0, 0, 0, 0.16);
}

.chat-command-header::before {
  position: absolute;
  top: 0;
  left: 0;
  width: 68px;
  height: 2px;
  content: '';
  background: var(--chat-input);
}

.chat-command-title {
  display: grid;
  gap: 4px;
}

.chat-command-title > span,
.conversation-list-title > span,
.command-bus-head {
  color: var(--chat-work);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.1em;
}

.chat-command-title > div {
  display: flex;
  align-items: baseline;
  gap: 10px;
}

.chat-command-title h1 {
  margin: 0;
  font-size: 24px;
  font-weight: 500;
  line-height: 1.1;
}

.chat-command-title small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.08em;
}

.chat-command-route {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.08em;
}

.chat-command-route span:nth-of-type(1) {
  color: var(--chat-input);
}

.chat-command-route span:nth-of-type(2) {
  color: var(--chat-work);
}

.chat-command-route span:nth-of-type(3) {
  color: var(--chat-output);
}

.chat-command-route i {
  position: relative;
  width: 26px;
  height: 1px;
  background: var(--chat-line);
}

.chat-command-route i::after {
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

.chat-command-status {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.chat-command-status > span,
.chat-live-status {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-height: 28px;
  padding: 4px 9px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 700;
  white-space: nowrap;
}

.chat-live-status {
  border-color: color-mix(in srgb, var(--chat-output) 35%, var(--border));
  color: var(--chat-output);
  background: color-mix(in srgb, var(--chat-output) 8%, transparent);
}

.chat-live-status i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: chat-live-pulse 1.6s ease-in-out infinite;
}

.conversation-list {
  padding: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 5px;
  background:
    repeating-linear-gradient(
      180deg,
      color-mix(in srgb, var(--chat-input) 4%, transparent) 0 1px,
      transparent 1px 9px
    ),
    var(--chat-panel);
}

.conversation-list::before {
  display: block;
  height: 2px;
  flex: 0 0 auto;
  content: '';
  background: var(--chat-input);
}

.conversation-list-header {
  display: grid;
  grid-template-columns: 1fr;
  gap: 9px;
  margin: 0;
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
}

.conversation-list-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.conversation-list-title > span {
  color: var(--chat-input);
  font-size: 7px;
}

.conversation-list-title strong {
  color: var(--text-primary);
  font-size: 14px;
}

.conversation-header-actions {
  justify-content: flex-start;
  gap: 6px;
}

.conversation-header-actions .button {
  min-width: 0;
  padding: 5px 8px;
  border-radius: 3px;
  font-size: 10px;
}

.conversation-count {
  margin-right: auto;
  border-radius: 3px;
  color: var(--chat-input);
  background: color-mix(in srgb, var(--chat-input) 7%, transparent);
  font-size: 9px;
}

.select-all {
  margin: 0;
  padding: 8px 12px;
  border-bottom: 1px solid color-mix(in srgb, var(--border) 75%, transparent);
  font-size: 10px;
}

.conversation-items {
  gap: 6px;
  padding: 8px;
}

.conversation-group {
  --conversation-group-tone: var(--text-muted);
  display: grid;
  gap: 5px;
}

.conversation-group + .conversation-group {
  padding-top: 5px;
  border-top: 1px solid color-mix(in srgb, var(--border) 55%, transparent);
}

.conversation-group.queued {
  --conversation-group-tone: var(--warning);
}

.conversation-group.running {
  --conversation-group-tone: var(--chat-work);
}

.conversation-group.completed {
  --conversation-group-tone: var(--text-muted);
}

.conversation-group-header {
  display: flex;
  gap: 6px;
  align-items: center;
  min-width: 0;
  padding: 1px 4px;
  color: var(--conversation-group-tone);
}

.conversation-group-header strong {
  overflow: hidden;
  font-size: 10px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.conversation-group-header em {
  min-width: 18px;
  margin-left: auto;
  padding: 0 5px;
  border: 1px solid color-mix(in srgb, var(--conversation-group-tone) 28%, var(--border));
  border-radius: 999px;
  background: color-mix(in srgb, var(--conversation-group-tone) 7%, transparent);
  font-family: var(--mono);
  font-size: 8px;
  font-style: normal;
  line-height: 1.6;
  text-align: center;
}

.conversation-group-dot {
  width: 6px;
  height: 6px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px color-mix(in srgb, currentColor 56%, transparent);
}

.conversation-group.running .conversation-group-dot {
  animation: chat-live-pulse 1.6s ease-in-out infinite;
}

.conversation-group-list {
  display: grid;
  gap: 6px;
  min-width: 0;
}

.conversation-group-empty {
  margin: 0;
  padding: 5px 4px 7px 16px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
  opacity: 0.55;
}

.conversation-row {
  gap: 6px;
  padding: 3px 5px;
  border-radius: 3px;
  background: color-mix(in srgb, var(--field-bg) 72%, transparent);
}

.conversation-row.active {
  border-color: color-mix(in srgb, var(--chat-work) 36%, var(--border));
  background: color-mix(in srgb, var(--chat-work) 8%, var(--field-bg));
  box-shadow: inset 3px 0 0 var(--chat-work);
}

.conversation-row .conversation-item {
  color: var(--text-secondary);
}

.conversation-row.active .conversation-item {
  color: var(--text-primary);
}

.conversation-title {
  font-size: 12px;
}

.conversation-meta {
  font-size: 9px;
}

.chat-panel {
  gap: 8px;
}

.message-list-shell {
  position: relative;
  display: flex;
  flex: 1 1 auto;
  min-width: 0;
  min-height: 0;
}

.message-list-shell .message-list {
  width: 100%;
}

.message-list {
  gap: 14px;
  padding: 14px 48px 14px 14px;
  border: 1px solid color-mix(in srgb, var(--chat-work) 18%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--chat-work) 5%, transparent), transparent 34%),
    repeating-linear-gradient(
      0deg,
      color-mix(in srgb, var(--text-primary) 2%, transparent) 0 1px,
      transparent 1px 18px
    ),
    var(--chat-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--chat-work) 11%, transparent),
    0 5px 18px rgba(0, 0, 0, 0.16);
}

.message-question-rail {
  position: absolute;
  top: 50%;
  right: 8px;
  z-index: 3;
  display: flex;
  max-height: 76%;
  flex-direction: column;
  justify-content: center;
  gap: 4px;
  padding: 4px 2px;
  transform: translateY(-50%);
}

.message-question-button {
  position: relative;
  display: flex;
  width: 28px;
  min-height: 7px;
  flex: 0 1 10px;
  align-items: center;
  justify-content: flex-end;
  padding: 0;
  border: 0;
  color: inherit;
  background: transparent;
  cursor: pointer;
}

.message-question-bar {
  display: block;
  width: 19px;
  height: 3px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--text-primary) 42%, transparent);
  transition:
    width 0.14s ease,
    background 0.14s ease,
    opacity 0.14s ease;
}

.message-question-button.active .message-question-bar,
.message-question-button:hover .message-question-bar,
.message-question-button:focus-visible .message-question-bar {
  width: 26px;
  background: color-mix(in srgb, var(--text-primary) 88%, transparent);
}

.message-question-button:focus-visible {
  outline: 0;
}

.message-question-tooltip {
  position: absolute;
  top: 50%;
  right: calc(100% + 10px);
  display: grid;
  width: min(278px, 34vw);
  grid-template-columns: auto minmax(0, 1fr);
  gap: 3px 8px;
  padding: 9px 10px;
  border: 1px solid color-mix(in srgb, var(--chat-work) 26%, var(--border));
  border-radius: 5px;
  color: var(--text-primary);
  background: color-mix(in srgb, var(--chat-panel) 96%, var(--chat-work));
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.26);
  opacity: 0;
  pointer-events: none;
  transform: translate(5px, -50%);
  transition:
    opacity 0.12s ease,
    transform 0.12s ease;
}

.message-question-button:hover .message-question-tooltip,
.message-question-button:focus-visible .message-question-tooltip {
  opacity: 1;
  transform: translate(0, -50%);
}

.message-question-index {
  grid-row: 1 / span 2;
  color: var(--chat-work);
  font-family: var(--mono);
  font-size: 9px;
  line-height: 1.5;
}

.message-question-copy {
  overflow: hidden;
  font-size: 11px;
  line-height: 1.55;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.message-question-tooltip small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  line-height: 1.4;
}

.scroll-to-bottom-button {
  position: absolute;
  right: 18px;
  bottom: 18px;
  z-index: 4;
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  padding: 0;
  border: 1px solid color-mix(in srgb, var(--chat-work) 44%, var(--border));
  border-radius: 50%;
  color: var(--chat-work);
  background: color-mix(in srgb, var(--chat-panel) 92%, var(--chat-work));
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--chat-work) 14%, transparent),
    0 5px 16px rgba(0, 0, 0, 0.24);
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    color 0.15s ease,
    transform 0.15s ease;
}

.scroll-to-bottom-button:hover {
  border-color: var(--chat-work);
  transform: translateY(-2px);
}

.scroll-to-bottom-button:focus-visible {
  outline: 2px solid var(--chat-work);
  outline-offset: 2px;
}

.scroll-to-bottom-button svg {
  width: 16px;
  height: 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.message {
  width: min(92%, 880px);
  max-width: 880px;
  padding: 11px 13px 12px;
  border-radius: 4px;
  background: var(--chat-panel);
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.14);
}

.message.user {
  width: min(82%, 720px);
  border-color: color-mix(in srgb, var(--chat-input) 30%, var(--border));
  border-right: 3px solid var(--chat-input);
  background: color-mix(in srgb, var(--chat-input) 6%, var(--chat-panel));
}

.message.assistant {
  width: min(100%, 940px);
  max-width: 940px;
  padding: 8px 0 8px 12px;
  border: 0;
  border-color: color-mix(in srgb, var(--chat-work) 22%, var(--border));
  border-left: 2px solid color-mix(in srgb, var(--chat-work) 62%, var(--border));
  border-radius: 0;
  background: transparent;
  box-shadow: none;
}

.message.streaming {
  border-left-color: var(--chat-work);
  background: color-mix(in srgb, var(--chat-work) 3%, transparent);
}

.message-avatar {
  width: 26px;
  height: 26px;
  border-radius: 3px;
}

.message.user .user-avatar {
  border-color: color-mix(in srgb, var(--chat-input) 42%, var(--border));
  color: var(--chat-input);
  background: color-mix(in srgb, var(--chat-input) 8%, transparent);
}

.assistant-avatar {
  border-color: color-mix(in srgb, var(--chat-work) 42%, var(--border));
  background: color-mix(in srgb, var(--chat-work) 10%, var(--chat-panel));
}

.message-avatar img {
  display: block;
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.message-role {
  color: var(--text-secondary);
}

.message p {
  line-height: 1.62;
}

.chat-composer {
  position: relative;
  z-index: 5;
  width: 100%;
  max-width: none;
  overflow: visible;
  box-sizing: border-box;
  border: 1px solid color-mix(in srgb, var(--chat-work) 24%, var(--border));
  border-radius: 5px;
  background: var(--chat-panel);
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--chat-work) 12%, transparent),
    0 5px 18px rgba(0, 0, 0, 0.16);
}

.chat-composer:focus-within {
  border-color: color-mix(in srgb, var(--chat-work) 48%, var(--border));
}

.command-bus-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 12px;
  border-bottom: 1px solid var(--border);
  color: var(--chat-output);
}

.command-bus-head span:last-child {
  color: var(--text-muted);
}

.chat-composer-context {
  gap: 8px;
  padding: 9px 12px 8px;
  background: color-mix(in srgb, var(--chat-work) 3%, transparent);
}

.composer-selector,
.composer-toggle {
  height: 32px;
  border-radius: 3px;
  background: var(--field-bg);
}

.composer-selector:hover,
.composer-selector:focus-within,
.composer-toggle:hover {
  border-color: color-mix(in srgb, var(--chat-work) 38%, var(--border));
}

.composer-toggle.active {
  border-color: color-mix(in srgb, var(--chat-work) 40%, var(--border));
  color: var(--chat-work);
  background: color-mix(in srgb, var(--chat-work) 8%, transparent);
}

.composer-toggle.active .composer-toggle-track {
  background: color-mix(in srgb, var(--chat-work) 22%, var(--field-bg));
}

.composer-toggle.active .composer-toggle-knob {
  background: var(--chat-work);
}

.chat-input {
  width: 100%;
  max-width: none;
  padding: 0 0 10px;
  box-sizing: border-box;
}

.chat-input > textarea {
  display: block;
  width: 100%;
  min-width: 0;
  max-width: none;
  min-height: 112px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-primary);
  background: var(--field-bg);
  box-shadow: none;
  font-size: 13px;
  box-sizing: border-box;
}

.chat-input > textarea:focus {
  border-color: color-mix(in srgb, var(--chat-work) 46%, var(--border));
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--chat-work) 14%, transparent);
}

.chat-input-footer {
  width: 100%;
  padding-inline: 12px;
  box-sizing: border-box;
}

.composer-icon-button {
  width: 34px;
  height: 34px;
  border-radius: 3px;
}

.composer-icon-button.send {
  color: #101410;
  background: var(--chat-output);
}

.composer-icon-button.send:hover {
  color: #101410;
  background: color-mix(in srgb, var(--chat-output) 86%, white);
}

@keyframes chat-live-pulse {
  0%,
  100% {
    opacity: 0.35;
  }

  50% {
    opacity: 1;
  }
}

.chat-layout.chat-layout-fullscreen {
  grid-template-columns: minmax(0, 1fr);
  grid-template-rows: minmax(0, 1fr);
  gap: 0;
}

.chat-layout.chat-layout-fullscreen .chat-command-header {
  display: none;
}

.chat-layout.chat-layout-fullscreen .conversation-toggle-rail {
  display: none;
}

.chat-layout.chat-layout-fullscreen .chat-panel {
  grid-column: 1 / -1;
  grid-row: 1 / -1;
}

.chat-layout.chat-layout-fullscreen .message-list {
  justify-items: stretch;
}

.chat-layout.chat-layout-fullscreen .message,
.chat-layout.chat-layout-fullscreen .message.user,
.chat-layout.chat-layout-fullscreen .message.assistant,
.chat-layout.chat-layout-fullscreen .message.streaming {
  width: 100%;
  max-width: none;
  justify-self: stretch;
}

@media (prefers-reduced-motion: reduce) {
  .chat-live-status i {
    animation: none;
  }

  .scroll-to-bottom-button {
    transition: none;
  }

  .message-question-bar,
  .message-question-tooltip {
    transition: none;
  }
}

@media (max-width: 900px) {
  .chat-command-header {
    grid-template-columns: 1fr auto;
  }

  .chat-command-route {
    display: none;
  }
}

@media (max-width: 760px) {
  .chat-layout {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: minmax(0, 230px) minmax(0, 1fr);
    gap: 8px;
  }

  .chat-command-header {
    grid-template-columns: 1fr;
    gap: 9px;
    padding: 12px;
  }

  .chat-command-title > div {
    flex-wrap: wrap;
  }

  .chat-command-status {
    justify-content: flex-start;
  }

  .conversation-list {
    max-height: 230px;
  }

  .message,
  .message.user {
    width: 100%;
    max-width: 100%;
  }

  .message-list {
    padding: 10px 38px 10px 10px;
  }

  .message-question-rail {
    right: 3px;
    gap: 3px;
  }

  .message-question-button {
    width: 22px;
  }

  .message-question-bar {
    width: 14px;
  }

  .message-question-button.active .message-question-bar,
  .message-question-button:hover .message-question-bar,
  .message-question-button:focus-visible .message-question-bar {
    width: 20px;
  }

  .message-question-tooltip {
    display: none;
  }

  .scroll-to-bottom-button {
    right: 14px;
    bottom: 14px;
    width: 36px;
    height: 36px;
  }

  .command-bus-head {
    padding-inline: 10px;
  }
}
</style>

<style scoped>
/* Collapsible conversation history */
.conversation-list-title-copy {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.conversation-toggle-rail {
  position: absolute;
  top: 50%;
  left: calc(270px + 5px);
  z-index: 6;
  display: grid;
  width: 30px;
  height: 30px;
  padding: 0;
  border: 1px solid color-mix(in srgb, var(--chat-work) 34%, var(--border));
  border-radius: 50%;
  color: var(--chat-work);
  background: color-mix(in srgb, var(--surface) 92%, var(--chat-work));
  box-shadow: 0 5px 16px rgba(0, 0, 0, 0.28);
  cursor: pointer;
  place-items: center;
  transform: translate(-50%, -50%);
}

.conversation-toggle-rail:hover {
  border-color: color-mix(in srgb, var(--chat-work) 58%, var(--border));
  background: color-mix(in srgb, var(--chat-work) 12%, var(--surface));
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.38);
}

.conversation-toggle-rail.collapsed {
  left: 15px;
}

.conversation-toggle-rail svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.chat-layout.chat-layout-conversation-collapsed {
  grid-template-columns: minmax(0, 1fr);
  grid-template-rows: minmax(0, 1fr);
  gap: 0;
}

.chat-layout.chat-layout-conversation-collapsed .conversation-list {
  display: none;
}

.chat-layout.chat-layout-conversation-collapsed .chat-panel {
  justify-self: stretch;
  width: 100%;
  min-width: 0;
  max-width: none;
  margin-inline: 0;
}

.chat-layout.chat-layout-fullscreen,
.chat-layout.chat-layout-fullscreen.chat-layout-conversation-collapsed {
  grid-template-columns: minmax(0, 1fr);
  grid-template-areas: "chat";
  grid-template-rows: minmax(0, 1fr);
  gap: 0;
}

.chat-layout.chat-layout-fullscreen .chat-panel {
  grid-area: chat;
}

.chat-layout.chat-layout-conversation-collapsed .message-list {
  justify-items: stretch;
}

.chat-layout.chat-layout-conversation-collapsed .message,
.chat-layout.chat-layout-conversation-collapsed .message.user,
.chat-layout.chat-layout-conversation-collapsed .message.assistant,
.chat-layout.chat-layout-conversation-collapsed .message.streaming {
  width: 100%;
  max-width: none;
  justify-self: stretch;
}

.chat-layout.chat-layout-conversation-collapsed .chat-composer,
.chat-layout.chat-layout-conversation-collapsed .chat-input {
  width: 100%;
  min-width: 0;
  max-width: none;
  box-sizing: border-box;
}

.chat-layout.chat-layout-conversation-collapsed .chat-input > textarea {
  width: 100%;
  min-width: 0;
  max-width: none;
  box-sizing: border-box;
}

@media (max-width: 760px) {
  .chat-layout.chat-layout-conversation-collapsed {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: minmax(0, 1fr);
  }

  .conversation-toggle-rail {
    top: calc(230px + 4px);
    left: 50%;
    transform: translate(-50%, -50%);
  }

  .conversation-toggle-rail.collapsed {
    top: 50%;
    left: 15px;
    transform: translate(-50%, -50%);
  }
}
</style>
