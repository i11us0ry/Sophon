<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '../i18n'
import type { AgentStep, AgentTraceSummary } from '../stores/chat'

const props = defineProps<{
  steps: AgentStep[]
  live?: boolean
  totalCount?: number
  loaded?: boolean
  loading?: boolean
  hasMore?: boolean
  agentSummary?: AgentTraceSummary
}>()
const emit = defineEmits<{ 'load-more': [] }>()
const { t } = useI18n()

interface ToolGroup {
  key: string
  agent: AgentIdentity
  call?: AgentStep
  result?: AgentStep
}

interface AgentIdentity {
  id: string
  name: string
  kind: string
  intentId: string
  hypothesisId: string
  capabilityMode: string
  workerFocus: string
  allowedSkills: string[]
}

type StepItem =
  | { kind: 'reasoning' | 'thinking'; step: AgentStep; agent: AgentIdentity }
  | {
      kind: 'agent_started' | 'agent_completed' | 'agent_failed'
      step: AgentStep
      agent: AgentIdentity
    }
  | { kind: 'tool'; group: ToolGroup }

interface AgentGroup {
  key: string
  agent: AgentIdentity
  items: StepItem[]
}

function stepAgent(step: AgentStep): AgentIdentity {
  return {
    id: step.agentId || 'mainagent',
    name: step.agentName || 'Sophon',
    kind: step.agentKind || 'mainagent',
    intentId: step.intentId || '',
    hypothesisId: step.hypothesisId || '',
    capabilityMode: step.capabilityMode || '',
    workerFocus: step.workerFocus || '',
    allowedSkills: Array.isArray(step.allowedSkills) ? step.allowedSkills : [],
  }
}

function agentName(agent: AgentIdentity): string {
  return agent.name || 'Agent'
}

function agentInitial(agent: AgentIdentity): string {
  return agentName(agent).slice(0, 1).toUpperCase()
}

function agentKindLabel(agent: AgentIdentity): string {
  switch (agent.kind) {
    case 'planner':
      return t('chat.agentPlanner')
    case 'worker':
      return t('chat.agentWorker')
    case 'subagent':
      return t('chat.agentSubagent')
    default:
      return t('chat.agentMain')
  }
}

function agentColor(agent: AgentIdentity): string {
  if (agent.id === 'mainagent') {
    return 'var(--accent)'
  }
  let hash = 0
  for (const character of agent.id) {
    hash = (hash * 31 + character.charCodeAt(0)) >>> 0
  }
  return `hsl(${hash % 360} 88% 68%)`
}

function agentStyle(agent: AgentIdentity): Record<string, string> {
  return { '--agent-color': agentColor(agent) }
}

// 工具调用与结果按 toolCallId 配对（并行工具也不会错配），其余按出现顺序渲染。
const items = computed<StepItem[]>(() => {
  const output: StepItem[] = []
  const groups = new Map<string, ToolGroup>()
  for (const step of props.steps) {
    const agent = stepAgent(step)
    if (step.type === 'tool_call') {
      const key = `${agent.id}:${step.toolCallId || `call-${step.id}`}`
      const group: ToolGroup = { key, agent, call: step }
      groups.set(key, group)
      output.push({ kind: 'tool', group })
      continue
    }
    if (step.type === 'tool_result') {
      const groupKey = step.toolCallId ? `${agent.id}:${step.toolCallId}` : ''
      const existing = groupKey ? groups.get(groupKey) : undefined
      if (existing) {
        existing.result = step
        continue
      }
      const group: ToolGroup = { key: `result-${step.id}`, agent, result: step }
      groups.set(group.key, group)
      output.push({ kind: 'tool', group })
      continue
    }
    if (
      step.type === 'agent_started' ||
      step.type === 'agent_completed' ||
      step.type === 'agent_failed'
    ) {
      output.push({ kind: step.type, step, agent })
      continue
    }
    output.push({
      kind: step.type === 'reasoning' ? 'reasoning' : 'thinking',
      step,
      agent,
    })
  }
  return output
})

// 连续事件归到同一个 Agent 身份卡，形成群聊式分组，而不是每个步骤重复身份。
const groups = computed<AgentGroup[]>(() => {
  const output: AgentGroup[] = []
  for (const item of items.value) {
    const agent = item.kind === 'tool' ? item.group.agent : item.agent
    const current = output.at(-1)
    if (current && current.agent.id === agent.id) {
      current.items.push(item)
      continue
    }
    output.push({
      key: `${agent.id}-${output.length}`,
      agent,
      items: [item],
    })
  }
  return output
})

const fallbackAgentCounts = computed(() => {
  const agents = new Map<string, AgentIdentity>()
  for (const item of items.value) {
    const agent = item.kind === 'tool' ? item.group.agent : item.agent
    agents.set(agent.id, agent)
  }
  const counts = { main: 0, planner: 0, worker: 0, subagent: 0 }
  for (const agent of agents.values()) {
    if (agent.kind === 'planner') {
      counts.planner++
    } else if (agent.kind === 'worker') {
      counts.worker++
    } else if (agent.kind === 'subagent') {
      counts.subagent++
    } else {
      counts.main++
    }
  }
  return counts
})

const agentCounts = computed(() => {
  if (props.agentSummary) {
    return {
      main: props.agentSummary.main || 0,
      planner: props.agentSummary.planner || 0,
      worker: props.agentSummary.worker || 0,
      subagent: props.agentSummary.subagent || 0,
    }
  }
  return fallbackAgentCounts.value
})

const displayStepCount = computed(() => Math.max(props.totalCount || 0, items.value.length))

function itemKey(item: StepItem, index: number) {
  if (item.kind === 'tool') {
    return `tool-${item.group.key || index}`
  }
  return `${item.kind}-${item.step.id || index}`
}

function lifecycleLabel(kind: string) {
  switch (kind) {
    case 'agent_started':
      return t('chat.workerStarted')
    case 'agent_failed':
      return t('chat.workerFailed')
    default:
      return t('chat.workerCompleted')
  }
}

function formatDuration(value?: number) {
  const milliseconds = Number(value || 0)
  if (milliseconds <= 0) {
    return '-'
  }
  if (milliseconds < 1000) {
    return `${milliseconds}ms`
  }
  const seconds = Math.round(milliseconds / 1000)
  if (seconds < 60) {
    return `${seconds}s`
  }
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return `${minutes}m ${rest}s`
}

function onToggle(event: Event) {
  if (props.live || props.loaded) {
    return
  }
  const details = event.target as HTMLDetailsElement
  if (details.open) {
    emit('load-more')
  }
}

</script>

<template>
  <details
    v-if="live || items.length || (totalCount || 0) > 0"
    class="agent-run"
    :open="live"
    @toggle="onToggle"
  >
    <summary v-if="!live" class="agent-run-summary">
      <span>{{ t('chat.executionSteps', { count: displayStepCount }) }}</span>
      <svg class="agent-run-chevron" viewBox="0 0 24 24" aria-hidden="true">
        <path d="m6 9 6 6 6-6" />
      </svg>
    </summary>
    <div class="agent-steps" :class="{ live }">
      <div
        v-if="
          agentCounts.main ||
          agentCounts.planner ||
          agentCounts.worker ||
          agentCounts.subagent
        "
        class="agent-run-overview"
      >
        <span v-if="agentCounts.main">{{ t('chat.agentMain') }} {{ agentCounts.main }}</span>
        <span v-if="agentCounts.planner">
          {{ t('chat.agentPlanner') }} {{ agentCounts.planner }}
        </span>
        <span v-if="agentCounts.worker">{{ t('chat.agentWorker') }} {{ agentCounts.worker }}</span>
        <span v-if="agentCounts.subagent">
          {{ t('chat.agentSubagent') }} {{ agentCounts.subagent }}
        </span>
      </div>
      <section
        v-for="group in groups"
        :key="group.key"
        class="agent-message"
        :style="agentStyle(group.agent)"
      >
        <header class="agent-trace-head">
          <span class="agent-avatar">
            {{ agentInitial(group.agent) }}
          </span>
          <strong>{{ agentName(group.agent) }}</strong>
          <span class="agent-kind">{{ agentKindLabel(group.agent) }}</span>
          <span
            v-if="group.agent.capabilityMode"
            class="agent-capability"
            :title="group.agent.capabilityMode"
          >
            {{ group.agent.capabilityMode }}
          </span>
          <span
            v-if="group.agent.allowedSkills.length"
            class="agent-capability"
            :title="group.agent.allowedSkills.join('、')"
          >
            {{ t('chat.workerSkillCount', { count: group.agent.allowedSkills.length }) }}
          </span>
          <span v-if="group.agent.intentId || group.agent.hypothesisId" class="agent-ref">
            <span v-if="group.agent.intentId">I:{{ group.agent.intentId }}</span>
            <span v-if="group.agent.hypothesisId">H:{{ group.agent.hypothesisId }}</span>
          </span>
        </header>
        <div class="agent-message-body">
          <article
            v-for="(item, index) in group.items"
            :key="itemKey(item, index)"
            class="agent-step"
            :class="item.kind"
          >
            <template
              v-if="
                item.kind === 'agent_started' ||
                item.kind === 'agent_completed' ||
                item.kind === 'agent_failed'
              "
            >
              <div class="step-tool-head">
                <span class="step-badge">{{ lifecycleLabel(item.kind) }}</span>
                <strong>{{ item.step.workerFocus || item.agent.name }}</strong>
              </div>
              <div v-if="item.step.task" class="step-block">
                <small class="step-label">{{ t('chat.workerTask') }}</small>
                <pre>{{ item.step.task }}</pre>
              </div>
              <div v-if="item.step.allowedSkills?.length" class="step-block">
                <small class="step-label">{{ t('chat.workerSkills') }}</small>
                <div class="agent-skill-list">
                  <span v-for="skill in item.step.allowedSkills" :key="skill">{{ skill }}</span>
                </div>
              </div>
              <div
                v-if="item.kind === 'agent_completed' || item.kind === 'agent_failed'"
                class="step-block agent-lifecycle-state"
              >
                <span>{{ t('chat.workerDuration') }} {{ formatDuration(item.step.durationMs) }}</span>
                <span v-if="item.step.status">
                  {{ t('chat.workerStatus') }} {{ item.step.status }}
                </span>
              </div>
              <div v-if="item.step.resultSummary" class="step-block">
                <small class="step-label">{{ t('chat.workerResult') }}</small>
                <pre>{{ item.step.resultSummary }}</pre>
              </div>
              <div v-if="item.step.errorMessage" class="step-block">
                <small class="step-label">{{ t('chat.workerError') }}</small>
                <pre>{{ item.step.errorMessage }}</pre>
              </div>
            </template>
            <template v-else-if="item.kind === 'reasoning' || item.kind === 'thinking'">
              <div class="step-head">
                <span class="step-badge">
                  {{ item.kind === 'reasoning' ? t('chat.stepsReasoning') : t('chat.stepsThinking') }}
                </span>
              </div>
              <pre>{{ item.step.content }}</pre>
            </template>
            <template v-else>
              <div class="step-tool-head">
                <span class="step-badge">{{ t('chat.stepsToolCall') }}</span>
                <strong>{{ item.group.call?.toolName || item.group.result?.toolName || 'tool' }}</strong>
              </div>
              <div v-if="item.group.call" class="step-block">
                <small class="step-label">{{ t('chat.stepsArguments') }}</small>
                <pre>{{ item.group.call.content || '{}' }}</pre>
              </div>
              <div v-if="item.group.result" class="step-block">
                <small class="step-label">
                  {{ item.group.result.content ? t('chat.stepsToolResult') : t('chat.stepsRunning') }}
                </small>
                <pre>{{ item.group.result.content }}</pre>
              </div>
            </template>
          </article>
        </div>
      </section>
      <button
        v-if="hasMore"
        class="button compact agent-run-more"
        type="button"
        :disabled="loading"
        @click.prevent="emit('load-more')"
      >
        {{ loading ? t('common.loading') : t('chat.loadMoreProcess') }}
      </button>
    </div>
  </details>
</template>

<style scoped>
.agent-steps {
  display: grid;
  gap: 10px;
  margin-bottom: 8px;
}

.agent-message {
  overflow: hidden;
  border: 1px solid var(--line);
  border-top: 3px solid var(--agent-color, var(--accent));
  border-radius: var(--radius);
  background: var(--field-bg);
  box-shadow: none;
}

.agent-message-body {
  display: grid;
}

.agent-run {
  margin-bottom: 8px;
}

.agent-run-summary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 9px;
  border: 1px solid color-mix(in srgb, var(--border) 78%, transparent);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: color-mix(in srgb, var(--surface-soft) 72%, transparent);
  font-size: 11px;
  cursor: pointer;
  list-style: none;
}

.agent-run-summary > span:first-child {
  flex: 0 0 auto;
}

.agent-run-summary::-webkit-details-marker {
  display: none;
}

.agent-run-chevron {
  flex: 0 0 auto;
  width: 13px;
  height: 13px;
  margin-left: auto;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2;
  transition: transform 0.15s ease;
}

.agent-run[open] > .agent-run-summary {
  border-radius: var(--radius);
}

.agent-run[open] > .agent-run-summary .agent-run-chevron {
  transform: rotate(180deg);
}

.agent-run > .agent-steps {
  margin-top: 6px;
  margin-bottom: 0;
}

.agent-run-overview {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 6px 9px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--text-muted);
  background: var(--surface-soft);
  font-size: 10px;
}

.agent-run-overview span {
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.agent-run-more {
  justify-self: start;
}

.agent-step {
  border: 0;
  border-top: 1px solid var(--border);
  border-radius: var(--radius);
  background: transparent;
  font-size: 12px;
}

.agent-step:first-child {
  border-top: 0;
}

.agent-step.live {
  border-style: dashed;
}

.agent-trace-head {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
  background: transparent;
  background: var(--accent-soft);
}

.agent-trace-head strong {
  color: var(--text-primary);
  font-size: 11px;
}

.agent-avatar {
  display: inline-grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border: 1px solid var(--agent-color, var(--accent));
  border-radius: 50%;
  color: var(--agent-color, var(--accent));
  background: color-mix(in srgb, var(--agent-color, var(--accent)) 14%, var(--surface));
  box-shadow: none;
  font-size: 10px;
  font-weight: 700;
}

.agent-kind,
.agent-capability,
.agent-ref {
  color: var(--text-muted);
  font-size: 10px;
}

.agent-capability {
  overflow: hidden;
  max-width: 120px;
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.agent-ref {
  display: flex;
  gap: 6px;
  margin-left: auto;
  font-family: var(--mono);
}

.step-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
}

.step-block {
  padding: 0 10px 8px;
}

.step-label {
  display: block;
  margin-bottom: 4px;
  color: var(--text-muted);
  font-size: 11px;
}

.step-badge {
  flex: 0 0 auto;
  padding: 1px 8px;
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text-muted);
  font-size: 11px;
}

.agent-step.reasoning .step-badge {
  border-color: var(--accent-line);
  color: var(--accent);
}

.agent-step.thinking .step-badge {
  border-color: color-mix(in srgb, var(--warning) 45%, var(--border));
  color: var(--warning);
}

.step-tool-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
}

.step-tool-head strong {
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 12px;
}

.agent-step pre {
  max-height: 220px;
  margin: 0 10px 8px;
  overflow: auto;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  font-size: 11.5px;
  white-space: pre-wrap;
  word-break: break-all;
}

.step-block pre {
  margin: 0;
}

.agent-skill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.agent-skill-list span {
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface);
  font-family: var(--mono);
  font-size: 10px;
}

.agent-lifecycle-state {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  color: var(--text-muted);
  font-size: 11px;
}

.agent-step.reasoning pre,
.agent-step.thinking pre {
  color: var(--text-secondary);
  font-family: inherit;
}
</style>
