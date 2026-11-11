import { computed, onUnmounted, ref } from 'vue'

import {
  fetchConsoleSnapshot,
  simulateTelemetry,
  tokenSeries,
  type ConsoleLogEntry,
  type ConsoleSnapshot,
  type SimulatedTelemetry,
} from '../services/consoleData'

export type ModuleStatus = 'online' | 'warn' | 'error' | 'idle'

export interface ConsoleModule {
  key: string
  labelKey: string
  detailKey: string
  status: ModuleStatus
  value: string
  load: number
}

const POLL_INTERVAL_MS = 15000
const TELEMETRY_INTERVAL_MS = 2000
const REQUEST_WARNING_MS = 1500

function emptySnapshot(): ConsoleSnapshot {
  return {
    summary: null,
    system: null,
    mcpServers: [],
    metrics: null,
    context: null,
    executions: [],
    conversations: [],
    logs: [],
    fetchedAt: '',
    degraded: [],
  }
}

function eventCount(snapshot: ConsoleSnapshot, types: string[]): number {
  const byType = snapshot.metrics?.byType ?? {}
  return types.reduce((total, type) => total + (byType[type] ?? 0), 0)
}

/**
 * useRobotConsole 负责控制台的状态聚合：
 * - 真实数据：每 15s 轮询一次后端接口，失败来源记录在 degraded 里，UI 显示"数据不可用"。
 * - 模拟数据：机器人本体遥测（温度/电量/信号/坐标）单独 tick，UI 标记 SIMULATED。
 * 所有定时器在组件卸载时清理，暂停时保留最后一帧数据。
 */
export function useRobotConsole() {
  const snapshot = ref<ConsoleSnapshot>(emptySnapshot())
  const loading = ref(false)
  const paused = ref(false)
  const lastUpdated = ref<Date | null>(null)
  const latencyMs = ref(0)
  const clearedAt = ref(0)
  const telemetry = ref<SimulatedTelemetry>(simulateTelemetry(0))
  const tick = ref(0)

  let pollTimer: number | undefined
  let telemetryTimer: number | undefined

  async function refresh() {
    if (paused.value) {
      return
    }
    loading.value = true
    const startedAt = performance.now()
    try {
      snapshot.value = await fetchConsoleSnapshot()
      lastUpdated.value = new Date()
      latencyMs.value = Math.round(performance.now() - startedAt)
    } finally {
      loading.value = false
    }
  }

  function startTimers() {
    stopTimers()
    pollTimer = window.setInterval(() => {
      void refresh()
    }, POLL_INTERVAL_MS)
    telemetryTimer = window.setInterval(() => {
      if (paused.value) {
        return
      }
      tick.value += 1
      telemetry.value = simulateTelemetry(tick.value)
    }, TELEMETRY_INTERVAL_MS)
  }

  function stopTimers() {
    if (pollTimer !== undefined) {
      window.clearInterval(pollTimer)
      pollTimer = undefined
    }
    if (telemetryTimer !== undefined) {
      window.clearInterval(telemetryTimer)
      telemetryTimer = undefined
    }
  }

  function togglePause() {
    paused.value = !paused.value
    if (!paused.value) {
      void refresh()
    }
  }

  function clearLogs() {
    clearedAt.value = Date.now()
  }

  function start() {
    void refresh()
    startTimers()
  }

  onUnmounted(stopTimers)

  const logs = computed<ConsoleLogEntry[]>(() =>
    snapshot.value.logs.filter((item) => new Date(item.time).getTime() > clearedAt.value),
  )

  const degraded = computed(() => snapshot.value.degraded)

  const hasFailures = computed(
    () =>
      (snapshot.value.metrics?.failuresTotal ?? 0) > 0 ||
      snapshot.value.mcpServers.some(
        (server) => server.enabled && server.status !== 'connected',
      ),
  )

  const connectionStatus = computed<'online' | 'degraded' | 'offline'>(() => {
    if (!snapshot.value.fetchedAt) {
      return 'offline'
    }
    return degraded.value.length > 0 ? 'degraded' : 'online'
  })

  const identity = computed(() => ({
    name: 'SOPHON',
    unit: snapshot.value.system?.hostname || 'localhost',
    model: 'AUTONOMOUS PENTEST UNIT',
    firmware: 'v0.1.0',
    platform: snapshot.value.system
      ? `${snapshot.value.system.os} / ${snapshot.value.system.arch}`
      : 'unknown',
  }))

  const tasks = computed(() => {
    const started = eventCount(snapshot.value, ['run.started'])
    const completed = eventCount(snapshot.value, ['run.completed'])
    const failed = eventCount(snapshot.value, ['run.failed'])
    const running = Math.max(0, started - completed - failed)
    return {
      running,
      completed,
      failed,
      conversations: snapshot.value.summary?.conversations ?? 0,
    }
  })

  const network = computed(() => {
    const servers = snapshot.value.mcpServers.filter((server) => server.enabled)
    const connected = servers.filter((server) => server.status === 'connected').length
    return {
      connected,
      total: servers.length,
      latencyMs: latencyMs.value,
      latencyWarning: latencyMs.value > REQUEST_WARNING_MS,
      toolCalls: snapshot.value.summary?.toolCalls ?? 0,
    }
  })

  const memory = computed(() => {
    const system = snapshot.value.system
    const total = system?.memoryTotalBytes ?? 0
    const used = system?.memoryUsedBytes ?? 0
    return {
      percent: system?.memoryPercent ?? 0,
      used,
      total,
      source: system?.memorySource ?? '',
      compactions: snapshot.value.context?.compactions.total ?? 0,
      memoryWrites: snapshot.value.context?.memoryWrites.total ?? 0,
      injections: snapshot.value.context?.injections.total ?? 0,
    }
  })

  const modules = computed<ConsoleModule[]>(() => {
    const metrics = snapshot.value.metrics
    const agentRuns = eventCount(snapshot.value, [
      'run.started',
      'run.completed',
      'run.failed',
      'subagent.started',
      'subagent.completed',
      'subagent.failed',
    ])
    const toolEvents = eventCount(snapshot.value, [
      'tool.started',
      'tool.completed',
      'tool.failed',
      'tool.decision',
    ])
    const memoryEvents =
      (snapshot.value.context?.memoryWrites.total ?? 0) +
      (snapshot.value.context?.compactions.total ?? 0)
    const guardrailEvents =
      (metrics?.approvalsTotal ?? 0) + (metrics?.deniedTotal ?? 0)
    const delivered = snapshot.value.summary?.vulnerabilities ?? 0
    const peak = Math.max(agentRuns, toolEvents, memoryEvents, guardrailEvents, delivered, 1)

    const mcpUnhealthy = snapshot.value.mcpServers.filter(
      (server) => server.enabled && server.status !== 'connected',
    ).length

    return [
      {
        key: 'agent',
        labelKey: 'console.module.agent',
        detailKey: 'console.module.agentDetail',
        status: (metrics?.failuresTotal ?? 0) > 0 ? 'warn' : 'online',
        value: `${agentRuns}`,
        load: Math.round((agentRuns / peak) * 100),
      },
      {
        key: 'tools',
        labelKey: 'console.module.tools',
        detailKey: 'console.module.toolsDetail',
        status: mcpUnhealthy > 0 ? 'error' : toolEvents > 0 ? 'online' : 'idle',
        value: `${snapshot.value.summary?.toolCalls ?? 0}`,
        load: Math.round((toolEvents / peak) * 100),
      },
      {
        key: 'memory',
        labelKey: 'console.module.memory',
        detailKey: 'console.module.memoryDetail',
        status: 'online',
        value: `${memoryEvents}`,
        load: Math.round((memoryEvents / peak) * 100),
      },
      {
        key: 'guardrails',
        labelKey: 'console.module.guardrails',
        detailKey: 'console.module.guardrailsDetail',
        status: (metrics?.deniedTotal ?? 0) > 0 ? 'warn' : 'online',
        value: `${metrics?.approvalsTotal ?? 0}/${metrics?.deniedTotal ?? 0}`,
        load: Math.round((guardrailEvents / peak) * 100),
      },
      {
        key: 'delivery',
        labelKey: 'console.module.delivery',
        detailKey: 'console.module.deliveryDetail',
        status: delivered > 0 ? 'online' : 'idle',
        value: `${delivered}`,
        load: Math.round((delivered / peak) * 100),
      },
    ]
  })

  const tokenTrend = computed(() => tokenSeries(snapshot.value.summary?.tokens.total ?? 0))

  return {
    snapshot,
    loading,
    paused,
    lastUpdated,
    degraded,
    connectionStatus,
    hasFailures,
    identity,
    tasks,
    network,
    memory,
    modules,
    logs,
    telemetry,
    tokenTrend,
    refresh,
    togglePause,
    clearLogs,
    start,
  }
}
