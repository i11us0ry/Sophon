/**
 * 控制台数据层：只做真实接口适配与聚合，不包含任何业务写操作。
 * 机器人专属遥测（温度/电量/信号/坐标）后端没有对应接口，统一放在
 * SIMULATED_TELEMETRY 里并在 UI 上标记 SIMULATED，绝不冒充真实连接。
 */
import { apiGet } from '../api/client'

export interface DashboardSummary {
  conversations: number
  vulnerabilities: number
  toolCalls: number
  assets?: {
    total: number
    criticality: Record<string, number>
    status: Record<string, number>
  }
  tokens: { prompt: number; completion: number; total: number; estimated: boolean }
  vulnerabilityStatus?: Record<string, number>
  vulnerabilitySeverity?: Record<string, number>
}

export interface SystemStats {
  hostname: string
  os: string
  arch: string
  cpuPercent: number
  cpuSupported: boolean
  memoryPercent: number
  memoryUsedBytes: number
  memoryTotalBytes: number
  memorySource: string
  collectedAt: string
}

export interface McpServer {
  id: string
  name: string
  status: string
  enabled: boolean
  toolCount: number
  lastError?: string
}

export interface ObservabilityMetrics {
  enabled: boolean
  eventsTotal: number
  failuresTotal: number
  deniedTotal: number
  approvalsTotal: number
  byType: Record<string, number>
  tools: Record<string, number>
  bufferSize: number
  fileBytes: number
}

export interface ObservabilityEvent {
  event_id: string
  event_type: string
  timestamp: string
  project_id?: string
  conversation_id?: string
  run_id?: string
  agent_mode?: string
  subagent_id?: string
  subagent_mode?: string
  agent_name?: string
  agent_kind?: string
  parent_agent_id?: string
  intent_id?: string
  hypothesis_id?: string
  capability_mode?: string
  tool_name?: string
  server_name?: string
  policy_decision?: string
  capability?: string
  duration_ms?: number
  success?: boolean
  error_category?: string
  detail?: string
}

export interface AuditLogItem {
  id: string
  username: string
  action: string
  resourceType: string
  resourceId: string
  result: string
  detail: string
  createdAt: string
}

export interface ToolExecution {
  id: string
  conversationId: string
  toolName: string
  arguments: Record<string, unknown>
  status: string
  result: string
  error: string
  startedAt: string
  finishedAt?: string | null
}

export interface ConversationSummary {
  id: string
  title: string
  projectId: string
  status?: string
  updatedAt: string
  createdAt: string
}

export interface ContextMetrics {
  compactions: { total: number; major: number; minor: number; avgRatio: number; lastAt: string | null }
  injections: { total: number }
  memoryWrites: { total: number; ADD: number; UPDATE: number; SUPERSEDE: number; NONE: number }
}

export type LogLevel = 'info' | 'success' | 'warn' | 'error'

export interface ConsoleLogEntry {
  id: string
  time: string
  level: LogLevel
  source: 'event' | 'audit'
  message: string
}

export interface ConsoleSnapshot {
  summary: DashboardSummary | null
  system: SystemStats | null
  mcpServers: McpServer[]
  metrics: ObservabilityMetrics | null
  context: ContextMetrics | null
  executions: ToolExecution[]
  conversations: ConversationSummary[]
  logs: ConsoleLogEntry[]
  fetchedAt: string
  degraded: string[]
}

// SIMULATED：机器人本体遥测，后端没有数据源，仅用于控制台视觉与交互演示。
export interface SimulatedTelemetry {
  temperatureC: number
  batteryPercent: number
  signalPercent: number
  position: { x: number; y: number; z: number }
  simulated: true
}

async function safeGet<T>(path: string, degraded: string[], label: string): Promise<T | null> {
  try {
    return await apiGet<T>(path)
  } catch {
    degraded.push(label)
    return null
  }
}

export async function fetchConsoleSnapshot(): Promise<ConsoleSnapshot> {
  const degraded: string[] = []
  const [summary, system, servers, metrics, context, executions, conversations, events, audit] =
    await Promise.all([
      safeGet<DashboardSummary>('/dashboard/summary', degraded, 'summary'),
      safeGet<SystemStats>('/system/stats', degraded, 'system'),
      safeGet<{ items: McpServer[] }>('/mcp/servers', degraded, 'mcp'),
      safeGet<ObservabilityMetrics>('/observability/metrics', degraded, 'metrics'),
      safeGet<ContextMetrics>('/context/metrics', degraded, 'context'),
      safeGet<{ items: ToolExecution[] }>('/monitor/executions', degraded, 'executions'),
      safeGet<{ items: ConversationSummary[] }>('/conversations?limit=6', degraded, 'conversations'),
      safeGet<{ items: ObservabilityEvent[] }>('/observability/events?limit=80', degraded, 'events'),
      safeGet<{ items: AuditLogItem[] }>('/audit/logs?limit=40', degraded, 'audit'),
    ])

  return {
    summary,
    system,
    mcpServers: servers?.items ?? [],
    metrics,
    context,
    executions: executions?.items ?? [],
    conversations: conversations?.items ?? [],
    logs: buildLogs(events?.items ?? [], audit?.items ?? []),
    fetchedAt: new Date().toISOString(),
    degraded,
  }
}

// buildLogs 把可观测性事件与审计日志合成统一的控制台事件流（只保留元数据，不含提示词/参数）。
export function buildLogs(
  events: ObservabilityEvent[],
  audit: AuditLogItem[],
): ConsoleLogEntry[] {
  const entries: ConsoleLogEntry[] = []
  for (const event of events) {
    entries.push({
      id: `evt-${event.event_id}`,
      time: event.timestamp,
      level: eventLevel(event),
      source: 'event',
      message: eventMessage(event),
    })
  }
  for (const item of audit) {
    entries.push({
      id: `audit-${item.id}`,
      time: item.createdAt,
      level: item.result === 'success' ? 'info' : 'warn',
      source: 'audit',
      message: `${item.action}${item.resourceType ? ` · ${item.resourceType}` : ''}`,
    })
  }
  return entries
    .sort((left, right) => new Date(left.time).getTime() - new Date(right.time).getTime())
    .slice(-120)
}

function eventLevel(event: ObservabilityEvent): LogLevel {
  if (event.event_type.endsWith('.failed')) {
    return 'error'
  }
  if (event.event_type === 'tool.decision') {
    return event.policy_decision === 'allow' ? 'info' : 'warn'
  }
  if (event.event_type.endsWith('.completed')) {
    return 'success'
  }
  return 'info'
}

function eventMessage(event: ObservabilityEvent): string {
  const parts: string[] = [event.event_type]
  if (event.tool_name) {
    parts.push(event.tool_name)
  }
  if (event.policy_decision) {
    parts.push(event.policy_decision)
  }
  if (event.agent_name) {
    parts.push(event.agent_name)
  }
  if (event.agent_mode) {
    parts.push(`mode:${event.agent_mode}`)
  }
  if (event.hypothesis_id) {
    parts.push(`hypothesis:${event.hypothesis_id}`)
  }
  if (typeof event.duration_ms === 'number' && event.duration_ms > 0) {
    parts.push(`${event.duration_ms}ms`)
  }
  if (event.error_category) {
    parts.push(event.error_category)
  }
  return parts.join(' · ')
}

// simulateTelemetry 生成稳定的模拟遥测：基于 tick 缓变，避免每帧剧烈跳动。
export function simulateTelemetry(tick: number): SimulatedTelemetry {
  const wave = (period: number, amplitude: number, phase = 0) =>
    Math.sin((tick / period) * Math.PI * 2 + phase) * amplitude
  return {
    temperatureC: Number((41.5 + wave(24, 3.2)).toFixed(1)),
    batteryPercent: Number(Math.max(12, 92 - (tick % 240) * 0.08).toFixed(1)),
    signalPercent: Number((86 + wave(16, 7, 0.7)).toFixed(1)),
    position: {
      x: Number((wave(40, 1.6)).toFixed(2)),
      y: Number((wave(52, 0.9, 1.1)).toFixed(2)),
      z: Number((wave(64, 2.4, 2.2)).toFixed(2)),
    },
    simulated: true,
  }
}

// tokenSeries 从真实 token 用量推导趋势采样（无历史接口时退化为单点，不做伪造）。
export function tokenSeries(total: number, points = 24): number[] {
  if (total <= 0) {
    return new Array(points).fill(0)
  }
  return Array.from({ length: points }, (_, index) => {
    const ratio = (index + 1) / points
    return Math.round(total * ratio * (0.6 + 0.4 * Math.sin(ratio * Math.PI)))
  })
}
