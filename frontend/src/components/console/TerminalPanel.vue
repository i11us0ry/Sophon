<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '../../i18n'
import type { ToolExecution } from '../../services/consoleData'
import { formatClock, formatDuration } from '../../utils/format'

const props = defineProps<{ executions: ToolExecution[] }>()
const { t } = useI18n()

const rows = computed(() => props.executions.slice(0, 40))

// 只展示工具名与参数键，不渲染参数值，避免把命令原文与凭据带进界面日志。
function argumentKeys(execution: ToolExecution): string {
  const keys = Object.keys(execution.arguments ?? {})
  if (!keys.length) {
    return ''
  }
  return keys.map((key) => `<${key}>`).join(' ')
}
</script>

<template>
  <section class="hud-panel terminal-panel">
    <header class="hud-panel-head">
      <span class="hud-index">10</span>
      <h3>{{ t('console.terminal') }}</h3>
      <span class="hud-tag">{{ rows.length }}</span>
    </header>
    <div class="terminal-viewport">
      <div class="terminal-body">
        <p v-if="!rows.length" class="terminal-empty">{{ t('console.terminalEmpty') }}</p>
        <div v-for="execution in rows" :key="execution.id" class="terminal-line">
          <span class="terminal-time">{{ formatClock(execution.startedAt) }}</span>
          <span class="terminal-prompt">$</span>
          <span class="terminal-cmd">
            {{ execution.toolName }}
            <em v-if="argumentKeys(execution)">{{ argumentKeys(execution) }}</em>
          </span>
          <span class="terminal-status" :class="`status-${execution.status}`">
            {{ execution.status }}
          </span>
          <span class="terminal-duration">
            {{ formatDuration(execution.startedAt, execution.finishedAt) }}
          </span>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.terminal-panel {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  min-width: 0;
}

.terminal-viewport {
  position: relative;
  min-width: 0;
  max-height: 240px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 4px;
  background:
    repeating-linear-gradient(0deg, rgba(0, 245, 255, 0.03) 0 1px, transparent 1px 3px),
    radial-gradient(120% 100% at 50% 0%, rgba(0, 245, 255, 0.08), transparent 62%),
    #01060e;
  box-shadow:
    inset 0 0 46px -26px rgba(0, 245, 255, 0.95),
    inset 0 0 0 1px rgba(0, 245, 255, 0.08);
}

/* 终端扫描线：自上而下循环，强调实时执行 */
.terminal-viewport::after {
  position: absolute;
  right: 0;
  left: 0;
  height: 32px;
  content: '';
  background: linear-gradient(
    180deg,
    transparent,
    rgba(0, 255, 178, 0.07) 62%,
    rgba(0, 255, 178, 0.15) 100%
  );
  border-bottom: 1px solid rgba(0, 255, 178, 0.34);
  animation: terminal-scan 5.8s linear infinite;
  pointer-events: none;
}

.terminal-body {
  display: grid;
  gap: 3px;
  align-content: start;
  max-height: 240px;
  padding: 10px;
  overflow: auto;
}

.terminal-line:hover {
  background: linear-gradient(90deg, rgba(0, 245, 255, 0.09), transparent 72%);
  box-shadow: inset 2px 0 0 var(--neon-cyan);
}

.terminal-line {
  display: grid;
  grid-template-columns: 60px 10px minmax(0, 1fr) auto 52px;
  gap: 8px;
  align-items: baseline;
  font-family: var(--mono);
  font-size: 11px;
  line-height: 1.5;
}

.terminal-time {
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

.terminal-prompt {
  color: var(--cyan);
}

:root[data-theme='dark'] .terminal-prompt {
  text-shadow: var(--glow-cyan);
}

:root[data-theme='dark'] .status-failed,
:root[data-theme='dark'] .status-error {
  text-shadow: var(--glow-red);
}

:root[data-theme='dark'] .status-succeeded,
:root[data-theme='dark'] .status-success {
  text-shadow: var(--glow-green);
}

:root[data-theme='dark'] .status-running {
  text-shadow: var(--glow-yellow);
}

.terminal-cmd {
  min-width: 0;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.terminal-cmd em {
  margin-left: 6px;
  color: var(--text-muted);
  font-style: normal;
}

.terminal-status {
  color: var(--text-secondary);
  text-transform: uppercase;
}

.status-failed,
.status-error {
  color: var(--danger);
}

.status-succeeded,
.status-success {
  color: var(--success);
}

.status-running {
  color: var(--warning);
}

.terminal-duration {
  color: var(--text-muted);
  text-align: right;
}

.terminal-empty {
  margin: 0;
  padding: 14px 0;
  color: var(--text-muted);
  font-size: 11px;
  text-align: center;
}

@keyframes terminal-scan {
  from {
    transform: translateY(-36px);
  }
  to {
    transform: translateY(240px);
  }
}

@media (prefers-reduced-motion: reduce) {
  .terminal-viewport::after {
    animation: none;
  }
}
</style>
