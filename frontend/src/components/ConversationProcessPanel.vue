<script setup lang="ts">
import { ref } from 'vue'

import { useI18n } from '../i18n'
import type { ProcessDetail } from '../stores/chat'

defineProps<{ details: ProcessDetail[] }>()
const emit = defineEmits<{ close: [] }>()
const { t } = useI18n()
const expanded = ref(new Set<string>())

function isExpanded(id: string) {
  return expanded.value.has(id)
}

function onToggle(id: string, event: Event) {
  const open = (event.currentTarget as HTMLDetailsElement).open
  const next = new Set(expanded.value)
  if (open) {
    next.add(id)
  } else {
    next.delete(id)
  }
  expanded.value = next
}

function formatArguments(value: unknown): string {
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2)
    } catch {
      return value
    }
  }
  return JSON.stringify(value ?? {}, null, 2)
}

function resultText(detail: ProcessDetail): string {
  const result = detail.data?.result
  if (typeof result === 'string') {
    return result
  }
  return JSON.stringify(result ?? '', null, 2)
}
</script>

<template>
  <aside class="process-panel">
    <header class="process-header">
      <strong>{{ t('chat.process') }}</strong>
      <button class="button compact" type="button" @click="emit('close')">
        {{ t('common.close') }}
      </button>
    </header>
    <div class="process-items">
      <article
        v-for="detail in details"
        :key="detail.id"
        class="process-item"
        :class="detail.eventType"
      >
        <span class="process-dot"></span>
        <div class="process-body">
          <div class="process-head">
            <small>{{ detail.eventType }}</small>
            <strong>{{ detail.message }}</strong>
          </div>
          <details
            v-if="detail.eventType === 'tool_call'"
            @toggle="onToggle(detail.id, $event)"
          >
            <summary>{{ t('chat.stepsArguments') }}</summary>
            <pre v-if="isExpanded(detail.id)">{{ formatArguments(detail.data?.arguments) }}</pre>
          </details>
          <details
            v-else-if="detail.eventType === 'tool_result'"
            @toggle="onToggle(detail.id, $event)"
          >
            <summary>{{ t('chat.eventToolResult') }}</summary>
            <pre v-if="isExpanded(detail.id)">{{ resultText(detail) }}</pre>
          </details>
        </div>
      </article>
      <p v-if="!details.length" class="process-empty">{{ t('chat.noProcess') }}</p>
    </div>
  </aside>
</template>

<style scoped>
.process-panel {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 10px;
  max-height: 320px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-soft);
}

.process-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.process-items {
  position: relative;
  display: grid;
  gap: 10px;
  align-content: start;
  padding-left: 14px;
  overflow: auto;
}

.process-items::before {
  content: '';
  position: absolute;
  top: 4px;
  bottom: 4px;
  left: 4px;
  width: 1px;
  background: var(--border);
}

.process-item {
  position: relative;
}

.process-dot {
  position: absolute;
  top: 8px;
  left: -14px;
  width: 9px;
  height: 9px;
  border: 2px solid var(--surface-soft);
  border-radius: 50%;
  background: var(--text-muted);
}

.process-item.tool_call .process-dot {
  background: var(--accent);
}

.process-item.tool_result .process-dot {
  background: var(--success);
}

.process-body {
  display: grid;
  gap: 4px;
  padding: 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--field-bg);
}

.process-head {
  display: flex;
  align-items: center;
  gap: 8px;
}

.process-head small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 11px;
}

.process-head strong {
  color: var(--text-secondary);
  font-size: 13px;
}

.process-body pre {
  margin: 0;
  max-height: 180px;
  overflow: auto;
  padding: 6px;
  border-radius: 4px;
  background: var(--surface);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

.process-body details summary {
  color: var(--text-muted);
  font-size: 12px;
  cursor: pointer;
}

.process-body details[open] summary {
  margin-bottom: 6px;
}

.process-empty {
  margin: 0;
  padding: 16px 6px;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
}
</style>
