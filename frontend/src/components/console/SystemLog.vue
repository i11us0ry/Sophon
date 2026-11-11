<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'

import { useI18n } from '../../i18n'
import type { ConsoleLogEntry, LogLevel } from '../../services/consoleData'
import { formatClock } from '../../utils/format'

const props = defineProps<{ entries: ConsoleLogEntry[] }>()
const emit = defineEmits<{ (event: 'clear'): void }>()

const { t } = useI18n()
const filter = ref<'all' | LogLevel>('all')
const listRef = ref<HTMLElement | null>(null)
const autoScroll = ref(true)

const filters: Array<'all' | LogLevel> = ['all', 'info', 'success', 'warn', 'error']

const visible = computed(() =>
  props.entries.filter((item) => filter.value === 'all' || item.level === filter.value),
)

watch(
  () => visible.value.length,
  async () => {
    if (!autoScroll.value || !listRef.value) {
      return
    }
    await nextTick()
    listRef.value.scrollTop = listRef.value.scrollHeight
  },
)

function onScroll() {
  if (!listRef.value) {
    return
  }
  const el = listRef.value
  autoScroll.value = el.scrollHeight - el.scrollTop - el.clientHeight < 24
}
</script>

<template>
  <section class="hud-panel system-log">
    <header class="hud-panel-head">
      <span class="hud-index">08</span>
      <h3>{{ t('console.log') }}</h3>
      <div class="log-filters">
        <button
          v-for="item in filters"
          :key="item"
          type="button"
          class="log-filter"
          :class="{ active: filter === item }"
          @click="filter = item"
        >
          {{ item === 'all' ? t('console.logAll') : item.toUpperCase() }}
        </button>
        <button type="button" class="log-filter" @click="emit('clear')">
          {{ t('console.logClear') }}
        </button>
      </div>
    </header>
    <div class="log-viewport">
      <ul ref="listRef" class="log-list" @scroll="onScroll">
        <transition-group name="log-line">
          <li v-for="item in visible" :key="item.id" class="log-row" :class="`level-${item.level}`">
            <span class="log-time">{{ formatClock(item.time) }}</span>
            <span class="log-level">{{ item.level.toUpperCase() }}</span>
            <span class="log-message">{{ item.message }}</span>
          </li>
        </transition-group>
        <li v-if="!visible.length" class="log-empty">{{ t('console.logEmpty') }}</li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.system-log {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  min-width: 0;
}

.log-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-left: auto;
}

.log-filter {
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: transparent;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
  cursor: pointer;
}

.log-filter.active {
  border-color: var(--border-active);
  color: var(--cyan);
  background: rgba(0, 200, 255, 0.08);
}

.log-viewport {
  position: relative;
  min-width: 0;
  max-height: 260px;
  overflow: hidden;
  border: 1px solid rgba(0, 245, 255, 0.12);
  border-radius: 6px;
  background:
    repeating-linear-gradient(0deg, rgba(0, 245, 255, 0.028) 0 1px, transparent 1px 3px),
    radial-gradient(130% 100% at 50% 0%, rgba(22, 119, 255, 0.12), transparent 64%),
    rgba(3, 4, 11, 0.72);
  box-shadow: inset 0 0 46px -30px rgba(0, 245, 255, 0.95);
}

.log-viewport::after {
  position: absolute;
  right: 0;
  left: 0;
  height: 36px;
  content: '';
  background: linear-gradient(
    180deg,
    transparent,
    rgba(0, 245, 255, 0.08) 62%,
    rgba(0, 245, 255, 0.15) 100%
  );
  border-bottom: 1px solid rgba(0, 245, 255, 0.32);
  animation: log-scan 7.2s linear infinite;
  pointer-events: none;
}

.log-list {
  display: grid;
  gap: 2px;
  align-content: start;
  max-height: 260px;
  margin: 0;
  padding: 8px 6px;
  overflow-y: auto;
  list-style: none;
}

.log-row {
  display: grid;
  grid-template-columns: 66px 58px minmax(0, 1fr);
  gap: 8px;
  padding: 3px 4px;
  border-left: 2px solid transparent;
  font-family: var(--mono);
  font-size: 11px;
  line-height: 1.45;
}

.log-time {
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

.log-level {
  align-self: center;
  padding: 1px 5px;
  border: 1px solid currentColor;
  border-radius: 3px;
  color: var(--text-label);
  font-size: 9.5px;
  text-align: center;
  box-shadow: inset 0 0 12px -8px currentColor;
}

.log-message {
  min-width: 0;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.level-info {
  border-left-color: rgba(36, 120, 255, 0.6);
}

.level-success {
  border-left-color: rgba(0, 245, 184, 0.6);
}

.level-success .log-level {
  color: var(--success);
  text-shadow: 0 0 10px rgba(0, 255, 178, 0.8);
}

.level-warn {
  border-left-color: rgba(255, 181, 71, 0.6);
}

.level-warn .log-level {
  color: var(--warning);
  text-shadow: 0 0 10px rgba(255, 181, 71, 0.8);
}

.level-error {
  border-left-color: rgba(255, 69, 106, 0.65);
}

.level-error .log-level,
.level-error .log-message {
  color: var(--danger);
  text-shadow: 0 0 12px rgba(255, 79, 163, 0.75);
}

.log-row:hover {
  background: linear-gradient(90deg, rgba(0, 245, 255, 0.1), transparent 74%);
  box-shadow: inset 2px 0 0 var(--neon-cyan);
}

.log-empty {
  padding: 18px;
  color: var(--text-muted);
  font-size: 12px;
  text-align: center;
}

.log-line-enter-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}

.log-line-enter-from {
  opacity: 0;
  transform: translateY(-4px);
}

@media (prefers-reduced-motion: reduce) {
  .log-line-enter-active,
  .log-viewport::after {
    animation: none;
    transition: none;
  }
}

@keyframes log-scan {
  from {
    transform: translateY(-40px);
  }
  to {
    transform: translateY(260px);
  }
}
</style>
