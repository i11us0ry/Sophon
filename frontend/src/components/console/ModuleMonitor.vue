<script setup lang="ts">
import { ref } from 'vue'

import { useI18n } from '../../i18n'
import type { ConsoleModule } from '../../composables/useRobotConsole'

defineProps<{ modules: ConsoleModule[] }>()

const { t } = useI18n()
const expanded = ref<string[]>([])

function toggle(key: string) {
  expanded.value = expanded.value.includes(key)
    ? expanded.value.filter((item) => item !== key)
    : [...expanded.value, key]
}
</script>

<template>
  <section class="hud-panel module-monitor">
    <header class="hud-panel-head">
      <span class="hud-index">05</span>
      <h3>{{ t('console.modules') }}</h3>
      <span class="hud-tag">{{ modules.length }}</span>
    </header>
    <ul class="module-list">
      <li v-for="item in modules" :key="item.key" class="module-item">
        <button class="module-head" type="button" @click="toggle(item.key)">
          <span class="module-status" :class="`status-${item.status}`" aria-hidden="true"></span>
          <span class="module-name">{{ t(item.labelKey) }}</span>
          <span class="module-value">{{ item.value }}</span>
          <span class="module-caret">{{ expanded.includes(item.key) ? '▾' : '▸' }}</span>
        </button>
        <span class="module-track">
          <i :style="{ width: `${Math.min(100, item.load)}%` }"></i>
          <em :style="{ left: `${Math.min(100, item.load)}%` }" aria-hidden="true"></em>
        </span>
        <p v-if="expanded.includes(item.key)" class="module-detail">{{ t(item.detailKey) }}</p>
      </li>
      <li v-if="!modules.length" class="module-empty">{{ t('console.noData') }}</li>
    </ul>
  </section>
</template>

<style scoped>
.module-monitor {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  min-width: 0;
}

.module-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
  gap: 10px;
  align-content: start;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
}

.module-item {
  display: grid;
  gap: 6px;
  padding: 9px 11px 11px;
  border: 1px solid rgba(0, 245, 255, 0.14);
  border-left: 2px solid rgba(0, 245, 255, 0.22);
  border-radius: 6px;
  background: linear-gradient(180deg, rgba(16, 28, 66, 0.5), rgba(7, 11, 26, 0.42));
  transition: border-color 0.2s ease, background 0.2s ease, box-shadow 0.25s ease;
}

.module-item:hover {
  border-left-color: var(--neon-cyan);
  background: linear-gradient(90deg, rgba(0, 245, 255, 0.08), transparent 76%);
  box-shadow: inset 0 0 22px -18px rgba(0, 245, 255, 1);
}

.module-head {
  display: grid;
  grid-template-columns: 10px minmax(0, 1fr) auto 14px;
  gap: 8px;
  align-items: center;
  padding: 0;
  border: 0;
  background: none;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}

.module-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-muted);
}

.status-online {
  background: var(--success);
  box-shadow: 0 0 0 3px rgba(0, 245, 184, 0.16);
}

.status-warn {
  background: var(--warning);
}

.status-error {
  background: var(--danger);
}

.status-idle {
  background: var(--text-muted);
}

.module-name {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.module-value {
  color: var(--cyan);
  font-family: var(--mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}

.module-caret {
  color: var(--text-muted);
  font-size: 10px;
}

.module-track {
  position: relative;
  display: block;
  height: 3px;
  margin-left: 18px;
  overflow: hidden;
  border-radius: 2px;
  background: rgba(22, 54, 83, 0.8);
}

.module-track i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--electric-blue), var(--neon-cyan), var(--plasma-violet));
  background-size: 200% 100%;
  box-shadow: 0 0 12px -3px var(--cyan);
  transition: width 0.4s ease;
  animation: energy-flow 7.5s linear infinite;
}

.module-track em {
  position: absolute;
  top: 50%;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--ice-blue);
  box-shadow: 0 0 8px var(--ice-blue);
  transform: translate(-50%, -50%);
  animation: module-dot 3.4s ease-in-out infinite;
}

:root[data-theme='dark'] .status-online {
  box-shadow: 0 0 10px -2px var(--success);
}

:root[data-theme='dark'] .status-warn {
  box-shadow: 0 0 10px -2px var(--warning);
}

:root[data-theme='dark'] .status-error {
  box-shadow: 0 0 10px -2px var(--danger);
}

.module-detail {
  margin: 2px 0 0 18px;
  color: var(--text-muted);
  font-size: 11px;
  line-height: 1.5;
}

.module-empty {
  color: var(--text-muted);
  font-size: 12px;
}

@media (prefers-reduced-motion: reduce) {
  .module-track i,
  .module-track em {
    animation: none;
    transition: none;
  }
}

@keyframes module-dot {
  0%,
  100% {
    opacity: 0.45;
    transform: translate(-50%, -50%) scale(0.8);
  }
  50% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1.15);
  }
}
</style>
