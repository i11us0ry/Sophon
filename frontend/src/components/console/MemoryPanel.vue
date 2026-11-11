<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '../../i18n'
import { formatBytes } from '../../utils/format'

const props = defineProps<{
  memory: {
    percent: number
    used: number
    total: number
    source: string
    memoryWrites: number
    injections: number
  }
}>()

const { t } = useI18n()

const rows = computed(() => [
  {
    key: 'console.memory.writes',
    value: `${props.memory.memoryWrites}`,
    tone: 'cyan',
  },
  {
    key: 'console.memory.injections',
    value: `${props.memory.injections}`,
    tone: 'violet',
  },
])

const usedPercent = computed(() => Math.min(100, Math.max(0, props.memory.percent)))
</script>

<template>
  <section class="hud-panel memory-panel">
    <header class="hud-panel-head">
      <span class="hud-index">09</span>
      <h3>{{ t('console.system.title') }}</h3>
      <span class="hud-tag">{{ memory.source || 'HOST' }}</span>
    </header>
    <p class="memory-figure">
      <strong>{{ formatBytes(memory.used) }}</strong>
      <span>/ {{ formatBytes(memory.total) }}</span>
    </p>
    <span class="memory-track" :title="`${usedPercent.toFixed(1)}%`">
      <i :style="{ width: `${usedPercent}%` }"></i>
    </span>
    <ul class="memory-rows">
      <li v-for="row in rows" :key="row.key" :class="`tone-${row.tone}`">
        <span>{{ t(row.key) }}</span>
        <strong>{{ row.value }}</strong>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.memory-panel {
  display: grid;
  gap: 10px;
  align-content: start;
  min-width: 0;
}

.memory-figure {
  display: flex;
  gap: 6px;
  align-items: baseline;
  margin: 0;
  font-family: var(--mono);
}

.memory-figure strong {
  color: var(--cyan);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.memory-figure span {
  color: var(--text-muted);
  font-size: 11px;
}

.memory-track {
  position: relative;
  display: block;
  height: 5px;
  overflow: hidden;
  border-radius: 3px;
  background: rgba(22, 54, 83, 0.85);
}

.memory-track i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--electric-blue), var(--neon-cyan), var(--plasma-violet));
  background-size: 220% 100%;
  box-shadow: 0 0 16px 0 rgba(0, 245, 255, 0.8);
  transition: width 0.4s ease;
  animation: energy-flow 6.5s linear infinite;
}

.memory-rows {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.memory-rows li {
  position: relative;
  display: grid;
  overflow: hidden;
  gap: 2px;
  padding: 7px 9px;
  border: 1px solid rgba(0, 245, 255, 0.16);
  border-radius: 5px;
  background: linear-gradient(180deg, rgba(16, 28, 66, 0.5), rgba(7, 11, 26, 0.42));
}

.memory-rows li::after {
  position: absolute;
  top: 0;
  bottom: 0;
  left: -40%;
  width: 35%;
  content: '';
  background: linear-gradient(90deg, transparent, rgba(0, 245, 255, 0.22), transparent);
  transform: skewX(-18deg);
  animation: memory-scan 4.6s ease-in-out infinite;
  pointer-events: none;
}

.memory-rows li:nth-child(2)::after {
  background: linear-gradient(90deg, transparent, rgba(139, 92, 255, 0.26), transparent);
  animation-delay: 1.4s;
}

.memory-rows li span {
  color: var(--text-muted);
  font-size: 10px;
}

.memory-rows strong {
  font-family: var(--mono);
  font-size: 15px;
  font-variant-numeric: tabular-nums;
}

.tone-cyan strong {
  color: var(--neon-cyan);
  text-shadow: 0 0 12px rgba(0, 245, 255, 0.7);
}

.tone-violet strong {
  color: var(--plasma-violet);
  text-shadow: 0 0 12px rgba(139, 92, 255, 0.7);
}

@keyframes memory-scan {
  0%,
  55% {
    left: -40%;
  }
  100% {
    left: 110%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .memory-track i,
  .memory-rows li::after {
    animation: none;
    transition: none;
  }
}
</style>
