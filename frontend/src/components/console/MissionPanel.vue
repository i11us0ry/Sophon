<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '../../i18n'
import { formatRelative } from '../../utils/format'

const props = defineProps<{
  mission: { id: string; title: string; projectId: string; updatedAt: string } | null
  tasks: { running: number; completed: number; failed: number; conversations: number }
}>()

const { t } = useI18n()

const progress = computed(() => {
  const done = props.tasks.completed + props.tasks.failed
  const total = done + props.tasks.running
  return total > 0 ? Math.round((done / total) * 100) : 0
})
</script>

<template>
  <section class="hud-panel mission-panel">
    <header class="hud-panel-head">
      <span class="hud-index">07</span>
      <h3>{{ t('console.mission') }}</h3>
      <span v-if="mission" class="hud-tag">{{ formatRelative(mission.updatedAt) }}</span>
    </header>
    <template v-if="mission">
      <div class="mission-body">
        <p class="mission-title" :title="mission.title">{{ mission.title }}</p>
        <p class="mission-meta">
          <span>{{ t('console.mission.project') }} {{ mission.projectId.slice(0, 8) || '-' }}</span>
          <span>{{ t('console.mission.conversations') }} {{ tasks.conversations }}</span>
        </p>
        <span class="mission-track">
          <i :style="{ width: `${progress}%` }"></i>
          <em v-if="progress > 0" :style="{ left: `${progress}%` }" aria-hidden="true"></em>
        </span>
        <ul class="mission-stats">
          <li class="stat-running">
            <span>{{ t('console.mission.running') }}</span><strong>{{ tasks.running }}</strong>
          </li>
          <li class="stat-completed">
            <span>{{ t('console.mission.completed') }}</span><strong>{{ tasks.completed }}</strong>
          </li>
          <li class="stat-failed">
            <span>{{ t('console.mission.failed') }}</span><strong>{{ tasks.failed }}</strong>
          </li>
        </ul>
      </div>
    </template>
    <p v-else class="mission-empty">{{ t('console.mission.empty') }}</p>
  </section>
</template>

<style scoped>
.mission-panel {
  display: grid;
  gap: 10px;
  align-content: start;
  min-width: 0;
}

.mission-body {
  display: grid;
  gap: 9px;
  align-content: start;
}

.mission-title {
  margin: 0;
  padding-left: 8px;
  border-left: 2px solid var(--neon-magenta);
  overflow: hidden;
  color: var(--text-primary);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
  box-shadow: -2px 0 12px -2px var(--neon-magenta);
}

.mission-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 0;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
}

.mission-track {
  position: relative;
  display: block;
  height: 4px;
  overflow: hidden;
  border-radius: 2px;
  background: rgba(22, 54, 83, 0.85);
}

.mission-track i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--plasma-violet), var(--neon-cyan), var(--ice-blue));
  background-size: 220% 100%;
  box-shadow: 0 0 14px 0 rgba(0, 245, 255, 0.85);
  transition: width 0.4s ease;
  animation: energy-flow 5.5s linear infinite;
}

/* 进度端点：脉冲光标，强调"仍在推进" */
.mission-track em {
  position: absolute;
  top: 50%;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ice-blue);
  box-shadow: 0 0 10px var(--ice-blue);
  transform: translate(-50%, -50%);
  animation: mission-dot 2.8s ease-in-out infinite;
}

.mission-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.mission-stats li {
  display: grid;
  gap: 2px;
  padding: 6px 8px;
  border: 1px solid rgba(255, 56, 209, 0.14);
  border-radius: 5px;
  background: linear-gradient(180deg, rgba(38, 16, 52, 0.45), rgba(8, 6, 22, 0.4));
}

.mission-stats span {
  color: var(--text-muted);
  font-size: 10px;
}

.mission-stats strong {
  font-family: var(--mono);
  font-size: 15px;
  font-variant-numeric: tabular-nums;
  text-shadow: 0 0 12px currentColor;
}

.stat-running strong {
  color: var(--warning);
}

.stat-completed strong {
  color: var(--success);
}

.stat-failed strong {
  color: var(--danger);
}

.mission-empty {
  margin: 0;
  padding: 14px 0;
  color: var(--text-muted);
  font-size: 11px;
  text-align: center;
}

@media (prefers-reduced-motion: reduce) {
  .mission-track i,
  .mission-track em {
    animation: none;
    transition: none;
  }
}

@keyframes mission-dot {
  0%,
  100% {
    opacity: 0.55;
    transform: translate(-50%, -50%) scale(0.85);
  }
  50% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1.15);
  }
}
</style>
