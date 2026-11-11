<script setup lang="ts">
import { computed } from 'vue'

import { useI18n } from '../../i18n'

let flowChartSeq = 0

const props = withDefaults(
  defineProps<{
    points: number[]
    title?: string
    unit?: string
    tone?: 'cyan' | 'blue'
    simulated?: boolean
    promptTokens?: number
    completionTokens?: number
    contextPercent?: number
  }>(),
  {
    title: '',
    unit: '',
    tone: 'cyan',
    simulated: false,
    promptTokens: 0,
    completionTokens: 0,
    contextPercent: 0,
  },
)

const { t } = useI18n()
const uid = `flow-${(flowChartSeq += 1)}`
const strokeId = computed(() => `flowStroke-${uid}`)
const fillId = computed(() => `flowFill-${uid}`)

const geometry = computed(() => {
  const points = props.points.length > 1 ? props.points : [0, 0]
  const max = Math.max(...points, 1)
  const line = points
    .map((point, index) => {
      const x = (index / (points.length - 1)) * 100
      const y = 40 - (point / max) * 34
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
  const area = `${line} L100,40 L0,40 Z`
  const last = {
    x: 100,
    y: 40 - (points[points.length - 1] / max) * 34,
  }
  return { line, area, max, last }
})

const tokenSplit = computed(() => {
  const prompt = props.promptTokens
  const completion = props.completionTokens
  const total = Math.max(prompt + completion, 1)
  return {
    prompt,
    completion,
    promptPercent: Math.round((prompt / total) * 100),
  }
})

const contextPercent = computed(() => Math.min(100, Math.max(0, Math.round(props.contextPercent))))
</script>

<template>
  <section class="hud-panel data-flow">
    <header class="hud-panel-head">
      <span class="hud-index">05</span>
      <h3>{{ title || t('console.dataFlow') }}</h3>
      <span v-if="simulated" class="hud-tag simulated">SIMULATED</span>
    </header>
    <div class="flow-plot">
      <svg class="flow-chart" viewBox="0 0 100 42" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <linearGradient :id="strokeId" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#00f5ff" />
            <stop offset="55%" stop-color="#7df9ff" />
            <stop offset="100%" stop-color="#8b5cff" />
          </linearGradient>
          <linearGradient :id="fillId" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#00f5ff" stop-opacity="0.42" />
            <stop offset="100%" stop-color="#8b5cff" stop-opacity="0" />
          </linearGradient>
          <clipPath :id="`${uid}-clip`">
            <path :d="geometry.area" />
          </clipPath>
        </defs>
        <g class="flow-grid">
          <path d="M0,10 H100 M0,20 H100 M0,30 H100" />
        </g>
        <rect
          class="flow-area"
          x="0"
          y="0"
          width="100"
          height="42"
          :fill="`url(#${fillId})`"
          :clip-path="`url(#${uid}-clip)`"
        />
        <path class="flow-line" :d="geometry.line" :stroke="`url(#${strokeId})`" />
        <path class="flow-stream" :d="geometry.line" />
        <circle class="flow-dot" :cx="geometry.last.x" :cy="geometry.last.y" r="1.5" />
      </svg>
      <span class="flow-scan" aria-hidden="true"></span>
    </div>
    <div class="flow-chips">
      <span class="flow-chip">
        <i class="chip-dot prompt"></i>
        {{ t('console.flow.prompt') }} <strong>{{ tokenSplit.prompt.toLocaleString() }}</strong>
      </span>
      <span class="flow-chip">
        <i class="chip-dot completion"></i>
        {{ t('console.flow.completion') }} <strong>{{ tokenSplit.completion.toLocaleString() }}</strong>
      </span>
      <span class="flow-chip">
        {{ t('console.flow.context') }} <strong>{{ contextPercent }}%</strong>
      </span>
    </div>
    <footer class="flow-meta">
      <span>{{ t('console.peak') }} {{ geometry.max.toLocaleString() }}{{ unit }}</span>
      <span>{{ t('console.window') }} 24</span>
    </footer>
  </section>
</template>

<style scoped>
.data-flow {
  display: grid;
  gap: 8px;
  align-content: start;
  min-width: 0;
}

.flow-chart {
  width: 100%;
  height: 92px;
  overflow: visible;
}

.flow-plot {
  position: relative;
  min-width: 0;
  overflow: hidden;
}

/* 图表扫描带：缓慢横扫，数据为空时也保留实时采集质感 */
.flow-scan {
  position: absolute;
  top: -4%;
  bottom: -4%;
  left: -12%;
  width: 16%;
  background: linear-gradient(
    90deg,
    transparent,
    rgba(0, 245, 255, 0.09) 58%,
    rgba(125, 249, 255, 0.2) 100%
  );
  animation: flow-scan 6.4s ease-in-out infinite;
  pointer-events: none;
}

.flow-grid path {
  fill: none;
  stroke: rgba(22, 54, 83, 0.75);
  stroke-width: 0.4;
}

.flow-line {
  fill: none;
  stroke-width: 1.2;
  filter: drop-shadow(0 0 4px rgba(0, 245, 255, 0.85));
}

.flow-area {
  stroke: none;
}

/* 数据流动：虚线沿曲线滚动 */
.flow-stream {
  fill: none;
  stroke: var(--ice-blue);
  stroke-width: 1.6;
  stroke-linecap: round;
  stroke-dasharray: 3 14;
  opacity: 0.9;
  filter: drop-shadow(0 0 6px rgba(125, 249, 255, 0.95));
  animation: flow-dash 3.6s linear infinite;
}

.flow-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 2px;
}

.flow-chip {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  padding: 3px 8px;
  border: 1px solid rgba(0, 245, 255, 0.22);
  border-radius: 999px;
  background: rgba(0, 245, 255, 0.06);
  color: var(--text-muted);
  font-size: 10px;
}

.flow-chip strong {
  color: var(--ice-blue);
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  text-shadow: 0 0 10px rgba(125, 249, 255, 0.6);
}

.chip-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.chip-dot.prompt {
  background: var(--neon-cyan);
  box-shadow: 0 0 8px var(--neon-cyan);
}

.chip-dot.completion {
  background: var(--plasma-violet);
  box-shadow: 0 0 8px var(--plasma-violet);
}

/* 数据端点：脉冲提示实时采集位置 */
.flow-dot {
  fill: var(--ice-blue);
  filter: drop-shadow(0 0 5px rgba(125, 249, 255, 1));
  animation: flow-dot 2.6s ease-in-out infinite;
}

.flow-meta {
  display: flex;
  gap: 12px;
  justify-content: space-between;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
}

@keyframes flow-dash {
  from {
    stroke-dashoffset: 0;
  }
  to {
    stroke-dashoffset: -34;
  }
}

@keyframes flow-dot {
  0%,
  100% {
    opacity: 0.5;
    r: 1.2;
  }
  50% {
    opacity: 1;
    r: 1.9;
  }
}

@keyframes flow-scan {
  0%,
  18% {
    transform: translateX(0);
    opacity: 0;
  }
  32% {
    opacity: 0.9;
  }
  74%,
  100% {
    transform: translateX(680%);
    opacity: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .flow-stream,
  .flow-dot,
  .flow-scan {
    animation: none;
  }
}
</style>
