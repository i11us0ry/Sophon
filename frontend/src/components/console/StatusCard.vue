<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

const props = withDefaults(
  defineProps<{
    index: string
    title: string
    value: string
    unit?: string
    hint?: string
    tone?: 'cyan' | 'blue' | 'violet' | 'magenta' | 'success' | 'warning' | 'danger'
    trend?: number[]
    badge?: string
    simulated?: boolean
    to?: string
  }>(),
  {
    tone: 'cyan',
    trend: () => [],
    unit: '',
    hint: '',
    badge: '',
    simulated: false,
    to: '',
  },
)

const spark = computed(() => {
  const points = props.trend
  if (points.length < 2) {
    return { line: '', area: '', last: null as { x: number; y: number } | null }
  }
  const max = Math.max(...points, 1)
  const line = points
    .map((point, index) => {
      const x = (index / (points.length - 1)) * 100
      const y = 26 - (point / max) * 20
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
  const last = {
    x: 100,
    y: 26 - (points[points.length - 1] / max) * 20,
  }
  return { line, area: `${line} L100,28 L0,28 Z`, last }
})
</script>

<template>
  <component
    :is="to ? RouterLink : 'article'"
    class="hud-panel status-card"
    :class="[`tone-${tone}`, { 'is-link': Boolean(to) }]"
    :to="to || undefined"
  >
    <header class="hud-panel-head">
      <span class="hud-index">{{ index }}</span>
      <h3>{{ title }}</h3>
      <span v-if="simulated" class="hud-tag simulated">SIMULATED</span>
      <span v-else-if="badge" class="hud-tag">{{ badge }}</span>
    </header>
    <div class="status-body">
      <div class="status-value">
        <strong>{{ value }}</strong>
        <small v-if="unit">{{ unit }}</small>
      </div>
      <svg v-if="sparkPath" class="status-spark" viewBox="0 0 100 28" preserveAspectRatio="none">
        <path :d="sparkPath" />
      </svg>
    </div>
    <svg
      v-if="spark.line"
      class="status-spark"
      viewBox="0 0 100 28"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient :id="`sparkFill-${index}`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--console-tone, var(--neon-cyan))" stop-opacity="0.32" />
          <stop offset="100%" stop-color="var(--console-tone, var(--neon-cyan))" stop-opacity="0" />
        </linearGradient>
      </defs>
      <path class="spark-area" :d="spark.area" :fill="`url(#sparkFill-${index})`" />
      <path class="spark-line" :d="spark.line" />
      <path class="spark-stream" :d="spark.line" />
      <circle
        v-if="spark.last"
        class="spark-dot"
        :cx="spark.last.x"
        :cy="spark.last.y"
        r="1.6"
      />
    </svg>
    <p v-if="hint" class="status-hint">{{ hint }}</p>
    <span v-if="to" class="status-more" aria-hidden="true">→</span>
  </component>
</template>

<style scoped>
.status-card {
  display: grid;
  gap: 8px;
  min-width: 0;
  background-image:
    radial-gradient(
      220px 120px at 12% -20%,
      color-mix(in srgb, var(--console-tone, var(--cyan)) 22%, transparent),
      transparent 70%
    ),
    linear-gradient(158deg, rgba(12, 22, 56, 0.9) 0%, rgba(6, 10, 26, 0.88) 52%, rgba(9, 14, 38, 0.9) 100%);
  transition: transform 0.25s ease;
}

.status-card:hover {
  transform: translateY(-2px);
}

.status-card::before {
  position: absolute;
  top: 10px;
  bottom: 10px;
  left: -1px;
  width: 2px;
  content: '';
  border-radius: 2px;
  background: var(--console-tone, var(--cyan));
  box-shadow: 0 0 14px 1px var(--console-tone, var(--cyan));
  opacity: 0.95;
}

.status-body {
  display: flex;
  gap: 12px;
  align-items: flex-end;
  justify-content: space-between;
  min-width: 0;
}

.status-value {
  display: flex;
  gap: 6px;
  align-items: baseline;
  min-width: 0;
}

.status-value strong {
  font-family: var(--mono);
  font-size: 24px;
  font-weight: 700;
  letter-spacing: 0;
  font-variant-numeric: tabular-nums;
  color: var(--console-tone, var(--cyan));
  overflow-wrap: anywhere;
}

.status-value small {
  color: var(--text-muted);
  font-size: 11px;
}

.status-spark {
  width: 100%;
  height: 34px;
  overflow: visible;
}

.spark-line {
  fill: none;
  stroke: var(--console-tone, var(--cyan));
  stroke-width: 1.1;
  opacity: 0.55;
}

/* 卡片底部数据流动：与 Token 趋势图同一套虚线语言 */
.spark-stream {
  fill: none;
  stroke: var(--console-tone, var(--cyan));
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-dasharray: 2.6 12;
  opacity: 0.95;
  filter: drop-shadow(0 0 5px currentColor);
  animation: status-flow 3.2s linear infinite;
}

.spark-dot {
  fill: var(--console-tone, var(--cyan));
  filter: drop-shadow(0 0 4px currentColor);
  animation: status-dot 2.4s ease-in-out infinite;
}

.status-hint {
  margin: 0;
  color: var(--text-secondary);
  font-size: 11px;
  line-height: 1.5;
}

/* 可点击卡片：明确指向与反馈 */
.status-card.is-link {
  display: grid;
  color: inherit;
  text-decoration: none;
  cursor: pointer;
}

.status-card.is-link:hover {
  transform: translateY(-3px);
}

.status-more {
  position: absolute;
  top: 12px;
  right: 14px;
  color: var(--console-tone, var(--neon-cyan));
  font-family: var(--mono);
  font-size: 14px;
  text-shadow: 0 0 12px currentColor;
  transition: transform 0.2s ease;
}

.status-card.is-link:hover .status-more {
  transform: translateX(3px);
}

.tone-cyan {
  --console-tone: var(--cyan);
}

.tone-blue {
  --console-tone: var(--blue);
}

.tone-violet {
  --console-tone: var(--plasma-violet);
}

.tone-magenta {
  --console-tone: var(--magenta);
}

.tone-success {
  --console-tone: var(--success);
}

.tone-warning {
  --console-tone: var(--warning);
}

.tone-danger {
  --console-tone: var(--danger);
}

@keyframes status-flow {
  from {
    stroke-dashoffset: 0;
  }
  to {
    stroke-dashoffset: -29.2;
  }
}

@keyframes status-dot {
  0%,
  100% {
    opacity: 0.55;
    r: 1.4;
  }
  50% {
    opacity: 1;
    r: 1.9;
  }
}

/* 错峰：避免四张卡片同步闪烁 */
.status-card:nth-child(2n) .spark-stream {
  animation-duration: 3.8s;
}

.status-card:nth-child(3n) .spark-stream {
  animation-duration: 4.4s;
}

@media (prefers-reduced-motion: reduce) {
  .spark-stream,
  .spark-dot {
    animation: none;
  }
}
</style>
