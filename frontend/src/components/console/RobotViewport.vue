<script setup lang="ts">
import { computed } from 'vue'

import type { SimulatedTelemetry } from '../../services/consoleData'

const props = defineProps<{
  identity: { name: string; unit: string; model: string; platform: string }
  telemetry: SimulatedTelemetry
  cpuPercent: number
  memoryPercent: number
  connection: 'online' | 'degraded' | 'offline'
  runningTasks: number
  tokenTotal: number
  simulatedNote: string
}>()

const statusLabel = computed(() => props.connection.toUpperCase())

const gauges = computed(() => [
  { key: 'CPU', value: Math.round(props.cpuPercent), tone: 'cyan', simulated: false },
  { key: 'MEM', value: Math.round(props.memoryPercent), tone: 'violet', simulated: false },
  {
    key: 'TEMP',
    value: Math.round(props.telemetry.temperatureC),
    tone: 'amber',
    simulated: true,
  },
  {
    key: 'PWR',
    value: Math.round(props.telemetry.batteryPercent),
    tone: 'green',
    simulated: true,
  },
])
</script>

<template>
  <section class="hud-panel robot-viewport" aria-label="robot viewport">
    <div class="viewport-stage">
      <div class="stage-grid" aria-hidden="true"></div>
      <div class="stage-halo" aria-hidden="true"></div>
      <div class="stage-sweep" aria-hidden="true"></div>
      <div class="stage-scan" aria-hidden="true"></div>
      <span class="corner tl" aria-hidden="true"></span>
      <span class="corner tr" aria-hidden="true"></span>
      <span class="corner bl" aria-hidden="true"></span>
      <span class="corner br" aria-hidden="true"></span>

      <!-- 全息刻度环：两层反向旋转 -->
      <svg class="holo-rings" viewBox="0 0 520 520" aria-hidden="true">
        <defs>
          <linearGradient id="ringCyan" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#00f5ff" stop-opacity="0.9" />
            <stop offset="60%" stop-color="#1677ff" stop-opacity="0.5" />
            <stop offset="100%" stop-color="#8b5cff" stop-opacity="0.25" />
          </linearGradient>
          <linearGradient id="ringViolet" x1="1" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#ff38d1" stop-opacity="0.55" />
            <stop offset="100%" stop-color="#8b5cff" stop-opacity="0.2" />
          </linearGradient>
        </defs>
        <circle class="ring-outer" cx="260" cy="260" r="206" />
        <circle class="ring-mid" cx="260" cy="260" r="176" />
        <circle class="ring-inner" cx="260" cy="260" r="148" />
        <circle class="ring-ticks" cx="260" cy="260" r="192" />
        <path class="ring-arc" d="M260 54 A206 206 0 0 1 466 260" />
        <path class="ring-arc violet" d="M54 260 A206 206 0 0 1 260 466" />
        <ellipse class="ring-platform" cx="260" cy="452" rx="150" ry="26" />
      </svg>

      <svg class="robot-art" viewBox="0 0 420 470" role="img" aria-label="robot hologram">
        <defs>
          <linearGradient id="robotStroke" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#00f5ff" />
            <stop offset="48%" stop-color="#1677ff" />
            <stop offset="100%" stop-color="#8b5cff" />
          </linearGradient>
          <linearGradient id="robotVisor" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#00f5ff" stop-opacity="0.55" />
            <stop offset="100%" stop-color="#8b5cff" stop-opacity="0.12" />
          </linearGradient>
          <linearGradient id="robotCore" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#7df9ff" />
            <stop offset="100%" stop-color="#00f5ff" />
          </linearGradient>
          <filter id="robotBloom" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="7" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="armorCyan" x1="0" y1="0" x2="0.4" y2="1">
            <stop offset="0%" stop-color="#00f5ff" stop-opacity="0.3" />
            <stop offset="100%" stop-color="#1677ff" stop-opacity="0.08" />
          </linearGradient>
          <linearGradient id="armorViolet" x1="0" y1="0" x2="0.6" y2="1">
            <stop offset="0%" stop-color="#8b5cff" stop-opacity="0.26" />
            <stop offset="100%" stop-color="#ff38d1" stop-opacity="0.06" />
          </linearGradient>
          <linearGradient id="rimLight" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#ffffff" stop-opacity="0.95" />
            <stop offset="60%" stop-color="#7df9ff" stop-opacity="0.6" />
            <stop offset="100%" stop-color="#00f5ff" stop-opacity="0.15" />
          </linearGradient>
        </defs>

        <!-- 半透明机械装甲：建立体积与材质 -->
        <g class="art-armor" aria-hidden="true">
          <path d="M163 78 L183 52 L237 52 L257 78 L257 106 L242 128 L178 128 L163 106 Z" fill="url(#armorCyan)" />
          <path d="M177 84 L243 84 L235 110 L185 110 Z" fill="url(#armorViolet)" />
          <path d="M96 176 L130 158 L186 166 L210 158 L234 166 L290 158 L324 176 L310 206 L286 198 L264 214 L210 206 L156 214 L134 198 L110 206 Z" fill="url(#armorCyan)" opacity="0.75" />
          <path d="M156 214 L210 206 L264 214 L276 288 L246 336 L174 336 L144 288 Z" fill="url(#armorViolet)" opacity="0.7" />
          <path d="M186 246 L234 246 L228 292 L192 292 Z" fill="url(#armorCyan)" opacity="0.85" />
        </g>

        <!-- 能量导管：核心 → 肩部，虚线流动 -->
        <g class="art-conduit" aria-hidden="true">
          <path d="M210 266 L192 236 L182 202" />
          <path d="M210 266 L228 236 L238 202" />
          <path d="M210 292 L210 316 L196 344" />
          <path d="M210 292 L210 316 L224 344" />
        </g>

        <!-- 泛光层：同一轮廓的模糊副本，制造体积光 -->
        <g class="art-bloom" filter="url(#robotBloom)" aria-hidden="true">
          <path d="M163 78 L183 52 L237 52 L257 78 L257 106 L242 128 L178 128 L163 106 Z" />
          <path d="M96 176 L130 158 L186 166 L210 158 L234 166 L290 158 L324 176 L310 206 L286 198 L264 214 L210 206 L156 214 L134 198 L110 206 Z" />
          <path d="M156 214 L210 206 L264 214 L276 288 L246 336 L174 336 L144 288 Z" />
          <circle cx="210" cy="268" r="17" />
        </g>

        <g class="art-frame" fill="none" stroke-width="1.2">
          <path d="M210 16 L210 44" />
          <path d="M198 30 L210 16 L222 30" />
          <circle cx="210" cy="14" r="3.6" class="art-node core" />

          <path d="M163 78 L183 52 L237 52 L257 78 L257 106 L242 128 L178 128 L163 106 Z" />
          <path d="M183 52 L210 44 L237 52" />
          <path d="M177 84 L243 84 L235 110 L185 110 Z" class="art-visor" fill="url(#robotVisor)" />
          <path d="M188 92 L232 92" />
          <path d="M190 100 L226 100" class="art-dim" />
          <path d="M166 92 L172 92 M166 100 L172 100 M248 92 L254 92 M248 100 L254 100" class="art-dim" />

          <path d="M196 128 L196 146 M224 128 L224 146" />
          <path d="M186 146 L234 146 L234 158 L186 158 Z" />

          <path d="M96 176 L130 158 L186 166 L210 158 L234 166 L290 158 L324 176 L310 206 L286 198 L264 214 L210 206 L156 214 L134 198 L110 206 Z" />
          <path d="M134 198 L130 158 M286 198 L290 158" class="art-dim" />
          <circle cx="120" cy="196" r="8" class="art-node" />
          <circle cx="300" cy="196" r="8" class="art-node" />

          <path d="M156 214 L210 206 L264 214 L276 288 L246 336 L174 336 L144 288 Z" />
          <path d="M174 336 L246 336 L240 372 L180 372 Z" />
          <path d="M176 226 L210 220 L244 226" />
          <path d="M186 246 L234 246 L228 292 L192 292 Z" class="art-dim" />

          <circle cx="210" cy="268" r="17" class="art-core" />
          <circle cx="210" cy="268" r="9" class="art-core-inner" />
          <circle cx="210" cy="268" r="24" class="art-core-halo" />
          <path d="M210 236 L210 251 M210 285 L210 300" class="art-dim" />
          <path d="M176 308 L244 308 M180 318 L240 318" class="art-dim" />

          <path d="M120 200 L104 260 L112 320 L128 356" />
          <path d="M104 260 L136 268" class="art-dim" />
          <circle cx="112" cy="322" r="6" class="art-node" />
          <path d="M128 356 L114 380 L128 392 L142 372 Z" class="art-dim" />

          <path d="M300 200 L316 260 L308 320 L292 356" />
          <path d="M316 260 L284 268" class="art-dim" />
          <circle cx="308" cy="322" r="6" class="art-node" />
          <path d="M292 356 L306 380 L292 392 L278 372 Z" class="art-dim" />

          <path d="M180 372 L156 404 L146 452" />
          <path d="M240 372 L264 404 L274 452" />
          <path d="M146 452 L128 458 L110 452" class="art-dim" />
          <path d="M274 452 L292 458 L310 452" class="art-dim" />
        </g>

        <!-- 边缘轮廓光：模拟来自左上方的冷光 -->
        <g class="art-rim" fill="none" aria-hidden="true">
          <path d="M163 78 L183 52" />
          <path d="M96 176 L130 158 L186 166" />
          <path d="M156 214 L210 206" />
          <path d="M120 200 L104 260 L112 320" />
          <path d="M180 372 L156 404" />
        </g>
      </svg>

      <!-- 数据定位标记 -->
      <span class="data-mark dm-1" aria-hidden="true">X-02</span>
      <span class="data-mark dm-2" aria-hidden="true">Y-11</span>
      <span class="data-mark dm-3" aria-hidden="true">Z-07</span>

      <!-- 定位标记与坐标 -->
      <span class="marker m-top" aria-hidden="true"></span>
      <span class="marker m-left" aria-hidden="true"></span>
      <span class="marker m-right" aria-hidden="true"></span>
      <span class="marker m-bottom" aria-hidden="true"></span>

      <div class="telemetry telemetry-left">
        <div v-for="gauge in gauges.slice(0, 2)" :key="gauge.key" class="telemetry-row">
          <span class="telemetry-key">{{ gauge.key }}</span>
          <span class="telemetry-bar">
            <i :class="`tone-${gauge.tone}`" :style="{ width: `${Math.min(100, gauge.value)}%` }"></i>
          </span>
          <span class="telemetry-value">{{ gauge.value }}%</span>
        </div>
      </div>

      <div class="telemetry telemetry-right">
        <div v-for="gauge in gauges.slice(2)" :key="gauge.key" class="telemetry-row">
          <span class="telemetry-key">{{ gauge.key }}</span>
          <span class="telemetry-bar">
            <i :class="`tone-${gauge.tone}`" :style="{ width: `${Math.min(100, gauge.value)}%` }"></i>
          </span>
          <span class="telemetry-value">{{ gauge.value }}{{ gauge.key === 'TEMP' ? '°' : '%' }}</span>
        </div>
      </div>

      <div class="viewport-footer">
        <span class="foot-id">{{ identity.unit }} / {{ identity.platform }}</span>
        <span class="foot-meta">TASKS {{ runningTasks }} · TOKENS {{ tokenTotal }}</span>
        <span class="foot-sim" :title="simulatedNote">
          POS {{ telemetry.position.x }}, {{ telemetry.position.y }}, {{ telemetry.position.z }}
        </span>
      </div>

      <span class="viewport-state" :class="`link-${connection}`">{{ statusLabel }}</span>
    </div>
  </section>
</template>

<style scoped>
.robot-viewport {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
  padding: 0;
  overflow: hidden;
  min-width: 0;
}

.viewport-stage {
  position: relative;
  display: grid;
  place-items: center;
  min-height: 460px;
  padding: 18px;
  overflow: hidden;
  border-radius: 8px;
  background:
    radial-gradient(circle at 50% 46%, rgba(0, 245, 255, 0.14), transparent 46%),
    radial-gradient(circle at 50% 100%, rgba(139, 92, 255, 0.2), transparent 58%),
    linear-gradient(180deg, rgba(4, 6, 18, 0.9), rgba(3, 4, 11, 0.96));
}

.stage-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(0, 245, 255, 0.1) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 245, 255, 0.1) 1px, transparent 1px),
    linear-gradient(rgba(139, 92, 255, 0.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(139, 92, 255, 0.06) 1px, transparent 1px);
  background-size: 34px 34px, 34px 34px, 170px 170px, 170px 170px;
  mask-image: radial-gradient(circle at 50% 48%, #000 42%, transparent 80%);
  -webkit-mask-image: radial-gradient(circle at 50% 48%, #000 42%, transparent 80%);
}

.stage-halo {
  position: absolute;
  top: 50%;
  left: 50%;
  width: min(560px, 92%);
  aspect-ratio: 1;
  background:
    radial-gradient(circle, rgba(0, 245, 255, 0.22) 0%, rgba(22, 119, 255, 0.12) 34%, transparent 62%),
    radial-gradient(circle at 62% 68%, rgba(255, 56, 209, 0.16) 0%, transparent 52%);
  filter: blur(6px);
  transform: translate(-50%, -50%);
  will-change: transform, opacity;
  animation: hologram-breathe 6.5s ease-in-out infinite;
  pointer-events: none;
}

.stage-scan {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 120px;
  background: linear-gradient(180deg, transparent, rgba(0, 245, 255, 0.2), transparent);
  will-change: transform;
  transform: translateY(-140px);
  animation: viewport-scan 6s linear infinite;
  pointer-events: none;
}

/* 侧向巡游光带：给全息投影补一层体积光 */
.stage-sweep {
  position: absolute;
  top: -24%;
  bottom: -24%;
  width: 96px;
  background: linear-gradient(90deg, transparent, rgba(0, 245, 255, 0.14), transparent);
  filter: blur(2px);
  will-change: transform, opacity;
  transform: rotate(12deg) translateX(-340px);
  animation: stage-sweep-x 13s ease-in-out infinite;
  pointer-events: none;
}

.corner {
  position: absolute;
  width: 22px;
  height: 22px;
  border: 1px solid var(--neon-cyan);
  box-shadow: 0 0 12px -2px rgba(0, 245, 255, 0.9);
}

.corner.tl {
  top: 10px;
  left: 10px;
  border-right: 0;
  border-bottom: 0;
}

.corner.tr {
  top: 10px;
  right: 10px;
  border-left: 0;
  border-bottom: 0;
}

.corner.bl {
  bottom: 10px;
  left: 10px;
  border-right: 0;
  border-top: 0;
}

.corner.br {
  right: 10px;
  bottom: 10px;
  border-left: 0;
  border-top: 0;
}

.holo-rings {
  position: absolute;
  top: 50%;
  left: 50%;
  width: min(560px, 96%);
  aspect-ratio: 1;
  transform: translate(-50%, -50%);
  pointer-events: none;
}

.ring-outer,
.ring-mid,
.ring-inner,
.ring-ticks,
.ring-arc,
.ring-platform {
  fill: none;
  stroke-linecap: round;
}

.ring-outer {
  stroke: url(#ringCyan);
  stroke-width: 1.1;
  stroke-dasharray: 3 9;
  transform-origin: 260px 260px;
  will-change: transform;
  animation: hud-rotate 42s linear infinite;
}

.ring-mid {
  stroke: url(#ringViolet);
  stroke-width: 0.9;
  stroke-dasharray: 26 14;
  transform-origin: 260px 260px;
  will-change: transform;
  animation: hud-rotate-reverse 34s linear infinite;
}

.ring-inner {
  stroke: rgba(0, 245, 255, 0.22);
  stroke-width: 0.8;
  stroke-dasharray: 2 6;
  transform-origin: 260px 260px;
  animation: hud-rotate 58s linear infinite;
}

.ring-ticks {
  stroke: rgba(125, 249, 255, 0.5);
  stroke-width: 6;
  stroke-dasharray: 1 17;
  transform-origin: 260px 260px;
  animation: hud-rotate-reverse 90s linear infinite;
}

.ring-arc {
  stroke: var(--neon-cyan);
  stroke-width: 2.2;
  filter: drop-shadow(0 0 8px rgba(0, 245, 255, 0.9));
  transform-origin: 260px 260px;
  will-change: transform;
  animation: hud-rotate 18s linear infinite;
}

.ring-arc.violet {
  stroke: var(--plasma-violet);
  filter: drop-shadow(0 0 10px rgba(139, 92, 255, 0.9));
  animation: hud-rotate-reverse 24s linear infinite;
}

.ring-platform {
  stroke: rgba(0, 245, 255, 0.4);
  stroke-width: 1;
  filter: drop-shadow(0 0 14px rgba(0, 245, 255, 0.45));
}

.robot-art {
  position: relative;
  width: min(420px, 74%);
  max-height: 100%;
  filter: drop-shadow(0 0 26px rgba(0, 245, 255, 0.45))
    drop-shadow(0 0 70px rgba(139, 92, 255, 0.24));
  animation: hologram-float 7.5s ease-in-out infinite;
}

.art-bloom {
  fill: none;
  stroke: rgba(0, 245, 255, 0.5);
  stroke-width: 2.4;
  opacity: 0.5;
}

/* 装甲填充：半透明玻璃金属，叠加轮廓 */
.art-armor path {
  stroke: rgba(0, 245, 255, 0.32);
  stroke-width: 0.8;
}

/* 能量导管：虚线沿路径滚动 */
.art-conduit path {
  fill: none;
  stroke: rgba(125, 249, 255, 0.9);
  stroke-width: 1.4;
  stroke-linecap: round;
  stroke-dasharray: 4 9;
  filter: drop-shadow(0 0 6px rgba(0, 245, 255, 0.95));
  animation: conduit-flow 2.8s linear infinite;
}

/* 边缘轮廓光 */
.art-rim path {
  stroke: url(#rimLight);
  stroke-width: 2;
  stroke-linecap: round;
  filter: drop-shadow(0 0 7px rgba(255, 255, 255, 0.5));
}

.data-mark {
  position: absolute;
  padding: 1px 5px;
  border: 1px solid rgba(125, 249, 255, 0.45);
  border-radius: 3px;
  color: var(--ice-blue);
  background: rgba(3, 4, 11, 0.72);
  box-shadow: 0 0 14px -6px rgba(0, 245, 255, 0.95);
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.1em;
  pointer-events: none;
}

/* 状态灯内嵌到全息区右上角，替代原面板标题栏 */
.viewport-state {
  position: absolute;
  top: 12px;
  right: 14px;
  padding: 2px 8px;
  border: 1px solid rgba(0, 245, 255, 0.32);
  border-radius: 3px;
  color: var(--ice-blue);
  background: rgba(3, 4, 11, 0.7);
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  box-shadow: inset 0 0 14px -10px rgba(0, 245, 255, 0.95);
  pointer-events: none;
}

.dm-1 {
  top: 26%;
  left: 12%;
}

.dm-2 {
  top: 62%;
  right: 11%;
}

.dm-3 {
  bottom: 22%;
  left: 18%;
}

.art-frame {
  stroke: url(#robotStroke);
}

.art-dim {
  stroke: rgba(125, 249, 255, 0.42);
}

.art-visor {
  stroke: rgba(125, 249, 255, 0.95);
}

.art-node {
  fill: rgba(3, 4, 11, 0.9);
  stroke: var(--neon-cyan);
  filter: drop-shadow(0 0 7px rgba(0, 245, 255, 0.95));
}

.art-node.core {
  fill: var(--ice-blue);
}

.art-core {
  fill: rgba(0, 245, 255, 0.12);
  stroke: var(--neon-cyan);
  filter: drop-shadow(0 0 12px rgba(0, 245, 255, 0.9));
}

.art-core-inner {
  fill: url(#robotCore);
  stroke: none;
  animation: core-pulse 2.4s ease-in-out infinite;
}

.art-core-halo {
  fill: none;
  stroke: rgba(255, 56, 209, 0.55);
  stroke-width: 0.8;
  stroke-dasharray: 4 6;
  transform-origin: 210px 268px;
  animation: hud-rotate 12s linear infinite;
}

.marker {
  position: absolute;
  width: 16px;
  height: 16px;
  border: 1px solid rgba(125, 249, 255, 0.6);
  pointer-events: none;
}

.marker::before,
.marker::after {
  position: absolute;
  content: '';
  background: rgba(125, 249, 255, 0.55);
}

.marker::before {
  top: 50%;
  left: -6px;
  width: 26px;
  height: 1px;
}

.marker::after {
  top: -6px;
  left: 50%;
  width: 1px;
  height: 26px;
}

.m-top {
  top: 42px;
  left: 50%;
}

.m-left {
  top: 50%;
  left: 42px;
}

.m-right {
  top: 50%;
  right: 42px;
}

.m-bottom {
  bottom: 64px;
  left: 50%;
}

.telemetry {
  position: absolute;
  display: grid;
  gap: 8px;
  width: 170px;
}

.telemetry-left {
  top: 72px;
  left: 16px;
}

.telemetry-right {
  top: 72px;
  right: 16px;
}

.telemetry-row {
  display: grid;
  grid-template-columns: 32px minmax(0, 1fr) 44px;
  gap: 8px;
  align-items: center;
  font-size: 10px;
}

.telemetry-key {
  color: var(--text-label);
  font-family: var(--mono);
}

.telemetry-bar {
  position: relative;
  height: 4px;
  overflow: hidden;
  border-radius: 2px;
  background: rgba(10, 18, 48, 0.9);
  box-shadow: inset 0 0 8px -4px rgba(0, 245, 255, 0.8);
}

.telemetry-bar i {
  display: block;
  height: 100%;
  transition: width 0.45s ease;
}

.telemetry-bar .tone-cyan {
  background: linear-gradient(90deg, var(--neon-cyan), var(--ice-blue));
  box-shadow: 0 0 12px 0 rgba(0, 245, 255, 0.85);
}

.telemetry-bar .tone-violet {
  background: linear-gradient(90deg, var(--plasma-violet), var(--neon-magenta));
  box-shadow: 0 0 12px 0 rgba(139, 92, 255, 0.85);
}

.telemetry-bar .tone-amber {
  background: linear-gradient(90deg, var(--amber-alert), #ff8f3d);
  box-shadow: 0 0 12px 0 rgba(255, 181, 71, 0.85);
}

.telemetry-bar .tone-green {
  background: linear-gradient(90deg, var(--cyber-green), #5cffd0);
  box-shadow: 0 0 12px 0 rgba(0, 255, 178, 0.85);
}

.telemetry-value {
  color: var(--ice-blue);
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  text-align: right;
  text-shadow: 0 0 10px rgba(0, 245, 255, 0.6);
}

.viewport-footer {
  position: absolute;
  right: 16px;
  bottom: 12px;
  left: 16px;
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 10px;
}

.foot-id {
  color: var(--ice-blue);
  overflow-wrap: anywhere;
}

.foot-sim {
  color: var(--amber-alert);
  text-shadow: 0 0 10px rgba(255, 181, 71, 0.45);
}

.link-online {
  border-color: rgba(0, 255, 178, 0.5) !important;
  color: var(--cyber-green) !important;
}

.link-degraded {
  border-color: rgba(255, 181, 71, 0.5) !important;
  color: var(--amber-alert) !important;
}

.link-offline {
  border-color: rgba(255, 79, 163, 0.5) !important;
  color: var(--laser-pink) !important;
}

@keyframes viewport-scan {
  from {
    transform: translateY(-140px);
  }
  to {
    transform: translateY(660px);
  }
}

@keyframes core-pulse {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@keyframes hud-rotate {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

@keyframes hud-rotate-reverse {
  from {
    transform: rotate(360deg);
  }
  to {
    transform: rotate(0deg);
  }
}

@keyframes hologram-breathe {
  0%,
  100% {
    opacity: 0.7;
    transform: translate(-50%, -50%) scale(0.98);
  }
  50% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1.03);
  }
}

@keyframes hologram-float {
  0%,
  100% {
    transform: translateY(-4px);
  }
  50% {
    transform: translateY(4px);
  }
}

@keyframes stage-sweep-x {
  0% {
    opacity: 0;
    transform: rotate(12deg) translateX(-340px);
  }
  30% {
    opacity: 0.9;
  }
  70% {
    opacity: 0.75;
  }
  100% {
    opacity: 0;
    transform: rotate(12deg) translateX(430px);
  }
}

@keyframes conduit-flow {
  from {
    stroke-dashoffset: 0;
  }
  to {
    stroke-dashoffset: -26;
  }
}

@media (prefers-reduced-motion: reduce) {
  .stage-scan,
  .stage-sweep,
  .art-core-inner,
  .art-core-halo,
  .art-conduit path,
  .ring-outer,
  .ring-mid,
  .ring-inner,
  .ring-ticks,
  .ring-arc,
  .stage-halo,
  .robot-art {
    animation: none;
  }
}

@media (max-width: 1400px) {
  .telemetry {
    width: 146px;
  }
}

@media (max-width: 1180px) {
  .telemetry-left,
  .telemetry-right {
    display: none;
  }
}
</style>
