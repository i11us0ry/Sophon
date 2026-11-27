<script setup lang="ts">
import { computed } from 'vue'

type AgentRole =
  | 'mainagent'
  | 'planner'
  | 'worker'
  | 'system'
  | 'reviewer'
  | 'writer'
  | 'retest'
  | 'policy'
  | 'profile'
type AgentStatus =
  | 'idle'
  | 'running'
  | 'waiting'
  | 'completed'
  | 'failed'
  | 'paused'
  | 'stopped'
  | 'blocked'
  | 'exhausted'
type WorkerClass = 'recon' | 'audit' | 'exploit' | 'verify' | 'general'

const props = withDefaults(
  defineProps<{
    role?: AgentRole
    status?: AgentStatus
    workerClass?: WorkerClass
    size?: 'sm' | 'md' | 'lg'
    accent?: string
  }>(),
  {
    role: 'worker',
    status: 'idle',
    workerClass: 'general',
    size: 'sm',
  },
)

const robotStyle = computed<Record<string, string>>(() =>
  props.accent ? { '--profile-accent': props.accent } : {},
)
</script>

<template>
  <span
    class="agent-robot"
    :class="[
      `role-${role}`,
      `status-${status}`,
      `worker-${workerClass}`,
      `size-${size}`,
    ]"
    :style="robotStyle"
    aria-hidden="true"
  >
    <span class="agent-robot-antenna"></span>
    <span class="agent-robot-head">
      <i class="agent-robot-eye eye-left"></i>
      <i class="agent-robot-eye eye-right"></i>
      <b class="agent-robot-visor"></b>
    </span>
    <span class="agent-robot-body"></span>
  </span>
</template>

<style scoped>
.agent-robot {
  --robot-color: #8b9aaa;
  --robot-accent: #03c3ec;
  --robot-status: #7b8794;
  --robot-glow: color-mix(in srgb, var(--robot-status) 46%, transparent);
  position: relative;
  display: inline-block;
  width: 22px;
  height: 22px;
  flex: 0 0 auto;
  color: var(--robot-color);
}

.agent-robot.size-md {
  width: 28px;
  height: 28px;
}

.agent-robot.size-lg {
  width: 48px;
  height: 48px;
}

.agent-robot-antenna {
  position: absolute;
  top: 0;
  left: 48%;
  width: 4%;
  height: 22%;
  border-radius: 1px;
  background: currentColor;
}

.agent-robot-antenna::before {
  position: absolute;
  top: -2px;
  left: 50%;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  content: '';
  background: var(--robot-status);
  box-shadow: 0 0 6px var(--robot-glow);
  transform: translateX(-50%);
}

.agent-robot-head {
  position: absolute;
  top: 19%;
  left: 7%;
  display: block;
  width: 86%;
  height: 52%;
  border: 1px solid currentColor;
  border-radius: 4px 4px 3px 3px;
  background: color-mix(in srgb, currentColor 12%, transparent);
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, currentColor 12%, transparent),
    0 0 5px color-mix(in srgb, currentColor 16%, transparent);
}

.agent-robot-eye {
  position: absolute;
  top: 33%;
  width: 17%;
  height: 18%;
  border-radius: 1px;
  background: var(--robot-status);
  box-shadow: 0 0 5px var(--robot-glow);
}

.agent-robot-eye.eye-left {
  left: 22%;
}

.agent-robot-eye.eye-right {
  right: 22%;
}

.agent-robot-visor {
  position: absolute;
  right: 23%;
  bottom: 17%;
  left: 23%;
  height: 1px;
  background: color-mix(in srgb, currentColor 55%, transparent);
}

.agent-robot-body {
  position: absolute;
  bottom: 0;
  left: 26%;
  display: block;
  width: 48%;
  height: 25%;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 16%, transparent);
}

.agent-robot-body::before,
.agent-robot-body::after {
  position: absolute;
  top: 20%;
  width: 24%;
  height: 58%;
  border: 1px solid currentColor;
  content: '';
  background: color-mix(in srgb, currentColor 9%, transparent);
}

.agent-robot-body::before {
  left: -30%;
  border-radius: 3px 1px 1px 3px;
}

.agent-robot-body::after {
  right: -30%;
  border-radius: 1px 3px 3px 1px;
}

.role-mainagent {
  --robot-color: #f0b94d;
  --robot-accent: #03c3ec;
}

.role-mainagent .agent-robot-head {
  border-radius: 6px 6px 3px 3px;
}

.role-mainagent .agent-robot-head::before {
  position: absolute;
  top: -5px;
  left: 50%;
  width: 42%;
  height: 5px;
  border: 1px solid currentColor;
  border-bottom: 0;
  border-radius: 4px 4px 0 0;
  content: '';
  background: color-mix(in srgb, var(--robot-accent) 12%, transparent);
  transform: translateX(-50%);
}

.role-mainagent .agent-robot-body::before,
.role-mainagent .agent-robot-body::after {
  top: 12%;
  width: 34%;
}

.role-planner {
  --robot-color: #55c7e8;
  --robot-accent: #7dd3fc;
}

.role-planner .agent-robot-head {
  left: 3%;
  width: 94%;
  border-radius: 46% 46% 3px 3px;
}

.role-planner .agent-robot-head::before {
  position: absolute;
  top: -4px;
  left: 50%;
  width: 68%;
  height: 5px;
  border: 1px solid color-mix(in srgb, currentColor 72%, transparent);
  border-bottom: 0;
  border-radius: 50% 50% 0 0;
  content: '';
  transform: translateX(-50%);
}

.role-planner .agent-robot-antenna::after {
  position: absolute;
  top: 0;
  left: -5px;
  width: 11px;
  height: 1px;
  content: '';
  background: currentColor;
  box-shadow:
    -1px -2px 0 -1px currentColor,
    1px -2px 0 -1px currentColor;
}

.role-worker {
  --robot-color: #ff9f43;
  --robot-accent: #ff5d5d;
}

.role-worker .agent-robot-head {
  top: 22%;
  left: 11%;
  width: 78%;
  height: 48%;
  border-radius: 3px;
  transform: skewX(-3deg);
}

.role-worker .agent-robot-eye {
  top: 38%;
  height: 13%;
  border-radius: 2px;
}

.role-worker .agent-robot-body {
  left: 31%;
  width: 38%;
}

.role-system {
  --robot-color: #8b9aaa;
}

.role-system .agent-robot-antenna {
  height: 18%;
}

.role-system .agent-robot-head {
  top: 16%;
  border-radius: 2px;
}

.role-system .agent-robot-eye.eye-right {
  display: none;
}

.role-system .agent-robot-eye.eye-left {
  left: 41%;
  width: 18%;
  height: 24%;
  border-radius: 50%;
}

.role-system .agent-robot-body {
  left: 20%;
  width: 60%;
  border-radius: 2px;
}

.role-reviewer {
  --robot-color: #34d399;
  --robot-accent: #a7f3d0;
}

.role-reviewer .agent-robot-head {
  left: 5%;
  width: 90%;
  border-radius: 8px 8px 3px 3px;
  clip-path: polygon(8% 0, 92% 0, 100% 35%, 82% 100%, 18% 100%, 0 35%);
}

.role-reviewer .agent-robot-head::before {
  position: absolute;
  top: 45%;
  left: 43%;
  width: 14%;
  height: 38%;
  border-right: 1px solid var(--robot-accent);
  border-bottom: 1px solid var(--robot-accent);
  content: '';
  transform: rotate(42deg);
}

.role-writer {
  --robot-color: #a78bfa;
  --robot-accent: #d8b4fe;
}

.role-writer .agent-robot-head {
  border-radius: 3px 8px 3px 8px;
}

.role-writer .agent-robot-head::after {
  position: absolute;
  top: -5px;
  right: 9%;
  width: 2px;
  height: 8px;
  content: '';
  background: var(--robot-accent);
  transform: rotate(32deg);
}

.role-writer .agent-robot-body {
  left: 22%;
  width: 56%;
}

.role-retest {
  --robot-color: #22d3ee;
  --robot-accent: #67e8f9;
}

.role-retest .agent-robot-head {
  border-radius: 50%;
}

.role-retest .agent-robot-head::after {
  position: absolute;
  top: -4px;
  right: -4px;
  width: 8px;
  height: 8px;
  border: 1.5px solid var(--robot-accent);
  border-left-color: transparent;
  border-radius: 50%;
  content: '';
}

.role-retest .agent-robot-antenna {
  height: 14%;
}

.role-policy {
  --robot-color: #d4a72c;
  --robot-accent: #fde68a;
}

.role-policy .agent-robot-head {
  top: 18%;
  left: 3%;
  width: 94%;
  height: 48%;
  border-radius: 2px;
}

.role-policy .agent-robot-eye {
  width: 9%;
  height: 36%;
  border-radius: 50%;
}

.role-policy .agent-robot-eye.eye-left {
  left: 36%;
}

.role-policy .agent-robot-eye.eye-right {
  right: 36%;
}

.role-policy .agent-robot-body::before,
.role-policy .agent-robot-body::after {
  top: -3px;
  width: 36%;
  height: 2px;
  border: 0;
  background: currentColor;
}

.role-policy .agent-robot-body::before {
  left: -42%;
  transform: rotate(12deg);
}

.role-policy .agent-robot-body::after {
  right: -42%;
  transform: rotate(-12deg);
}

.role-profile {
  --robot-color: var(--profile-accent, #a78bfa);
  --robot-accent: color-mix(in srgb, var(--profile-accent, #a78bfa) 64%, white);
}

.role-profile .agent-robot-head {
  border-radius: 7px 7px 4px 4px;
}

.role-profile .agent-robot-head::before {
  position: absolute;
  top: -4px;
  left: 12%;
  width: 20%;
  height: 3px;
  content: '';
  background: var(--robot-accent);
  box-shadow: 8px 0 0 var(--robot-accent);
}

.worker-recon {
  --robot-color: #4cc9f0;
}

.worker-recon .agent-robot-head::after {
  position: absolute;
  top: 45%;
  left: -10%;
  width: 120%;
  height: 1px;
  content: '';
  background: var(--robot-status);
  box-shadow: 0 0 5px var(--robot-glow);
  opacity: 0.7;
}

.worker-audit {
  --robot-color: #34d399;
}

.worker-audit .agent-robot-head::after {
  position: absolute;
  top: 18%;
  right: 12%;
  width: 7px;
  height: 7px;
  border: 1px solid currentColor;
  border-radius: 50%;
  content: '';
}

.worker-exploit {
  --robot-color: #ff7043;
  --robot-accent: #ff3e1d;
}

.worker-exploit .agent-robot-head::after {
  position: absolute;
  top: 18%;
  left: 50%;
  width: 6px;
  height: 6px;
  border: 1px solid var(--robot-accent);
  border-radius: 50%;
  content: '';
  transform: translateX(-50%);
}

.worker-verify {
  --robot-color: #22d3ee;
}

.worker-verify .agent-robot-body::after {
  border-color: var(--robot-status);
  transform: skewX(-18deg);
}

.status-running {
  --robot-status: #26d9fa;
}

.status-waiting {
  --robot-status: #f0a43a;
}

.status-completed {
  --robot-status: #34d399;
}

.status-failed,
.status-blocked {
  --robot-status: #ff5d5d;
}

.status-paused {
  --robot-status: #fb923c;
}

.status-stopped,
.status-exhausted,
.status-idle {
  --robot-status: #7b8794;
}

.status-running .agent-robot-antenna::before {
  animation: agent-robot-signal 1.8s ease-in-out infinite;
}

.status-running .agent-robot-eye {
  animation: agent-robot-blink 4.8s ease-in-out infinite;
}

@keyframes agent-robot-signal {
  0%,
  100% {
    box-shadow: 0 0 4px var(--robot-glow);
  }
  50% {
    box-shadow: 0 0 10px var(--robot-status);
  }
}

@keyframes agent-robot-blink {
  0%,
  45%,
  50%,
  100% {
    opacity: 1;
  }
  47%,
  49% {
    opacity: 0.35;
  }
}

@media (prefers-reduced-motion: reduce) {
  .status-running .agent-robot-antenna::before,
  .status-running .agent-robot-eye {
    animation: none;
  }
}
</style>
