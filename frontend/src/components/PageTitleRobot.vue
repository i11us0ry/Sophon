<script setup lang="ts">
withDefaults(
  defineProps<{
    tone?:
      | 'sky'
      | 'mint'
      | 'orange'
      | 'red'
      | 'pink'
      | 'violet'
      | 'indigo'
      | 'amber'
      | 'teal'
      | 'lime'
      | 'green'
      | 'magenta'
      | 'slate'
      | 'cyan'
      | 'coral'
  }>(),
  {
    tone: 'sky',
  },
)
</script>

<template>
  <span class="page-title-robot" :class="`tone-${tone}`" aria-hidden="true">
    <i class="page-title-robot-antenna"></i>
    <i class="page-title-robot-face">
      <b></b>
      <b></b>
      <em></em>
    </i>
    <i class="page-title-robot-body"></i>
  </span>
</template>

<style scoped>
:global(.page-heading-with-robot) {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

:global(.page-heading-with-robot > div) {
  min-width: 0;
}

.page-title-robot {
  --title-robot-tone: #55c7e8;
  position: relative;
  display: block;
  flex: 0 0 32px;
  width: 32px;
  height: 34px;
  color: var(--title-robot-tone);
}

.page-title-robot.tone-sky,
.page-title-robot.tone-cyan { --title-robot-tone: #38bdf8; }
.page-title-robot.tone-mint { --title-robot-tone: #34d399; }
.page-title-robot.tone-orange { --title-robot-tone: #fb923c; }
.page-title-robot.tone-red,
.page-title-robot.tone-coral { --title-robot-tone: #ef4444; }
.page-title-robot.tone-pink { --title-robot-tone: #f472b6; }
.page-title-robot.tone-violet { --title-robot-tone: #a78bfa; }
.page-title-robot.tone-indigo { --title-robot-tone: #6366f1; }
.page-title-robot.tone-amber { --title-robot-tone: #fbbf24; }
.page-title-robot.tone-teal { --title-robot-tone: #14b8a6; }
.page-title-robot.tone-lime { --title-robot-tone: #84cc16; }
.page-title-robot.tone-green { --title-robot-tone: #22c55e; }
.page-title-robot.tone-magenta { --title-robot-tone: #ec4899; }
.page-title-robot.tone-slate { --title-robot-tone: #94a3b8; }

.page-title-robot-antenna {
  position: absolute;
  top: 0;
  left: 15px;
  width: 1px;
  height: 6px;
  background: currentColor;
}

.page-title-robot-antenna::before {
  position: absolute;
  top: -2px;
  left: -2px;
  width: 4px;
  height: 4px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, currentColor 30%, transparent);
  box-shadow: 0 0 5px color-mix(in srgb, currentColor 45%, transparent);
}

.page-title-robot-face {
  position: absolute;
  top: 5px;
  left: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  width: 28px;
  height: 19px;
  border: 1px solid currentColor;
  border-radius: 5px;
  background: color-mix(in srgb, currentColor 7%, var(--surface));
}

.page-title-robot-face b {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 4px currentColor;
  animation: title-robot-blink 3.8s ease-in-out infinite;
}

.page-title-robot-face em {
  position: absolute;
  bottom: 2px;
  width: 6px;
  height: 1px;
  background: currentColor;
}

.page-title-robot-body {
  position: absolute;
  bottom: 1px;
  left: 7px;
  width: 19px;
  height: 8px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 3px 3px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

@keyframes title-robot-blink {
  0%,
  44%,
  50%,
  100% {
    opacity: 1;
  }
  47% {
    opacity: 0.35;
  }
}

@media (prefers-reduced-motion: reduce) {
  .page-title-robot-face b {
    animation: none;
  }
}
</style>
