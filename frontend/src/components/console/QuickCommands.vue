<script setup lang="ts">
import { ref } from 'vue'

import { useI18n } from '../../i18n'
import { copyText } from '../../utils/clipboard'

const props = defineProps<{ paused: boolean; diagnostics: string }>()
const emit = defineEmits<{
  (event: 'refresh'): void
  (event: 'toggle-pause'): void
  (event: 'clear-log'): void
  (event: 'open-chat'): void
  (event: 'open-mcp'): void
}>()

const { t } = useI18n()
const copyState = ref<'idle' | 'ok' | 'fail'>('idle')

async function copyDiagnostics() {
  try {
    copyState.value = (await copyText(props.diagnostics)) ? 'ok' : 'fail'
  } catch {
    copyState.value = 'fail'
  }
  window.setTimeout(() => {
    copyState.value = 'idle'
  }, 2200)
}
</script>

<template>
  <section class="hud-panel quick-commands">
    <header class="hud-panel-head">
      <span class="hud-index">06</span>
      <h3>{{ t('console.quickCommands') }}</h3>
    </header>
    <div class="command-grid">
      <button type="button" class="command" @click="emit('refresh')">
        <span class="command-key">F5</span>
        <span>{{ t('console.cmd.refresh') }}</span>
      </button>
      <button type="button" class="command" @click="emit('toggle-pause')">
        <span class="command-key">{{ paused ? '▶' : '❚❚' }}</span>
        <span>{{ paused ? t('console.cmd.resume') : t('console.cmd.pause') }}</span>
      </button>
      <button type="button" class="command" @click="emit('clear-log')">
        <span class="command-key">CLR</span>
        <span>{{ t('console.cmd.clearLog') }}</span>
      </button>
      <button type="button" class="command" @click="emit('open-mcp')">
        <span class="command-key">MCP</span>
        <span>{{ t('console.cmd.openMcp') }}</span>
      </button>
      <button type="button" class="command" @click="emit('open-chat')">
        <span class="command-key">AI</span>
        <span>{{ t('console.cmd.openChat') }}</span>
      </button>
      <button type="button" class="command" :class="`copy-${copyState}`" @click="copyDiagnostics">
        <span class="command-key">DIA</span>
        <span>
          {{
            copyState === 'ok'
              ? t('console.cmd.copied')
              : copyState === 'fail'
                ? t('console.cmd.copyFailed')
                : t('console.cmd.copyDiagnostics')
          }}
        </span>
      </button>
    </div>
    <p v-if="paused" class="command-note">{{ t('console.pausedNote') }}</p>
  </section>
</template>

<style scoped>
.quick-commands {
  display: grid;
  gap: 10px;
  align-content: start;
  min-width: 0;
}

.command-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
  gap: 8px;
}

.command {
  position: relative;
  display: flex;
  overflow: hidden;
  gap: 8px;
  align-items: center;
  padding: 8px 10px;
  border: 1px solid rgba(0, 245, 255, 0.3);
  border-radius: 6px;
  background: linear-gradient(180deg, rgba(16, 28, 66, 0.9), rgba(7, 11, 26, 0.9));
  color: var(--ice-blue);
  box-shadow:
    inset 0 0 18px -14px rgba(0, 245, 255, 0.95),
    0 0 14px -12px rgba(0, 245, 255, 0.8);
  text-shadow: 0 0 10px rgba(0, 245, 255, 0.35);
  font-family: inherit;
  font-size: 11px;
  text-align: left;
  cursor: pointer;
  transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
}

.command:hover {
  border-color: var(--border-active);
  color: var(--cyan);
  background: linear-gradient(90deg, rgba(0, 245, 255, 0.16), rgba(139, 92, 255, 0.08));
  box-shadow:
    0 0 22px -10px rgba(0, 245, 255, 0.95),
    inset 0 0 20px -14px rgba(0, 245, 255, 1);
  text-shadow: 0 0 10px rgba(0, 245, 255, 0.6);
}

.command::after {
  position: absolute;
  top: 0;
  bottom: 0;
  left: -60%;
  width: 40%;
  content: '';
  background: linear-gradient(90deg, transparent, rgba(0, 245, 255, 0.35), transparent);
  transform: skewX(-18deg);
  transition: left 0.45s ease;
  pointer-events: none;
}

.command:hover::after {
  left: 120%;
}

.command:active {
  transform: translateY(1px);
}

.command-key {
  padding: 1px 5px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
}

.copy-ok {
  border-color: rgba(0, 245, 184, 0.5);
  color: var(--success);
}

.copy-fail {
  border-color: rgba(255, 69, 106, 0.5);
  color: var(--danger);
}

.command-note {
  margin: 0;
  color: var(--warning);
  font-size: 11px;
}

@media (prefers-reduced-motion: reduce) {
  .command,
  .command:active {
    transition: none;
    transform: none;
  }
}
</style>
