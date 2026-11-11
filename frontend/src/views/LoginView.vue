<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import brandIcon from '../../img/icon.png'
import { apiGet } from '../api/client'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../i18n'
import { startLoginScene } from './loginScene'

const { t, locale, setLocale } = useI18n()

function onLocaleChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  setLocale(value === 'en-US' ? 'en-US' : 'zh-CN')
}

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()

const username = ref('')
const password = ref('')
const systemStatus = ref<'checking' | 'online' | 'offline'>('checking')
const secureTransport = window.location.protocol === 'https:'
const transportLabel = computed(() =>
  secureTransport ? 'HTTPS · SECURE CHANNEL' : 'LOCAL · HTTP CHANNEL',
)

async function checkSystemStatus() {
  try {
    const response = await apiGet<{ status: string }>('/health')
    systemStatus.value = response.status === 'ok' ? 'online' : 'offline'
  } catch {
    systemStatus.value = 'offline'
  }
}

async function submit() {
  if (!username.value || !password.value || auth.loading) {
    return
  }

  try {
    await auth.login(username.value, password.value)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/chat'
    await router.replace(redirect)
  } catch {
    // The store exposes the user-facing error.
  }
}

const sceneRoot = ref<HTMLElement | null>(null)
const sceneCanvas = ref<HTMLCanvasElement | null>(null)
const sceneNoise = ref<HTMLElement | null>(null)
let disposeScene: (() => void) | null = null
let healthTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  if (sceneRoot.value && sceneCanvas.value && sceneNoise.value) {
    disposeScene = startLoginScene({
      scene: sceneRoot.value,
      canvas: sceneCanvas.value,
      noise: sceneNoise.value,
    })
  }
  void checkSystemStatus()
  healthTimer = setInterval(() => void checkSystemStatus(), 30_000)
})

onBeforeUnmount(() => {
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
  disposeScene?.()
  disposeScene = null
})
</script>

<template>
  <main class="login-page">
    <div ref="sceneRoot" class="login-bg" aria-hidden="true">
      <div class="login-grid"></div>
      <canvas ref="sceneCanvas" class="login-particles"></canvas>
      <div ref="sceneNoise" class="login-noise"></div>
    </div>

    <header class="login-topbar">
      <div class="login-brand">
        <span class="login-logo-frame">
          <img class="login-logo" :src="brandIcon" alt="Sophon" />
        </span>
        <div>
          <p class="login-wordmark">SOPHON</p>
          <p class="login-brand-sub">SECURE FACTORY OS</p>
        </div>
      </div>
      <div class="login-topbar-actions">
        <span
          class="login-system-status"
          :class="`is-${systemStatus}`"
          aria-live="polite"
        >
          <i></i>
          {{
            systemStatus === 'online'
              ? t('login.systemOnline')
              : systemStatus === 'offline'
                ? t('login.systemOffline')
                : t('login.systemChecking')
          }}
        </span>
        <select
          class="language-select login-language"
          :value="locale"
          :aria-label="t('lang.label')"
          @change="onLocaleChange"
        >
          <option value="zh-CN">{{ t('lang.zh') }}</option>
          <option value="en-US">{{ t('lang.en') }}</option>
        </select>
      </div>
    </header>

    <section class="login-layout">
      <section class="login-factory" aria-hidden="true">
        <div class="robot-stage">
          <div class="robot-radar radar-a"></div>
          <div class="robot-radar radar-b"></div>
          <span class="robot-coordinate coordinate-a">X 114.28</span>
          <span class="robot-coordinate coordinate-b">Y 041.70</span>

          <div class="security-robot">
            <span class="robot-hood" aria-hidden="true"></span>
            <span class="security-robot-antenna"></span>
            <div class="security-robot-head">
              <span class="robot-eye eye-left"></span>
              <span class="robot-eye eye-right"></span>
              <span class="robot-mask"></span>
            </div>
            <div class="security-robot-neck"></div>
            <div class="security-robot-torso">
              <svg class="robot-terminal" viewBox="0 0 64 52">
                <rect x="5" y="6" width="54" height="40" rx="4" />
                <path d="m13 17 8 7-8 7" />
                <path d="M29 32h16" />
                <path d="M13 10h8" />
              </svg>
              <span class="robot-core"></span>
            </div>
            <span class="security-robot-arm arm-left"></span>
            <span class="security-robot-arm arm-right"></span>
            <span class="security-robot-base"></span>
          </div>

          <span class="robot-scan-beam"></span>
          <div class="robot-callout callout-security">
            <span>HACKER MODE</span>
            <strong>OFFENSIVE SIMULATION</strong>
          </div>
          <div class="robot-callout callout-intelligence">
            <span>PAYLOAD TRACE</span>
            <strong>EXPLOIT READY</strong>
          </div>
        </div>

        <div class="factory-line">
          <div class="factory-conveyor">
            <span class="factory-box box-a"><span>命令执行</span></span>
            <span class="factory-box box-b"><span>反序列化</span></span>
            <span class="factory-box box-c"><span>文件上传</span></span>
            <span class="factory-box box-d"><span>SQL注入</span></span>
          </div>
          <div class="factory-scanner">
            <span class="scanner-light"></span>
            <small>SECURE</small>
          </div>
          <div class="factory-output">
            <span class="output-pulse"></span>
            <small>VERIFIED</small>
          </div>
        </div>

        <div class="login-factory-status">
          <span><i class="tone-mint"></i>ROBOT LINK</span>
          <span><i class="tone-amber"></i>FACTORY FLOW</span>
          <span><i class="tone-coral"></i>SECURITY CORE</span>
        </div>
      </section>

      <form class="login-panel" @submit.prevent="submit">
        <span class="login-corner tl" aria-hidden="true"></span>
        <span class="login-corner tr" aria-hidden="true"></span>
        <span class="login-corner bl" aria-hidden="true"></span>
        <span class="login-corner br" aria-hidden="true"></span>

        <div class="login-module-label">
          <span>ACCESS MODULE</span>
          <strong>ENC-01</strong>
        </div>

        <header class="login-head">
          <div class="login-head-icon">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M12 3 20 6v5c0 5.5-3.4 9.1-8 11-4.6-1.9-8-5.5-8-11V6l8-3Z" />
              <rect x="9" y="11" width="6" height="5" rx="1" />
              <path d="M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11" />
            </svg>
          </div>
          <div>
            <h1 class="login-title">{{ t('login.title') }}</h1>
          </div>
        </header>

        <div class="login-trust-strip" aria-hidden="true">
          <span>ROBOT</span>
          <span>FACTORY</span>
          <span>SECURE</span>
          <span>INTELLIGENT</span>
        </div>

        <div class="login-fields">
          <label>
            <span>{{ t('login.username') }}</span>
            <span class="login-input">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z" />
                <path d="M4 20c0-3.5 3.6-6 8-6s8 2.5 8 6" />
              </svg>
              <input v-model.trim="username" autocomplete="username" maxlength="64" />
            </span>
          </label>

          <label>
            <span>{{ t('login.password') }}</span>
            <span class="login-input">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
                <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
              </svg>
              <input
                v-model="password"
                type="password"
                autocomplete="current-password"
                maxlength="256"
              />
            </span>
          </label>
        </div>

        <div class="login-security-policy" role="note">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 3 20 6v5c0 5.5-3.4 9.1-8 11-4.6-1.9-8-5.5-8-11V6l8-3Z" />
            <path d="m8.8 12.1 2.1 2.1 4.5-4.5" />
          </svg>
          <span>
            <strong>{{ t('login.securityPolicyTitle') }}</strong>
            <small>{{ t('login.securityPolicy') }}</small>
          </span>
        </div>

        <div v-if="auth.error" class="alert error">{{ auth.error }}</div>

        <div class="login-row">
          <span class="login-channel">{{ transportLabel }}</span>
        </div>

        <button class="button login-button" type="submit" :disabled="auth.loading">
          <span class="login-button-label">
            {{ auth.loading ? t('login.submitting') : t('login.submit') }}
          </span>
          <svg class="login-button-arrow" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M5 12h13" />
            <path d="m13 6 6 6-6 6" />
          </svg>
          <span class="login-button-shine" aria-hidden="true"></span>
        </button>

        <footer class="login-foot">
          <span class="login-pulse"></span>
          <span>{{ transportLabel }}</span>
        </footer>
      </form>
    </section>
  </main>
</template>
