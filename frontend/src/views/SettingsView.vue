<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { apiGet, apiPost, apiPut } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore, type User } from '../stores/auth'
import InterceptRulesPanel from '../components/settings/InterceptRulesPanel.vue'
import brandIcon from '../../img/icon.png'

const { t } = useI18n()
const auth = useAuthStore()
const canReadSettings = computed(() => auth.hasPermission('settings:read'))
const canWriteSettings = computed(() => auth.hasPermission('settings:write'))

interface SettingsValues {
  llm: {
    provider: string
    baseUrl: string
    apiKey: string
    model: string
    allowPrivateNetwork: boolean
    timeoutSeconds: number
    configured: boolean
    mock: boolean
  }
  agent: {
    mock: boolean
    contextMaxChars: number
    maxIterations: number
    maxTurnTokens: number
    maxHypotheses: number
  }
  hitl: {
    enabled: boolean
    tools: string[]
    timeoutSeconds: number
  }
  mcp: {
    callTimeoutSeconds: number
    maxConcurrentPerServer: number
    maxConcurrentTotal: number
  }
  proxy: {
    enabled: boolean
    type: string
    host: string
    port: number
    username: string
    password: string
    noProxy: string
  }
}

interface SettingsResponse {
  configPath: string
  editable: boolean
  envLocked: string[]
  requiresRestart: string[]
  values: SettingsValues
}

interface SaveResponse {
  saved: boolean
  reloaded: string[]
  requiresRestart: string[]
}

interface StorageCategory {
  name: string
  label: string
  kind: string
  path?: string
  enabled: boolean
  retentionDays: number
  expired: number
  files: number
  bytes: number
}

const loading = ref(false)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const configPath = ref('')
const editable = ref(false)
const writable = computed(() => editable.value && canWriteSettings.value)
const envLocked = ref<string[]>([])
const restartHints = ref<string[]>([])
const apiKeyInput = ref('')
const activeSection = ref<
  'basic' | 'llm' | 'proxy' | 'agent' | 'tools' | 'security' | 'storage' | 'intercept'
>('basic')
const profileSaving = ref(false)
const profile = reactive({
  displayName: '',
  assistantName: '',
  assistantAvatar: '',
  userAvatar: '',
})

const passwordDraft = reactive({ current: '', next: '', confirm: '' })
const passwordSaving = ref(false)
const storageSaving = ref(false)
const storageCleaning = ref(false)
const cleanupConfirmOpen = ref(false)
const storageEnvLocked = ref<string[]>([])
const storage = reactive({
  editable: false,
  autoClean: false,
  intervalMinutes: 60,
  artifactRoot: '',
  activeGraceHours: 24,
  note: '',
  categories: [] as StorageCategory[],
})
const passwordChecks = computed(() => {
  const value = passwordDraft.next
  return [
    { label: t('settings.passwordLength'), ok: value.length >= 8 },
    { label: t('settings.passwordLower'), ok: /[a-z]/.test(value) },
    { label: t('settings.passwordUpper'), ok: /[A-Z]/.test(value) },
    { label: t('settings.passwordDigit'), ok: /\d/.test(value) },
    { label: t('settings.passwordSymbol'), ok: /[^A-Za-z0-9]/.test(value) },
  ]
})
const passwordClassCount = computed(
  () => passwordChecks.value.slice(1).filter((item) => item.ok).length,
)
const passwordMatched = computed(
  () => passwordDraft.next.length > 0 && passwordDraft.next === passwordDraft.confirm,
)
const passwordStrength = computed(() => {
  const lengthOk = passwordDraft.next.length >= 8
  const classOk = passwordClassCount.value >= 3
  if (!passwordDraft.next) {
    return 0
  }
  if (!lengthOk) {
    return 25
  }
  if (!classOk) {
    return 55
  }
  return passwordMatched.value ? 100 : 80
})

const form = reactive({
  mock: true,
  provider: 'openai_compatible',
  baseUrl: '',
  model: '',
  llmAllowPrivate: false,
  llmTimeout: 120,
  contextMaxChars: 24000,
  maxIterations: 40,
  maxTurnTokens: 0,
  maxHypotheses: 200,
  hitlEnabled: false,
  hitlTools: '',
  hitlTimeout: 300,
  callTimeout: 30,
  maxConcurrentPerServer: 2,
  maxConcurrentTotal: 16,
  proxyEnabled: false,
  proxyType: 'http',
  proxyHost: '',
  proxyPort: 7890,
  proxyUsername: '',
  proxyNoProxy: 'localhost,127.0.0.1,::1',
})
const proxyPasswordInput = ref('')

const modelOptions = ref<Array<{ id: string; name?: string }>>([])
const modelFetching = ref(false)
const modelStatus = ref('')
const currentModelOption = computed(() =>
  modelOptions.value.some((item) => item.id === form.model) ? form.model : '',
)
const navGroups = computed(() => [
  {
    label: t('settings.navGroupIdentity'),
    items: [
      { key: 'basic' as const, label: t('settings.sectionBasic'), code: 'ID', visible: true },
      {
        key: 'llm' as const,
        label: t('settings.llmSection'),
        code: 'AI',
        visible: canReadSettings.value,
      },
      {
        key: 'proxy' as const,
        label: t('settings.proxySection'),
        code: 'NET',
        visible: canReadSettings.value,
      },
    ],
  },
  {
    label: t('settings.navGroupIntelligence'),
    items: [
      {
        key: 'agent' as const,
        label: t('settings.agentSection'),
        code: 'RUN',
        visible: canReadSettings.value,
      },
      {
        key: 'tools' as const,
        label: t('settings.toolsSection'),
        code: 'TOOL',
        visible: canReadSettings.value,
      },
    ],
  },
  {
    label: t('settings.navGroupSecurity'),
    items: [
      {
        key: 'security' as const,
        label: t('settings.sectionSecurity'),
        code: 'SEC',
        visible: true,
      },
      {
        key: 'storage' as const,
        label: t('settings.sectionStorage'),
        code: 'DATA',
        visible: canReadSettings.value,
      },
      {
        key: 'intercept' as const,
        label: t('settings.sectionIntercept'),
        code: 'GATE',
        visible: canReadSettings.value,
      },
    ],
  },
])
const activeSectionLabel = computed(
  () =>
    navGroups.value.flatMap((group) => group.items).find((item) => item.key === activeSection.value)
      ?.label ?? '',
)

function locked(field: string) {
  return envLocked.value.includes(field)
}

function restartRequired(field: string) {
  return restartHints.value.includes(field)
}

function syncProfile() {
  profile.displayName = auth.user?.displayName?.trim() || auth.user?.username || ''
  profile.assistantName = auth.user?.assistantName?.trim() || t('app.title')
  profile.assistantAvatar = auth.user?.assistantAvatar?.trim() || ''
  profile.userAvatar = auth.user?.userAvatar?.trim() || ''
}

async function saveProfile() {
  if (profileSaving.value) {
    return
  }
  profileSaving.value = true
  error.value = ''
  notice.value = ''
  try {
    const response = await apiPut<{ user: User }>('/auth/profile', {
      displayName: profile.displayName.trim() || auth.user?.username || '',
      assistantName: profile.assistantName.trim() || t('app.title'),
      assistantAvatar: profile.assistantAvatar.trim(),
      userAvatar: profile.userAvatar.trim(),
    })
    auth.applyUserProfile(response.user)
    syncProfile()
    notice.value = t('settings.profileSaved')
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.profileSaveFailed')
  } finally {
    profileSaving.value = false
  }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<SettingsResponse>('/settings/ai')
    configPath.value = response.configPath
    editable.value = response.editable
    envLocked.value = response.envLocked ?? []
    restartHints.value = response.requiresRestart ?? []
    const values = response.values
    form.mock = values.agent.mock
    form.provider = values.llm.provider || 'openai_compatible'
    form.baseUrl = values.llm.baseUrl
    form.model = values.llm.model
    form.llmAllowPrivate = values.llm.allowPrivateNetwork
    form.llmTimeout = values.llm.timeoutSeconds
    form.contextMaxChars = values.agent.contextMaxChars
    form.maxIterations = values.agent.maxIterations
    form.maxTurnTokens = values.agent.maxTurnTokens ?? 0
    form.maxHypotheses = values.agent.maxHypotheses
    form.hitlEnabled = values.hitl.enabled
    form.hitlTools = (values.hitl.tools ?? []).join(', ')
    form.hitlTimeout = values.hitl.timeoutSeconds
    form.callTimeout = values.mcp.callTimeoutSeconds
    form.maxConcurrentPerServer = values.mcp.maxConcurrentPerServer
    form.maxConcurrentTotal = values.mcp.maxConcurrentTotal
    form.proxyEnabled = values.proxy.enabled
    form.proxyType = values.proxy.type || 'http'
    form.proxyHost = values.proxy.host
    form.proxyPort = values.proxy.port || 7890
    form.proxyUsername = values.proxy.username
    form.proxyNoProxy = values.proxy.noProxy
    proxyPasswordInput.value = ''
    apiKeyInput.value = ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readSettingsFailed')
  } finally {
    loading.value = false
  }
}

async function save() {
  if (!writable.value) {
    error.value = t('message.noWritableConfig')
    return
  }
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    const tools = form.hitlTools
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
    const response = await apiPut<SaveResponse>('/settings/ai', {
      llm: {
        provider: form.provider,
        baseUrl: form.baseUrl.trim(),
        apiKey: apiKeyInput.value.trim(),
        model: form.model.trim(),
        allowPrivateNetwork: form.llmAllowPrivate,
        timeoutSeconds: Number(form.llmTimeout),
      },
      agent: {
        mock: form.mock,
        contextMaxChars: Number(form.contextMaxChars),
        maxIterations: Number(form.maxIterations),
        maxTurnTokens: Number(form.maxTurnTokens),
        maxHypotheses: Number(form.maxHypotheses),
      },
      hitl: {
        enabled: form.hitlEnabled,
        tools,
        timeoutSeconds: Number(form.hitlTimeout),
      },
      mcp: {
        callTimeoutSeconds: Number(form.callTimeout),
        maxConcurrentPerServer: Number(form.maxConcurrentPerServer),
        maxConcurrentTotal: Number(form.maxConcurrentTotal),
      },
      proxy: {
        enabled: form.proxyEnabled,
        type: form.proxyType,
        host: form.proxyHost.trim(),
        port: Number(form.proxyPort),
        username: form.proxyUsername.trim(),
        password: proxyPasswordInput.value.trim(),
        noProxy: form.proxyNoProxy.trim(),
      },
    })
    const restart = response.requiresRestart ?? []
    notice.value = restart.length
      ? t('settings.savedHotRestart', { fields: (response.reloaded ?? []).join(', '), restart: restart.join(', ') })
      : t('settings.savedHot', { fields: (response.reloaded ?? []).join(', ') })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.saveFailed')
  } finally {
    saving.value = false
  }
}

async function fetchModels() {
  modelFetching.value = true
  modelStatus.value = ''
  error.value = ''
  try {
    const response = await apiPost<{
      success: boolean
      supported: boolean
      models?: Array<{ id: string; name?: string }>
      count?: number
      error?: string
    }>('/settings/llm/models', {
      provider: form.provider,
      baseUrl: form.baseUrl.trim(),
      apiKey: apiKeyInput.value.trim(),
    })
    if (!response.success) {
      modelOptions.value = []
      modelStatus.value = response.error || t('settings.modelFetchFailed')
      return
    }
    modelOptions.value = response.models ?? []
    modelStatus.value = t('settings.modelFetchSuccess', {
      count: response.count ?? modelOptions.value.length,
    })
  } catch (err) {
    modelStatus.value = err instanceof Error ? err.message : t('settings.modelFetchFailed')
  } finally {
    modelFetching.value = false
  }
}

function selectModel(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  if (value) {
    form.model = value
  }
}

async function changePassword() {
  error.value = ''
  notice.value = ''
  if (!passwordChecks.value[0].ok || passwordClassCount.value < 3) {
    error.value = t('settings.passwordWeak')
    return
  }
  if (!passwordMatched.value) {
    error.value = t('settings.passwordMismatch')
    return
  }
  if (!passwordDraft.current) {
    error.value = t('settings.passwordCurrentRequired')
    return
  }
  passwordSaving.value = true
  try {
    await apiPost('/auth/password', {
      currentPassword: passwordDraft.current,
      newPassword: passwordDraft.next,
      confirmPassword: passwordDraft.confirm,
    })
    passwordDraft.current = ''
    passwordDraft.next = ''
    passwordDraft.confirm = ''
    notice.value = t('settings.passwordChanged')
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.changePasswordFailed')
  } finally {
    passwordSaving.value = false
  }
}

async function loadStorage() {
  try {
    const response = await apiGet<{
      editable: boolean
      autoClean: boolean
      intervalMinutes: number
      artifactRoot: string
      activeGraceHours: number
      note: string
      categories: StorageCategory[]
      envLocked: string[]
    }>('/settings/storage')
    storage.editable = response.editable && canWriteSettings.value
    storage.autoClean = response.autoClean
    storage.intervalMinutes = response.intervalMinutes
    storage.artifactRoot = response.artifactRoot
    storage.activeGraceHours = response.activeGraceHours
    storage.note = response.note
    storage.categories = response.categories ?? []
    storageEnvLocked.value = response.envLocked ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readStorageFailed')
  }
}

function formatBytes(value: number) {
  if (!value) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let size = value
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index++
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function storageLocked(field: string) {
  return storageEnvLocked.value.includes(field)
}

function categoryPending(item: StorageCategory) {
  if (item.kind === 'dir') {
    return t('settings.filesPending', { files: item.files, size: formatBytes(item.bytes) })
  }
  return t('settings.recordsPending', { count: item.expired })
}

async function saveStorage() {
  if (!storage.editable) {
    return
  }
  storageSaving.value = true
  error.value = ''
  notice.value = ''
  try {
    await apiPut('/settings/storage', {
      autoClean: storage.autoClean,
      intervalMinutes: Number(storage.intervalMinutes),
      categories: storage.categories.map((item) => ({
        name: item.name,
        enabled: item.enabled,
        retentionDays: Number(item.retentionDays),
      })),
    })
    notice.value = t('settings.policySaved')
    await loadStorage()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.saveStorageFailed')
  } finally {
    storageSaving.value = false
  }
}

function requestCleanupStorage() {
  if (!storage.editable) {
    return
  }
  const enabled = storage.categories.filter((item) => item.enabled).map((item) => item.name)
  if (!enabled.length) {
    error.value = t('message.noCleanupCategory')
    return
  }
  cleanupConfirmOpen.value = true
}

function closeCleanupDialog() {
  if (!storageCleaning.value) {
    cleanupConfirmOpen.value = false
  }
}

async function confirmCleanupStorage() {
  const enabled = storage.categories.filter((item) => item.enabled).map((item) => item.name)
  if (!storage.editable || !enabled.length) {
    cleanupConfirmOpen.value = false
    return
  }
  storageCleaning.value = true
  error.value = ''
  notice.value = ''
  try {
    const result = await apiPost<{
      total: number
      totalBytes: number
      deleted: Record<string, number>
    }>('/settings/storage/cleanup', { categories: enabled })
    notice.value =
      result.totalBytes > 0
        ? t('settings.cleaned', { total: result.total, size: formatBytes(result.totalBytes) })
        : t('settings.cleanedRecords', { count: result.total })
    await loadStorage()
    cleanupConfirmOpen.value = false
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.cleanupFailed')
    cleanupConfirmOpen.value = false
  } finally {
    storageCleaning.value = false
  }
}

onMounted(async () => {
  syncProfile()
  if (canReadSettings.value) {
    await load()
    await loadStorage()
  } else {
    activeSection.value = 'security'
  }
})
</script>

<template>
  <section class="page factory-page page-settings config-control">
    <header class="page-header config-header">
      <div class="config-heading page-heading-with-robot">
        <PageTitleRobot tone="cyan" />
        <div>
          <p class="eyebrow">CONFIG FLOOR // SYSTEM CONTROL</p>
          <h1>{{ t('settings.title') }}</h1>
          <p class="config-page-hint">{{ activeSectionLabel }}</p>
        </div>
      </div>
      <button class="button" type="button" :disabled="loading" @click="load">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
        {{ t('common.refresh') }}
      </button>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>
    <div v-if="canReadSettings && !editable && !loading" class="alert error">
      {{ t('settings.noWritable') }}
    </div>
    <div v-if="envLocked.length" class="alert warn">
      {{ t('settings.envLocked', { fields: envLocked.join(', ') }) }}
    </div>

    <section class="config-status-rail">
      <article class="config-stat tone-config">
        <small>
          <svg class="config-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 7h16M4 12h16M4 17h16" />
            <circle cx="8" cy="7" r="2" />
            <circle cx="16" cy="12" r="2" />
            <circle cx="10" cy="17" r="2" />
          </svg>
          {{ t('settings.configStatusLabel') }}
        </small>
        <strong>{{ editable ? 'RW' : 'RO' }}</strong>
      </article>
      <article class="config-stat tone-lock">
        <small>
          <svg class="config-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="5" y="10" width="14" height="10" rx="2" />
            <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2" />
          </svg>
          {{ t('settings.envLockedLabel') }}
        </small>
        <strong>{{ envLocked.length }}</strong>
      </article>
      <article class="config-stat tone-restart">
        <small>
          <svg class="config-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" />
          </svg>
          {{ t('settings.restartLabel') }}
        </small>
        <strong>{{ restartHints.length }}</strong>
      </article>
      <article class="config-stat tone-section">
        <small>
          <svg class="config-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="4" width="6" height="6" rx="1" />
            <rect x="14" y="4" width="6" height="6" rx="1" />
            <rect x="4" y="14" width="6" height="6" rx="1" />
            <rect x="14" y="14" width="6" height="6" rx="1" />
          </svg>
          {{ t('settings.currentSectionLabel') }}
        </small>
        <strong>{{ activeSectionLabel }}</strong>
      </article>
    </section>

    <div v-if="!loading" class="settings-layout">
      <nav class="settings-nav config-nav">
        <section v-for="group in navGroups" :key="group.label" class="config-nav-group">
          <span>{{ group.label }}</span>
          <button
            v-for="item in group.items.filter((entry) => entry.visible)"
            :key="item.key"
            type="button"
            :class="{ active: activeSection === item.key }"
            @click="activeSection = item.key"
          >
            <b>{{ item.code }}</b>
            <span>{{ item.label }}</span>
          </button>
        </section>
      </nav>

      <div class="settings-panels">
        <div class="settings-sections">
          <article v-show="activeSection === 'basic'" class="business-card settings-single profile-card">
            <h2>{{ t('settings.profileSection') }}</h2>
            <p class="field-hint">{{ t('settings.profileHint') }}</p>
            <div class="profile-grid">
              <label class="field">
                <span>{{ t('settings.profileName') }}</span>
                <input
                  v-model="profile.assistantName"
                  maxlength="40"
                  :placeholder="t('app.title')"
                />
              </label>
              <label class="field">
                <span>{{ t('settings.profileAvatar') }}</span>
                <input
                  v-model="profile.assistantAvatar"
                  maxlength="500000"
                  :placeholder="t('settings.avatarPlaceholder')"
                />
              </label>
              <div class="profile-avatar-preview">
                <img
                  :src="profile.assistantAvatar.trim() || brandIcon"
                  alt=""
                  aria-hidden="true"
                />
                <span>{{ t('settings.profileAvatarPreview') }}</span>
              </div>
              <label class="field">
                <span>{{ t('settings.userDisplayName') }}</span>
                <input
                  v-model="profile.displayName"
                  maxlength="40"
                  :placeholder="auth.user?.username || ''"
                />
              </label>
              <label class="field">
                <span>{{ t('settings.userAvatar') }}</span>
                <input
                  v-model="profile.userAvatar"
                  maxlength="500000"
                  :placeholder="t('settings.avatarPlaceholder')"
                />
              </label>
              <div class="profile-avatar-preview">
                <img
                  v-if="profile.userAvatar.trim()"
                  :src="profile.userAvatar.trim()"
                  alt=""
                  aria-hidden="true"
                />
                <span v-else class="profile-avatar-initial">
                  {{ (profile.displayName.trim() || auth.user?.username || 'U').slice(0, 1).toUpperCase() }}
                </span>
                <span>{{ t('settings.userAvatarPreview') }}</span>
              </div>
            </div>
            <div class="settings-save-row">
              <button
                class="button"
                type="button"
                :disabled="profileSaving"
                @click="saveProfile"
              >
                {{ profileSaving ? t('common.saving') : t('common.save') }}
              </button>
            </div>
          </article>

      <article v-show="activeSection === 'llm'" class="business-card">
        <h2>{{ t('settings.llmSection') }}</h2>
        <label class="field">
          <span>{{ t('settings.llmProvider') }}</span>
          <select v-model="form.provider" :disabled="locked('llm.provider') || !writable">
            <option value="openai_compatible">{{ t('settings.providerOpenAI') }}</option>
            <option value="anthropic">{{ t('settings.providerAnthropic') }}</option>
          </select>
        </label>
        <label class="field">
          <span>{{ t('settings.apiUrl') }}</span>
          <input v-model="form.baseUrl" :disabled="locked('llm.baseUrl') || !writable" />
        </label>
        <label class="checkbox-line">
          <input
            v-model="form.llmAllowPrivate"
            type="checkbox"
            :disabled="locked('llm.allowPrivateNetwork') || !writable"
          />
          <span>{{ t('settings.llmAllowPrivateNetwork') }}</span>
        </label>
        <label class="field">
          <span>{{ t('settings.apiKey') }}</span>
          <input
            v-model="apiKeyInput"
            type="password"
            :placeholder="locked('llm.apiKey') ? t('settings.apiKeyEnv') : t('settings.apiKeyKeep')"
            :disabled="locked('llm.apiKey') || !writable"
          />
        </label>
        <label class="field">
          <span>{{ t('settings.model') }}</span>
          <div class="model-row">
            <input v-model="form.model" :disabled="locked('llm.model') || !writable" />
            <button
              class="button compact"
              type="button"
              :disabled="modelFetching || !writable"
              @click="fetchModels"
            >
              {{ modelFetching
                ? t('settings.modelFetching')
                : modelOptions.length
                  ? t('settings.modelRefetch')
                  : t('settings.modelFetch') }}
            </button>
          </div>
          <select
            v-if="modelOptions.length"
            class="model-select"
            :value="currentModelOption"
            :disabled="locked('llm.model') || !writable"
            @change="selectModel"
          >
            <option value="">
              {{ t('settings.modelSelectPlaceholder', { count: modelOptions.length }) }}
            </option>
            <option v-for="item in modelOptions" :key="item.id" :value="item.id">
              {{ item.name ? `${item.id} · ${item.name}` : item.id }}
            </option>
          </select>
          <small v-if="modelStatus" class="field-hint">{{ modelStatus }}</small>
        </label>
        <label class="field">
          <span>{{ t('settings.requestTimeout') }}</span>
          <input
            v-model.number="form.llmTimeout"
            type="number"
            min="1"
            max="3600"
            :disabled="locked('llm.timeoutSeconds') || !writable"
          />
        </label>
      </article>

      <article v-show="activeSection === 'proxy'" class="business-card">
        <h2>{{ t('settings.proxySection') }}</h2>
        <label class="checkbox-line">
          <input
            v-model="form.proxyEnabled"
            type="checkbox"
            :disabled="locked('proxy.enabled') || !writable"
          />
          <span>{{ t('settings.proxyEnabled') }}</span>
        </label>
        <div class="proxy-grid">
          <label class="field">
            <span>{{ t('settings.proxyType') }}</span>
            <select
              v-model="form.proxyType"
              :disabled="locked('proxy.type') || !writable"
            >
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="socks5">SOCKS5</option>
            </select>
          </label>
          <label class="field">
            <span>{{ t('settings.proxyHost') }}</span>
            <input
              v-model="form.proxyHost"
              placeholder="127.0.0.1"
              :disabled="locked('proxy.host') || !writable"
            />
          </label>
          <label class="field">
            <span>{{ t('settings.proxyPort') }}</span>
            <input
              v-model.number="form.proxyPort"
              type="number"
              min="1"
              max="65535"
              :disabled="locked('proxy.port') || !writable"
            />
          </label>
          <label class="field">
            <span>{{ t('settings.proxyUsername') }}</span>
            <input
              v-model="form.proxyUsername"
              autocomplete="off"
              :disabled="locked('proxy.username') || !writable"
            />
          </label>
        </div>
        <label class="field">
          <span>{{ t('settings.proxyPassword') }}</span>
          <input
            v-model="proxyPasswordInput"
            type="password"
            autocomplete="new-password"
            :placeholder="locked('proxy.password') ? t('settings.apiKeyEnv') : t('settings.proxyPasswordKeep')"
            :disabled="locked('proxy.password') || !writable"
          />
        </label>
        <label class="field">
          <span>NO_PROXY</span>
          <input
            v-model="form.proxyNoProxy"
            placeholder="localhost,127.0.0.1,::1"
            :disabled="locked('proxy.noProxy') || !writable"
          />
        </label>
        <small class="field-hint">{{ t('settings.proxyRestartHint') }}</small>
      </article>

      <article v-show="activeSection === 'agent'" class="business-card">
        <h2>{{ t('settings.agentSection') }}</h2>
        <label class="checkbox-line">
          <input v-model="form.mock" type="checkbox" :disabled="locked('agent.mock') || !writable" />
          <span>{{ t('settings.mockModel') }}</span>
        </label>
        <label class="field">
          <span>{{ t('settings.contextLimit') }}</span>
          <input
            v-model.number="form.contextMaxChars"
            type="number"
            min="1000"
            max="200000"
            :disabled="locked('agent.contextMaxChars') || !writable"
          />
        </label>
        <label class="field">
          <span>{{ t('settings.maxHypotheses') }}</span>
          <input
            v-model.number="form.maxHypotheses"
            type="number"
            min="10"
            max="2000"
            :disabled="locked('agent.maxHypotheses') || !writable"
          />
          <small class="field-hint">{{ t('settings.maxHypothesesHint') }}</small>
        </label>
      </article>

      <article v-show="activeSection === 'tools'" class="business-card">
        <h2>{{ t('settings.toolsSection') }}</h2>
        <label class="field">
          <span>{{ t('settings.toolWait') }}</span>
          <input
            v-model.number="form.callTimeout"
            type="number"
            min="1"
            max="3600"
            :disabled="locked('mcp.callTimeoutSeconds') || !writable"
          />
          <small v-if="restartRequired('mcp.callTimeoutSeconds')" class="field-hint">{{ t('settings.restartHint') }}</small>
        </label>
        <label class="field">
          <span>{{ t('settings.perServerLimit') }}</span>
          <input
            v-model.number="form.maxConcurrentPerServer"
            type="number"
            min="-1"
            max="128"
            :disabled="locked('mcp.maxConcurrentPerServer') || !writable"
          />
          <small class="field-hint">{{ t('settings.restartHint') }}</small>
        </label>
        <label class="field">
          <span>{{ t('settings.totalLimit') }}</span>
          <input
            v-model.number="form.maxConcurrentTotal"
            type="number"
            min="-1"
            max="512"
            :disabled="locked('mcp.maxConcurrentTotal') || !writable"
          />
          <small class="field-hint">{{ t('settings.restartHint') }}</small>
        </label>
        <label class="checkbox-line">
          <input
            v-model="form.hitlEnabled"
            type="checkbox"
            :disabled="locked('hitl.enabled') || !writable"
          />
          <span>{{ t('settings.hitlExtraTools') }}</span>
        </label>
        <label class="field">
          <span>{{ t('settings.hitlTools') }}</span>
          <input v-model="form.hitlTools" :disabled="locked('hitl.tools') || !writable" />
        </label>
        <label class="field">
          <span>{{ t('settings.hitlTimeout') }}</span>
          <input
            v-model.number="form.hitlTimeout"
            type="number"
            min="1"
            max="86400"
            :disabled="locked('hitl.timeoutSeconds') || !writable"
          />
        </label>
      </article>

          <div
            v-if="canWriteSettings && ['llm', 'proxy', 'agent', 'tools'].includes(activeSection)"
            class="settings-save-row"
          >
            <button class="button" type="button" :disabled="saving || !writable" @click="save">
              {{ saving ? t('common.saving') : t('common.save') }}
            </button>
          </div>
        </div>

        <article v-show="activeSection === 'security'" class="business-card settings-single">
        <h2>{{ t('settings.securitySection') }}</h2>
        <label class="field">
          <span>{{ t('settings.currentPassword') }}</span>
          <input v-model="passwordDraft.current" type="password" autocomplete="current-password" />
        </label>
        <label class="field">
          <span>{{ t('settings.newPassword') }}</span>
          <input v-model="passwordDraft.next" type="password" autocomplete="new-password" />
        </label>
        <label class="field">
          <span>{{ t('settings.confirmPassword') }}</span>
          <input v-model="passwordDraft.confirm" type="password" autocomplete="new-password" />
        </label>
        <div class="password-strength" :class="{ strong: passwordStrength >= 80 }">
          <span>{{ t('settings.passwordRule') }}</span>
          <div><i :style="{ width: `${passwordStrength}%` }"></i></div>
          <b>{{ passwordStrength }}%</b>
        </div>
        <ul class="password-checks">
          <li v-for="item in passwordChecks" :key="item.label" :class="{ ok: item.ok }">
            {{ item.ok ? '✓' : '·' }} {{ item.label }}
          </li>
          <li :class="{ ok: passwordMatched }">{{ passwordMatched ? '✓' : '·' }} {{ t('settings.passwordMatch') }}</li>
        </ul>
        <p class="field-hint">{{ t('settings.passwordRule') }}</p>
        <div>
          <button class="button" type="button" :disabled="passwordSaving" @click="changePassword">
            {{ passwordSaving ? t('settings.submitting') : t('settings.changePassword') }}
          </button>
        </div>
      </article>

        <article v-show="activeSection === 'storage'" class="business-card settings-single">
        <h2>{{ t('settings.storageSection') }}</h2>
        <label class="checkbox-line">
          <input
            v-model="storage.autoClean"
            type="checkbox"
            :disabled="!storage.editable || storageLocked('autoClean')"
          />
          <span>{{ t('settings.autoClean') }}</span>
        </label>
        <label class="field">
          <span>{{ t('settings.cleanInterval') }}</span>
          <input
            v-model.number="storage.intervalMinutes"
            type="number"
            min="5"
            max="10080"
            :disabled="!storage.editable || storageLocked('intervalMinutes')"
          />
        </label>
        <div class="factory-table-scroll">
          <table class="storage-table">
          <thead>
            <tr>
              <th>{{ t('settings.category') }}</th>
              <th>{{ t('vulnerability.type') }}</th>
              <th>{{ t('settings.path') }}</th>
              <th>{{ t('common.enable') }}</th>
              <th>{{ t('settings.retentionDays') }}</th>
              <th>{{ t('settings.pending') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in storage.categories" :key="item.name">
              <td>{{ t(`storage.${item.name}`) }}</td>
              <td>{{ item.kind === 'dir' ? t('settings.kindDirectory') : t('settings.kindDatabase') }}</td>
              <td class="path-cell">{{ item.path || '-' }}</td>
              <td>
                <input
                  v-model="item.enabled"
                  type="checkbox"
                  :aria-label="t('storage.' + item.name) + ' ' + t('common.enable')"
                  :disabled="!storage.editable"
                />
              </td>
              <td>
                <input
                  v-model.number="item.retentionDays"
                  type="number"
                  min="0"
                  max="3650"
                  :aria-label="t('storage.' + item.name) + ' ' + t('settings.retentionDays')"
                  :disabled="!storage.editable"
                />
              </td>
              <td>{{ categoryPending(item) }}</td>
            </tr>
          </tbody>
          </table>
        </div>
        <p class="field-hint">{{ t('settings.storageNote') }}</p>
        <p class="field-hint">
          {{ t('settings.artifactRoot', { path: storage.artifactRoot || '-', hours: storage.activeGraceHours }) }}
        </p>
        <div class="storage-actions">
          <button
            class="button compact"
            type="button"
            :disabled="storageSaving || !storage.editable"
            @click="saveStorage"
          >
            {{ t('settings.savePolicy') }}
          </button>
          <button
            class="button compact danger"
            type="button"
            :disabled="storageCleaning"
            @click="requestCleanupStorage"
          >
            {{ t('settings.cleanNow') }}
          </button>
          <button class="button compact" type="button" @click="loadStorage">{{ t('settings.refreshPreview') }}</button>
        </div>
        </article>

        <InterceptRulesPanel
          v-show="activeSection === 'intercept'"
          :writable="writable"
        />
      </div>
    </div>

    <Teleport to="body">
      <div v-if="cleanupConfirmOpen" class="config-dialog-layer" @click.self="closeCleanupDialog">
        <aside class="config-dialog" role="dialog" aria-modal="true">
          <header>
            <span class="config-warning" aria-hidden="true">!</span>
            <div>
              <span class="config-code">DANGER // STORAGE CLEANUP</span>
              <h2>{{ t('settings.cleanNow') }}</h2>
            </div>
          </header>
          <p>{{ t('settings.confirmClean') }}</p>
          <div class="config-dialog-categories">
            <span v-for="item in storage.categories.filter((entry) => entry.enabled)" :key="item.name">
              {{ t(`storage.${item.name}`) }} · {{ categoryPending(item) }}
            </span>
          </div>
          <footer>
            <button class="button compact" type="button" :disabled="storageCleaning" @click="closeCleanupDialog">{{ t('common.cancel') }}</button>
            <button class="button compact danger" type="button" :disabled="storageCleaning" @click="confirmCleanupStorage">
              {{ storageCleaning ? t('common.loading') : t('settings.cleanNow') }}
            </button>
          </footer>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.header-actions {
  display: flex;
  gap: 8px;
}

.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.alert.warn {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.settings-layout {
  display: grid;
  grid-template-columns: 200px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.settings-nav {
  position: sticky;
  top: 16px;
  display: grid;
  gap: 6px;
}

.settings-nav button {
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
  text-align: left;
  cursor: pointer;
}

.settings-nav button.active {
  border-color: var(--accent);
  color: #ffffff;
  background: var(--accent-lime);
  box-shadow: none;
}

.settings-panels {
  min-width: 0;
}

.settings-sections {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 16px;
}

.profile-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 170px;
  gap: 12px;
  align-items: end;
}

.profile-avatar-preview {
  display: flex;
  align-items: center;
  gap: 9px;
  min-height: 40px;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-size: 11px;
}

.profile-avatar-preview img,
.profile-avatar-initial {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 auto;
  place-items: center;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: var(--surface);
  object-fit: cover;
}

.profile-avatar-initial {
  color: var(--accent);
  font-family: var(--mono);
  font-weight: 700;
}

.settings-save-row {
  grid-column: 1;
  display: flex;
  justify-content: flex-end;
}

.settings-single {
  margin: 0;
}

.field {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.field input,
.field select {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-weight: 400;
}

.field input:disabled,
.field select:disabled {
  background: var(--surface-soft);
  color: var(--text-muted);
}

.model-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.model-row input {
  flex: 1;
  min-width: 0;
}

.proxy-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.field-hint {
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 400;
}

.checkbox-line {
  display: flex;
  gap: 8px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 13px;
}

.checkbox-line input {
  width: auto;
}

.readonly-list {
  display: grid;
  grid-template-columns: 96px minmax(0, 1fr);
  gap: 6px 12px;
  margin: 0;
  font-size: 13px;
}

.readonly-list dt {
  color: var(--text-muted);
}

.readonly-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.password-checks {
  display: grid;
  gap: 4px;
  margin: 0;
  padding: 0;
  color: var(--text-muted);
  font-size: 12px;
  list-style: none;
}

.password-checks li.ok {
  color: var(--success);
}

.storage-table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid var(--border);
  background: var(--surface);
  font-size: 13px;
}

.storage-table th,
.storage-table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--border);
  text-align: left;
}

.storage-table th {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.storage-table input[type='number'] {
  width: 90px;
  padding: 5px 8px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
}

.storage-table input[type='checkbox'] {
  width: auto;
}

.path-cell {
  max-width: 220px;
  overflow-wrap: anywhere;
  color: var(--text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}

.storage-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

@media (max-width: 960px) {
  .settings-layout {
    grid-template-columns: minmax(0, 1fr);
  }

  .settings-nav {
    position: static;
    grid-auto-flow: column;
    grid-auto-columns: max-content;
    overflow-x: auto;
  }

  .settings-nav button {
    text-align: center;
  }

  .proxy-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .profile-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>

<style scoped>
.main-column .page-settings .config-header h1 {
  font-size: 26px;
}

.main-column .page-settings .config-header .eyebrow {
  font-size: 9px;
}

.main-column .page-settings .config-page-hint {
  font-size: 13px;
  line-height: 1.45;
}

.config-stat small {
  font-size: 9px;
}
</style>

<style scoped>
/* Configuration control room */
.main-column .page-settings.config-control {
  --config-accent: #55c7e8;
  --config-mint: #34d399;
  --config-amber: #f0a43a;
  --config-violet: #9d8cff;
  --config-coral: #fb7185;
  --config-panel: color-mix(in srgb, var(--surface) 95%, #071012);
  --config-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-settings.config-control .config-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--config-accent) 24%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--config-accent) 9%, transparent), transparent 38%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--config-accent) 5%, transparent) 37px 38px
    ),
    var(--config-panel) !important;
}

.config-heading {
  display: flex;
  min-width: 0;
  gap: 13px;
  align-items: center;
}

.config-heading > div {
  min-width: 0;
}

.config-robot {
  position: relative;
  display: block;
  flex: 0 0 52px;
  width: 52px;
  height: 52px;
  color: var(--config-accent);
}

.config-antenna {
  position: absolute;
  top: 0;
  left: 21px;
  width: 2px;
  height: 8px;
  background: currentColor;
}

.config-antenna::before {
  position: absolute;
  top: -3px;
  left: -2px;
  width: 5px;
  height: 5px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, currentColor 28%, transparent);
  box-shadow: 0 0 8px color-mix(in srgb, currentColor 48%, transparent);
}

.config-face {
  position: absolute;
  top: 7px;
  left: 3px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  width: 38px;
  height: 25px;
  border: 1px solid currentColor;
  border-radius: 7px;
  background: color-mix(in srgb, currentColor 7%, var(--surface));
}

.config-face b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
  animation: config-eye 3.2s ease-in-out infinite;
}

.config-face em {
  position: absolute;
  bottom: 3px;
  width: 8px;
  height: 1px;
  background: currentColor;
}

.config-body {
  position: absolute;
  bottom: 2px;
  left: 8px;
  width: 28px;
  height: 13px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

.config-gear {
  position: absolute;
  right: 0;
  bottom: 1px;
  width: 18px;
  height: 18px;
  border: 1px solid var(--config-amber);
  border-radius: 50%;
}

.config-gear::before {
  position: absolute;
  inset: 5px;
  content: '';
  border: 1px solid var(--config-amber);
  border-radius: 50%;
}

.main-column .page-settings .config-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.config-header .button {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.config-header .button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
}

.config-status-rail {
  display: grid;
  grid-template-columns: 1.2fr 0.8fr 0.8fr 1fr;
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--config-line);
  border-radius: 5px;
  background: var(--config-line);
}

.config-stat {
  --config-tone: var(--config-accent);
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 7px;
  min-height: 64px;
  padding: 9px 11px;
  background: var(--config-panel);
}

.config-stat::after {
  position: absolute;
  bottom: 0;
  left: 11px;
  width: 28px;
  height: 2px;
  content: '';
  background: var(--config-tone);
}

.config-stat.tone-lock {
  --config-tone: var(--config-amber);
}

.config-stat.tone-restart {
  --config-tone: var(--config-violet);
}

.config-stat.tone-section {
  --config-tone: var(--config-mint);
}

.config-stat > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.1em;
}

.config-stat strong {
  grid-row: span 2;
  align-self: center;
  overflow: hidden;
  max-width: 130px;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 19px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.config-stat small {
  align-self: end;
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.settings-layout {
  display: grid;
  grid-template-columns: 210px minmax(0, 1fr);
  gap: 10px;
  align-items: start;
}

.settings-nav {
  position: sticky;
  top: 10px;
  display: grid;
  gap: 8px;
  padding: 8px;
  border: 1px solid color-mix(in srgb, var(--config-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--config-panel);
}

.config-nav-group {
  display: grid;
  gap: 3px;
}

.config-nav-group > span {
  padding: 5px 7px 3px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
  letter-spacing: 0.1em;
}

.config-nav-group button {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr);
  gap: 7px;
  align-items: center;
  min-width: 0;
  padding: 6px 7px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-secondary);
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.config-nav-group button:hover {
  border-color: color-mix(in srgb, var(--config-accent) 28%, var(--border));
  background: color-mix(in srgb, var(--config-accent) 4%, transparent);
}

.config-nav-group button.active {
  border-color: color-mix(in srgb, var(--config-accent) 48%, var(--border));
  color: var(--text-primary);
  background: color-mix(in srgb, var(--config-accent) 8%, transparent);
  box-shadow: inset 2px 0 0 var(--config-accent);
}

.config-nav-group button b {
  color: var(--config-accent);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 500;
}

.config-nav-group button span {
  overflow: hidden;
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.settings-panels {
  min-width: 0;
}

.settings-sections {
  display: grid;
  gap: 10px;
}

.main-column .page-settings.config-control .settings-panels > .business-card,
.main-column .page-settings.config-control .settings-sections > .business-card {
  position: relative;
  display: grid;
  gap: 11px;
  padding: 14px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--config-accent) 18%, var(--border)) !important;
  border-radius: 5px !important;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--config-accent) 4%, transparent), transparent 110px),
    var(--config-panel) !important;
  box-shadow: none !important;
}

.main-column .page-settings.config-control .settings-panels > .business-card::before,
.main-column .page-settings.config-control .settings-sections > .business-card::before {
  position: absolute;
  top: 0;
  left: 0;
  width: 42px;
  height: 2px;
  content: '';
  background: var(--config-accent);
}

.main-column .page-settings.config-control .business-card > h2 {
  margin: 0;
  padding-bottom: 9px;
  border-bottom: 1px solid var(--border);
  font-size: 13px !important;
}

.profile-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 84px;
  gap: 10px;
  align-items: end;
}

.profile-avatar-preview {
  display: grid;
  gap: 4px;
  justify-items: center;
  color: var(--text-muted);
  font-size: 7px;
}

.profile-avatar-preview img,
.profile-avatar-initial {
  display: grid;
  width: 46px;
  height: 46px;
  object-fit: cover;
  border: 1px solid color-mix(in srgb, var(--config-accent) 35%, var(--border));
  border-radius: 7px;
  color: var(--config-accent);
  background: color-mix(in srgb, var(--config-accent) 7%, var(--surface));
  font-family: var(--mono);
  font-size: 17px;
  place-items: center;
}

.field {
  display: grid;
  gap: 5px;
  min-width: 0;
  color: var(--text-secondary);
  font-size: 10px;
}

.field > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.field input,
.field select,
.field textarea {
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.field input:disabled,
.field select:disabled,
.field textarea:disabled {
  color: var(--text-muted);
  background:
    repeating-linear-gradient(
      -45deg,
      transparent 0 5px,
      color-mix(in srgb, var(--config-amber) 3%, transparent) 5px 10px
    ),
    var(--field-disabled-bg);
}

.field-hint {
  margin: 0;
  color: var(--text-muted);
  font-size: 8px;
  line-height: 1.45;
}

.checkbox-line {
  display: flex;
  gap: 7px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 10px;
}

.checkbox-line input {
  width: auto;
}

.proxy-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 9px;
}

.model-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 6px;
}

.model-select {
  margin-top: 5px;
}

.settings-save-row {
  position: sticky;
  bottom: 0;
  z-index: 2;
  display: flex;
  justify-content: flex-end;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: color-mix(in srgb, var(--config-panel) 94%, transparent);
  backdrop-filter: blur(10px);
}

.password-strength {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 100px 38px;
  gap: 8px;
  align-items: center;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.password-strength > span {
  color: var(--text-muted);
  font-size: 8px;
}

.password-strength > div {
  height: 4px;
  overflow: hidden;
  border-radius: 2px;
  background: var(--border);
}

.password-strength i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--config-coral), var(--config-amber), var(--config-mint));
  transition: width 0.2s ease;
}

.password-strength b {
  color: var(--config-amber);
  font-family: var(--mono);
  font-size: 8px;
  font-weight: 500;
  text-align: right;
}

.password-strength.strong b {
  color: var(--config-mint);
}

.password-checks {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.password-checks li {
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-size: 8px;
}

.password-checks li.ok {
  border-color: color-mix(in srgb, var(--config-mint) 42%, var(--border));
  color: var(--config-mint);
}

.storage-table {
  min-width: 760px;
}

.storage-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.storage-actions .button.danger {
  border-color: color-mix(in srgb, var(--config-coral) 45%, var(--border)) !important;
  color: var(--config-coral) !important;
}

.config-dialog-layer {
  position: fixed;
  inset: 0;
  z-index: 95;
  display: grid;
  padding: 20px;
  background: rgba(5, 8, 9, 0.66);
  backdrop-filter: blur(4px);
  place-items: center;
}

.config-dialog {
  width: min(460px, 100%);
  padding: 16px;
  border: 1px solid color-mix(in srgb, var(--config-coral) 42%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--config-coral) 5%, transparent), transparent 95px),
    var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
}

.config-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
}

.config-code {
  color: var(--config-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.1em;
}

.config-dialog h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 15px;
}

.config-warning {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--config-coral);
  border-radius: 50%;
  color: var(--config-coral);
  font-family: var(--mono);
  font-size: 16px;
  place-items: center;
}

.config-dialog > p {
  margin: 12px 0;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.55;
}

.config-dialog-categories {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  max-height: 100px;
  padding: 7px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.config-dialog-categories span {
  padding: 2px 5px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.config-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  margin-top: 14px;
}

@keyframes config-eye {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@media (max-width: 980px) {
  .settings-layout {
    grid-template-columns: 1fr;
  }

  .settings-nav {
    position: static;
    display: flex;
    overflow-x: auto;
  }

  .config-nav-group {
    display: flex;
    flex: 0 0 auto;
  }

  .config-nav-group > span {
    display: none;
  }

  .config-nav-group button {
    min-width: 120px;
  }

  .config-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .main-column .page-settings.config-control {
    overflow-x: hidden;
  }

  .config-header {
    align-items: stretch;
  }

  .config-heading {
    align-items: flex-start;
  }

  .config-status-rail {
    grid-template-columns: 1fr;
  }

  .settings-layout,
  .settings-panels,
  .settings-sections {
    width: 100%;
    min-width: 0;
  }

  .profile-grid,
  .proxy-grid {
    grid-template-columns: 1fr;
  }

  .profile-avatar-preview {
    justify-self: start;
  }

  .password-strength {
    grid-template-columns: 1fr 38px;
  }

  .password-strength > span {
    grid-column: 1 / -1;
  }

  .storage-table {
    overflow-x: auto;
  }
}

@media (prefers-reduced-motion: reduce) {
  .config-face b {
    animation: none;
  }
}
</style>

<style scoped>
/* Settings in the Vulnerability Management visual system */
.main-column .page-settings.config-control .config-header {
  min-height: 78px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-settings .config-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-settings .config-header .button {
  min-height: 30px;
  padding: 5px 9px;
  border-radius: 3px;
  font-size: 10px;
}

.config-status-rail {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  padding: 0;
  border: 0;
  background: transparent;
}

.config-stat {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 4px;
  align-content: center;
  min-height: 72px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-left: 3px solid #55c7e8;
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.config-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  overflow: hidden;
  color: #55c7e8;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.config-stat-icon {
  width: 16px;
  height: 16px;
  flex: 0 0 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
  opacity: 0.82;
}

.config-stat strong {
  overflow: hidden;
  color: #55c7e8;
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.config-stat::after {
  display: none;
}

.config-stat.tone-lock {
  border-left-color: var(--warning);
}

.config-stat.tone-lock small,
.config-stat.tone-lock strong {
  color: var(--warning);
}

.config-stat.tone-restart {
  border-left-color: var(--danger);
}

.config-stat.tone-restart small,
.config-stat.tone-restart strong {
  color: var(--danger);
}

.config-stat.tone-section {
  border-left-color: var(--success);
}

.config-stat.tone-section small,
.config-stat.tone-section strong {
  color: var(--success);
}

.config-stat.tone-section strong {
  font-size: 16px;
}

.settings-layout {
  gap: 10px;
}

.settings-nav,
.settings-panels,
.settings-sections,
.settings-panels > .business-card {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.settings-nav {
  padding: 8px;
}

.settings-nav button {
  border: 1px solid transparent;
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: transparent;
}

.settings-nav button:hover {
  background: var(--surface-soft);
}

.settings-nav button.active {
  border-color: var(--border);
  border-left-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 6%, var(--surface));
}

.settings-panels > .business-card {
  padding: 16px;
}

.business-card > h2 {
  margin: 0 0 4px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}

.field-hint {
  color: var(--text-muted);
  font-size: 10px;
  line-height: 1.55;
}

.settings-save-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 4px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.settings-panels input,
.settings-panels textarea,
.settings-panels select {
  border-radius: 3px;
  background: var(--field-bg);
}

.config-dialog-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.config-dialog {
  width: min(430px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--danger) 42%, var(--border));
  border-radius: 4px;
  background: var(--surface);
}

@media (max-width: 760px) {
  .config-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
