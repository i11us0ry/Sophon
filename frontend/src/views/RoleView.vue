<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import AgentIdentityRobot from '../components/AgentIdentityRobot.vue'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

const { t } = useI18n()
const auth = useAuthStore()
const canManage = computed(() => auth.hasPermission('agentRole:admin'))
const canReadSkills = computed(() => auth.hasPermission('skills:read'))

interface AgentRole {
  id: string
  name: string
  description: string
  prompt: string
  icon: string
  skills: string[]
  builtin: boolean
  enabled: boolean
  internal?: boolean
  system?: boolean
  kind?: 'system_agent' | 'task_profile'
  mandatory?: boolean
  editable?: boolean
}

interface SkillItem {
  name: string
  description: string
}

type RoleRobotIdentity =
  | 'mainagent'
  | 'planner'
  | 'worker'
  | 'system'
  | 'reviewer'
  | 'writer'
  | 'retest'
  | 'policy'
  | 'profile'

interface RoleRobotVisual {
  identity: RoleRobotIdentity
  accent: string
}

const roles = ref<AgentRole[]>([])
const skills = ref<SkillItem[]>([])
const roleSearch = ref('')
const draft = ref<AgentRole | null>(null)
const systemAgent = ref<AgentRole | null>(null)
const loading = ref(false)
const error = ref('')
const notice = ref('')
const createDraft = reactive({
  name: '',
  description: '',
  prompt: '',
  skills: [] as string[],
  enabled: true,
})
const showCreateModal = ref(false)
const createModalRef = ref<HTMLElement | null>(null)
const createNameInput = ref<HTMLInputElement | null>(null)

const filteredRoles = computed(() => {
  const keyword = roleSearch.value.trim().toLowerCase()
  if (!keyword) {
    return roles.value
  }
  return roles.value.filter((role) => {
    const kind = isSystemRole(role)
      ? t('role.systemAgent')
      : role.builtin
        ? t('role.builtinTaskProfile')
        : t('role.customTaskProfile')
    return [
      role.name,
      role.description,
      kind,
      ...(role.skills ?? []),
    ]
      .join(' ')
      .toLowerCase()
      .includes(keyword)
  })
})
const systemAgents = computed(() => filteredRoles.value.filter(isSystemRole))
const taskProfiles = computed(() => filteredRoles.value.filter((role) => !isSystemRole(role)))
const roleGroups = computed(() => [
  {
    key: 'system',
    title: t('role.systemAgentsTitle'),
    hint: t('role.systemAgentsHint'),
    items: systemAgents.value,
  },
  {
    key: 'task-profile',
    title: t('role.taskProfilesTitle'),
    hint: t('role.taskProfilesHint'),
    items: taskProfiles.value,
  },
])
const draftIsSystem = computed(() => (draft.value ? isSystemRole(draft.value) : false))

function isSystemRole(role: AgentRole) {
  return Boolean(role.internal || role.system || role.kind === 'system_agent')
}

const roleRobotAccents = [
  '#55c7e8',
  '#f0a43a',
  '#fb7185',
  '#34d399',
  '#a78bfa',
  '#22d3ee',
]

function roleRobotVisual(role: AgentRole): RoleRobotVisual {
  switch (role.id) {
    case 'system-main-agent':
      return { identity: 'mainagent', accent: '#f0b94d' }
    case 'system-deep-path-planner':
      return { identity: 'planner', accent: '#55c7e8' }
    case 'system-deep-path-worker':
      return { identity: 'worker', accent: '#ff9f43' }
    case 'system-retest-agent':
      return { identity: 'retest', accent: '#22d3ee' }
    case 'system-vulnerability-reviewer':
      return { identity: 'reviewer', accent: '#34d399' }
    case 'system-vulnerability-writer':
      return { identity: 'writer', accent: '#a78bfa' }
    case 'system-mission-policy':
      return { identity: 'policy', accent: '#d4a72c' }
    default:
      break
  }
  if (isSystemRole(role)) {
    return { identity: 'system', accent: '#8b9aaa' }
  }
  let hash = 0
  for (const character of role.id) {
    hash = (hash * 31 + character.charCodeAt(0)) >>> 0
  }
  return {
    identity: 'profile',
    accent: roleRobotAccents[hash % roleRobotAccents.length],
  }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const roleResponse = await apiGet<{ items: AgentRole[] }>('/agent-roles?includeInternal=true')
    roles.value = roleResponse.items ?? []
    if (canReadSkills.value) {
      try {
        const skillResponse = await apiGet<{ items: SkillItem[] }>('/skills')
        skills.value = skillResponse.items ?? []
      } catch {
        skills.value = []
      }
    } else {
      skills.value = []
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readRolesFailed')
  } finally {
    loading.value = false
  }
}

async function run(action: () => Promise<void>, successText: string) {
  error.value = ''
  notice.value = ''
  try {
    await action()
    if (successText) {
      notice.value = successText
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  }
}

function createTaskProfile() {
  if (!createDraft.name.trim()) {
    error.value = t('role.nameRequired')
    return
  }
  void run(async () => {
    const name = createDraft.name.trim()
    await apiPost<AgentRole>('/agent-roles', {
      name,
      icon: '',
      description: createDraft.description.trim(),
      prompt: createDraft.prompt.trim() || t('role.defaultPrompt', { name }),
      skills: [...createDraft.skills],
      enabled: createDraft.enabled,
    })
    resetCreateDraft()
    showCreateModal.value = false
    await load()
  }, t('role.created'))
}

function resetCreateDraft() {
  createDraft.name = ''
  createDraft.description = ''
  createDraft.prompt = ''
  createDraft.skills = []
  createDraft.enabled = true
}

function openCreateRole() {
  resetCreateDraft()
  showCreateModal.value = true
  void nextTick(() => createNameInput.value?.focus())
}

function closeCreateRole() {
  showCreateModal.value = false
}

function toggleRole(role: AgentRole) {
  if (role.mandatory || (isSystemRole(role) && !role.editable)) {
    return
  }
  void run(async () => {
    await apiPut(`/agent-roles/${role.id}`, {
      name: role.name,
      description: role.description,
      prompt: role.prompt,
      icon: role.icon,
      skills: role.skills,
      enabled: !role.enabled,
    })
    await load()
  }, t('role.stateUpdated'))
}

function removeRole(role: AgentRole) {
  if (isSystemRole(role) || role.mandatory) {
    return
  }
  if (!window.confirm(t('role.confirmDelete', { name: role.name }))) {
    return
  }
  void run(async () => {
    await apiDelete(`/agent-roles/${role.id}`)
    await load()
  }, t('role.deleted'))
}

function toggleSkill(name: string) {
  const current = draft.value
  if (!current) {
    return
  }
  if (current.skills.includes(name)) {
    current.skills = current.skills.filter((item) => item !== name)
    return
  }
  current.skills = [...current.skills, name]
}

function toggleCreateSkill(name: string) {
  if (createDraft.skills.includes(name)) {
    createDraft.skills = createDraft.skills.filter((item) => item !== name)
    return
  }
  createDraft.skills = [...createDraft.skills, name]
}

function saveRole() {
  const current = draft.value
  if (!current) {
    return
  }
  void run(async () => {
    await apiPut(`/agent-roles/${current.id}`, {
      name: current.name,
      description: current.description,
      prompt: current.prompt,
      icon: current.icon,
      skills: current.skills,
      enabled: current.enabled,
    })
    draft.value = null
    await load()
  }, t('role.saved'))
}

function openRoleEditor(role: AgentRole) {
  if ((isSystemRole(role) || role.mandatory) && !role.editable) {
    return
  }
  systemAgent.value = null
  draft.value = { ...role, skills: [...role.skills] }
}

function openSystemAgent(role: AgentRole) {
  draft.value = null
  systemAgent.value = { ...role, skills: [...role.skills] }
}

onMounted(load)
</script>

<template>
  <section class="page factory-page page-roles">
    <header class="page-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="violet" />
        <div>
          <p class="eyebrow">AGENT CONTROL</p>
          <h1>{{ t('nav.roles') }}</h1>
          <p class="page-header-hint">{{ t('role.controlHint') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="button" type="button" :disabled="loading" @click="load">
          {{ t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>

    <div class="role-toolbar">
      <input
        v-model="roleSearch"
        type="search"
        :aria-label="t('role.searchPlaceholder')"
        :placeholder="t('role.searchPlaceholder')"
      />
      <button v-if="canManage" class="button" type="button" @click="openCreateRole">
        {{ t('role.create') }}
      </button>
      <span class="role-filter-count">{{ filteredRoles.length }} / {{ roles.length }}</span>
    </div>

    <template v-if="filteredRoles.length">
      <section
        v-for="group in roleGroups"
        v-show="group.items.length"
        :key="group.key"
        class="role-section"
      >
        <header class="role-section-head">
          <div>
            <h2>{{ group.title }}</h2>
            <p>{{ group.hint }}</p>
          </div>
          <span>{{ group.items.length }}</span>
        </header>
        <div class="role-grid">
          <article
            v-for="role in group.items"
            :key="role.id"
            class="role-card"
            :style="{ '--bot-tone': roleRobotVisual(role).accent }"
          >
            <div class="role-card-unit">
              <div class="role-bot" :class="{ off: !role.enabled }" aria-hidden="true">
                <AgentIdentityRobot
                  :role="roleRobotVisual(role).identity"
                  status="idle"
                  size="lg"
                  :accent="roleRobotVisual(role).accent"
                />
              </div>
              <div class="role-card-content">
                <div class="role-card-title">
                  <h2>{{ role.name }}</h2>
                  <span
                    class="role-state"
                    :class="{ off: !role.enabled, mandatory: role.mandatory }"
                  >
                    {{
                      role.mandatory
                        ? t('role.mandatoryEnabled')
                        : role.enabled
                          ? t('common.enable')
                          : t('common.disable')
                    }}
                  </span>
                </div>
                <div class="role-meta">
                  <span>
                    {{
                      isSystemRole(role)
                        ? t('role.systemAgent')
                        : role.builtin
                          ? t('role.builtinTaskProfile')
                          : t('role.customTaskProfile')
                    }}
                  </span>
                  <span>{{ t('role.skillCount', { count: role.skills.length }) }}</span>
                </div>
              </div>
            </div>
            <p class="role-description" :title="role.description || t('role.noDescription')">
              {{ role.description || t('role.noDescription') }}
            </p>
            <footer>
              <button
                v-if="isSystemRole(role)"
                class="button compact"
                type="button"
                @click="openSystemAgent(role)"
              >
                {{ t('role.viewResponsibilities') }}
              </button>
              <button
                v-if="canManage && (!isSystemRole(role) || role.editable)"
                class="button compact"
                type="button"
                @click="openRoleEditor(role)"
              >
                {{ t('common.edit') }}
              </button>
              <button
                v-if="canManage && (!isSystemRole(role) || role.editable)"
                class="button compact"
                type="button"
                @click="toggleRole(role)"
              >
                {{ role.enabled ? t('common.disable') : t('common.enable') }}
              </button>
              <button
                v-if="canManage && !isSystemRole(role)"
                class="button compact danger"
                type="button"
                :title="role.builtin ? t('role.builtinDeleteHint') : ''"
                @click="removeRole(role)"
              >
                {{ t('common.delete') }}
              </button>
            </footer>
          </article>
        </div>
      </section>
    </template>
    <div v-else-if="!loading" class="role-empty">{{ t('role.searchEmpty') }}</div>

    <aside v-if="draft" class="role-drawer">
      <header class="drawer-header">
        <h2>{{ draftIsSystem ? t('role.editSystemAgent') : t('role.editTitle') }}</h2>
        <button class="text-button dark" type="button" @click="draft = null">{{ t('common.close') }}</button>
      </header>
      <div class="drawer-body">
        <label>
          <span>{{ t('role.name') }}</span>
          <input v-model="draft.name" :disabled="draft.builtin" />
        </label>
        <label>
          <span>{{ t('role.description') }}</span>
          <input v-model="draft.description" />
        </label>
        <label>
          <span>{{ draftIsSystem ? t('role.systemPrompt') : t('role.methodPrompt') }}</span>
          <textarea v-model="draft.prompt" rows="8"></textarea>
        </label>
        <label class="checkbox-line">
          <input v-model="draft.enabled" type="checkbox" :disabled="draft.mandatory" />
          <span>{{ draftIsSystem ? t('role.enableSystemAgent') : t('role.enableLabel') }}</span>
        </label>
        <div v-if="canReadSkills && !draftIsSystem" class="skill-picker">
          <span>{{ t('role.bindSkills') }}</span>
          <div class="skill-options">
            <label v-for="skill in skills" :key="skill.name" class="checkbox-line">
              <input
                type="checkbox"
                :checked="draft.skills.includes(skill.name)"
                @change="toggleSkill(skill.name)"
              />
              <span>{{ skill.name }}</span>
            </label>
          </div>
        </div>
      </div>
      <footer class="drawer-footer">
        <button class="button" type="button" @click="saveRole">{{ t('common.save') }}</button>
        <button class="button compact" type="button" @click="draft = null">{{ t('common.cancel') }}</button>
      </footer>
    </aside>

    <aside v-if="systemAgent" class="role-drawer system-agent-drawer">
      <header class="drawer-header">
        <div class="system-agent-heading">
          <AgentIdentityRobot
            :role="roleRobotVisual(systemAgent).identity"
            status="idle"
            size="md"
            :accent="roleRobotVisual(systemAgent).accent"
          />
          <div>
            <h2>{{ systemAgent.name }}</h2>
            <small>{{ t('role.systemAgent') }}</small>
          </div>
        </div>
        <button class="text-button dark" type="button" @click="systemAgent = null">
          {{ t('common.close') }}
        </button>
      </header>
      <div class="drawer-body">
        <div class="system-agent-banner">
          <span class="system-agent-dot" aria-hidden="true"></span>
          <div>
            <strong>
              {{
                systemAgent.mandatory
                  ? t('role.mandatoryEnabled')
                  : systemAgent.enabled
                    ? t('common.enable')
                    : t('common.disable')
              }}
            </strong>
            <small>
              {{
                systemAgent.mandatory
                  ? t('role.alwaysEnabledHint')
                  : t('role.toggleableSystemHint')
              }}
            </small>
          </div>
        </div>
        <label>
          <span>{{ t('role.description') }}</span>
          <input :value="systemAgent.description" readonly />
        </label>
        <label class="system-agent-prompt-field">
          <span>{{ t('role.prompt') }}</span>
          <textarea
            :value="systemAgent.prompt"
            class="system-agent-prompt"
            readonly
            rows="28"
            spellcheck="false"
          ></textarea>
        </label>
      </div>
      <footer class="drawer-footer">
        <button class="button compact" type="button" @click="systemAgent = null">
          {{ t('common.close') }}
        </button>
      </footer>
    </aside>

    <div v-if="showCreateModal" class="role-modal-backdrop" @click.self="closeCreateRole">
      <section
        ref="createModalRef"
        class="role-modal"
        role="dialog"
        aria-modal="true"
        tabindex="-1"
        @keydown.esc="closeCreateRole"
      >
        <header class="role-modal-head">
          <h3>{{ t('role.create') }}</h3>
          <button class="text-button dark" type="button" @click="closeCreateRole">
            {{ t('common.close') }}
          </button>
        </header>
        <div class="role-modal-body">
          <label>
            <span>{{ t('role.name') }}</span>
            <input
              ref="createNameInput"
              v-model="createDraft.name"
              :placeholder="t('role.newName')"
            />
          </label>
          <label>
            <span>{{ t('role.description') }}</span>
            <input
              v-model="createDraft.description"
              :placeholder="t('role.descriptionPlaceholder')"
            />
          </label>
          <label>
            <span>{{ t('role.prompt') }}</span>
            <textarea v-model="createDraft.prompt" rows="8"></textarea>
          </label>
          <label class="checkbox-line">
            <input v-model="createDraft.enabled" type="checkbox" />
            <span>{{ t('role.enableLabel') }}</span>
          </label>
          <div v-if="canReadSkills" class="skill-picker">
            <span>{{ t('role.bindSkills') }}</span>
            <div class="skill-options">
              <label v-for="skill in skills" :key="skill.name" class="checkbox-line">
                <input
                  type="checkbox"
                  :checked="createDraft.skills.includes(skill.name)"
                  @change="toggleCreateSkill(skill.name)"
                />
                <span>{{ skill.name }}</span>
              </label>
            </div>
          </div>
        </div>
        <footer class="role-modal-foot">
          <button class="button" type="button" @click="createTaskProfile">{{ t('role.create') }}</button>
          <button class="button compact" type="button" @click="closeCreateRole">
            {{ t('common.cancel') }}
          </button>
        </footer>
      </section>
    </div>
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

.role-section {
  display: grid;
  gap: 10px;
  margin-top: 16px;
}

.role-section-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  padding: 0 2px 8px;
  border-bottom: 1px solid var(--line);
}

.role-section-head h2 {
  margin: 0;
  font-size: 14px;
}

.role-section-head p {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.role-section-head > span {
  min-width: 24px;
  padding: 2px 6px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 10px;
  text-align: center;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 14px;
  min-width: 0;
  width: 100%;
}

.role-card {
  position: relative;
  display: grid;
  grid-template-rows: auto minmax(38px, auto) auto;
  gap: 12px;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  min-height: 194px;
  padding: 16px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
  overflow: hidden;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.role-card::before {
  position: absolute;
  top: 0;
  left: 16px;
  width: 48px;
  height: 2px;
  content: '';
  background: var(--bot-tone);
  opacity: 0.7;
}

.role-card:nth-child(4n + 1) {
  --bot-tone: #55c7e8;
}

.role-card:nth-child(4n + 2) {
  --bot-tone: #f0a43a;
}

.role-card:nth-child(4n + 3) {
  --bot-tone: #fb7185;
}

.role-card:nth-child(4n + 4) {
  --bot-tone: #34d399;
}

.role-card:hover {
  border-color: color-mix(in srgb, var(--bot-tone) 52%, var(--line)) !important;
  transform: translateY(-2px);
}

.role-card-unit {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr);
  gap: 12px;
  align-items: center;
  min-width: 0;
}

.role-bot {
  position: relative;
  display: grid;
  place-items: center;
  width: 54px;
  height: 62px;
  color: var(--bot-tone);
  background:
    linear-gradient(
      90deg,
      transparent 49%,
      color-mix(in srgb, var(--bot-tone) 10%, transparent) 50%,
      transparent 51%
    ),
    linear-gradient(
      0deg,
      transparent 49%,
      color-mix(in srgb, var(--bot-tone) 10%, transparent) 50%,
      transparent 51%
    );
  background-size: 12px 12px;
  border: 1px solid color-mix(in srgb, var(--bot-tone) 24%, var(--line));
  border-radius: 6px;
}

.role-bot-antenna {
  position: absolute;
  top: 7px;
  left: 50%;
  width: 2px;
  height: 7px;
  background: currentColor;
  transform: translateX(-50%);
}

.role-bot-antenna::before {
  position: absolute;
  top: -5px;
  left: 50%;
  width: 5px;
  height: 5px;
  content: '';
  border: 1px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, var(--bot-tone) 34%, var(--surface));
  box-shadow: 0 0 8px color-mix(in srgb, var(--bot-tone) 55%, transparent);
  transform: translateX(-50%);
  animation: role-bot-signal 2.8s ease-in-out infinite;
}

.role-bot-head {
  position: absolute;
  top: 14px;
  left: 50%;
  display: flex;
  gap: 6px;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 20px;
  border: 1.5px solid currentColor;
  border-radius: 4px;
  background: color-mix(in srgb, var(--bot-tone) 8%, var(--surface));
  transform: translateX(-50%);
}

.role-bot-mouth {
  position: absolute;
  bottom: 2px;
  left: 50%;
  width: 9px;
  height: 5px;
  border-bottom: 1.5px solid color-mix(in srgb, var(--bot-tone) 68%, transparent);
  border-radius: 0 0 6px 6px;
  transform: translateX(-50%);
  transition:
    height 0.18s ease,
    bottom 0.18s ease,
    border-color 0.18s ease;
}

.role-bot.off .role-bot-mouth {
  bottom: 3px;
  height: 4px;
  border-top: 1.5px solid color-mix(in srgb, var(--text-muted) 72%, transparent);
  border-bottom: 0;
  border-radius: 8px 8px 0 0;
}

.role-bot-head i {
  width: 5px;
  height: 3px;
  margin-top: -3px;
  border-radius: 1px;
  background: currentColor;
  box-shadow: 0 0 7px color-mix(in srgb, var(--bot-tone) 70%, transparent);
  transform-origin: center;
  animation: role-bot-blink 6.5s ease-in-out infinite;
}

.role-bot-head i:nth-child(2) {
  animation-delay: 0.04s;
}

.role-bot-body {
  position: absolute;
  bottom: 6px;
  left: 50%;
  display: grid;
  place-items: center;
  width: 42px;
  height: 22px;
  border: 1.5px solid currentColor;
  border-radius: 4px;
  background: color-mix(in srgb, var(--bot-tone) 6%, var(--surface));
  transform: translateX(-50%);
}

.role-bot-body::before,
.role-bot-body::after {
  position: absolute;
  top: 6px;
  width: 5px;
  height: 1.5px;
  content: '';
  background: color-mix(in srgb, var(--bot-tone) 42%, transparent);
}

.role-bot-body::before {
  left: -7px;
}

.role-bot-body::after {
  right: -7px;
}

.role-bot-core {
  width: 7px;
  height: 7px;
  border: 1.5px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, var(--bot-tone) 30%, var(--surface));
}

.role-bot.off {
  color: var(--text-muted);
  opacity: 0.52;
}

.role-bot.off :deep(.agent-robot) {
  filter: grayscale(1);
  opacity: 0.72;
}

.role-bot.off .role-bot-antenna::before,
.role-bot.off .role-bot-head i {
  animation: none;
}

.role-card-content {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.role-card-title {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
  min-width: 0;
}

.role-card h2 {
  margin: 0;
  font-size: 16px;
  line-height: 1.35;
  overflow-wrap: anywhere;
}

.role-state {
  display: inline-flex;
  flex: 0 0 auto;
  gap: 5px;
  align-items: center;
  padding: 2px 8px;
  border: 1px solid currentColor;
  border-radius: 999px;
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
  font-family: var(--mono);
  font-size: 10px;
  line-height: 1.5;
}

.role-state::before {
  width: 5px;
  height: 5px;
  content: '';
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px color-mix(in srgb, currentColor 64%, transparent);
}

.role-state.off {
  color: var(--text-muted);
  background: var(--surface-soft);
}

.role-state.mandatory {
  color: var(--warning);
  background: color-mix(in srgb, var(--warning) 10%, var(--surface));
}

.role-state.mandatory::before {
  box-shadow: 0 0 7px color-mix(in srgb, var(--warning) 58%, transparent);
}

.role-state.off::before {
  box-shadow: none;
}

.role-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.role-meta span {
  padding: 2px 6px;
  border: 1px solid color-mix(in srgb, var(--line) 82%, transparent);
  border-radius: 3px;
  color: var(--text-muted);
  background: color-mix(in srgb, var(--surface-soft) 72%, transparent);
  font-family: var(--mono);
  font-size: 9px;
  line-height: 1.5;
}

.role-description {
  display: -webkit-box;
  min-height: 38px;
  margin: 0;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.5;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.role-card footer {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding-top: 10px;
  border-top: 1px solid color-mix(in srgb, var(--line) 66%, transparent);
}

@keyframes role-bot-blink {
  0%,
  43%,
  49%,
  100% {
    transform: scaleY(1);
  }

  46% {
    transform: scaleY(0.14);
  }
}

@keyframes role-bot-signal {
  0%,
  100% {
    opacity: 0.4;
  }

  50% {
    opacity: 1;
  }
}

@media (max-width: 760px) {
  .role-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .role-card {
    padding: 14px;
  }

  .role-card-unit {
    grid-template-columns: 52px minmax(0, 1fr);
    gap: 10px;
  }

  .role-bot {
    width: 48px;
    height: 56px;
  }

  .role-bot-head {
    top: 13px;
    width: 31px;
    height: 18px;
  }

  .role-bot-body {
    bottom: 5px;
    width: 38px;
    height: 20px;
  }

  .role-card-title {
    align-items: flex-start;
  }

  .role-card footer .button {
    flex: 1 1 calc(33.333% - 6px);
  }
}

@media (prefers-reduced-motion: reduce) {
  .role-bot-antenna::before,
  .role-bot-head i {
    animation: none;
  }
}

.role-drawer {
  position: fixed;
  top: 0;
  right: 0;
  z-index: 20;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(560px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
}

.system-agent-drawer {
  width: min(620px, 100%);
}

.drawer-header,
.drawer-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-soft);
}

.drawer-footer {
  justify-content: flex-end;
  border-top: 1px solid var(--line);
  border-bottom: 0;
}

.drawer-header h2 {
  margin: 0;
  font-size: 17px;
}

.drawer-header small {
  color: var(--text-muted);
  font-size: 11px;
}

.text-button.dark {
  color: var(--text-muted);
}

.drawer-body {
  display: grid;
  gap: 12px;
  align-content: start;
  padding: 18px 20px;
  overflow: auto;
}

.drawer-body label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.system-agent-banner {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: 11px 12px;
  border: 1px solid color-mix(in srgb, var(--warning) 28%, var(--line));
  border-radius: 4px;
  background: color-mix(in srgb, var(--warning) 6%, var(--surface-soft));
}

.system-agent-heading {
  display: flex;
  align-items: center;
  gap: 10px;
}

.system-agent-banner > div {
  display: grid;
  gap: 3px;
}

.system-agent-banner strong {
  color: var(--warning);
  font-size: 12px;
  font-weight: 600;
}

.system-agent-banner small {
  color: var(--text-muted);
  font-size: 11px;
  line-height: 1.5;
}

.system-agent-dot {
  width: 7px;
  height: 7px;
  flex: 0 0 auto;
  margin-top: 5px;
  border-radius: 50%;
  background: var(--warning);
  box-shadow: 0 0 7px color-mix(in srgb, var(--warning) 55%, transparent);
}

.system-agent-prompt-field {
  min-height: 0;
}

.system-agent-prompt {
  min-height: 420px;
  resize: vertical;
  font-family: var(--mono) !important;
  font-size: 11px !important;
  line-height: 1.6 !important;
  tab-size: 2;
  white-space: pre;
}

.drawer-body input,
.drawer-body textarea,
.drawer-body select {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-weight: 400;
}

.checkbox-line {
  display: flex !important;
  gap: 8px;
  align-items: center;
  font-weight: 400 !important;
}

.checkbox-line input {
  width: auto;
}

.skill-picker {
  display: grid;
  gap: 8px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.skill-options {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 6px 12px;
  max-height: 220px;
  overflow: auto;
}

.role-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 6, 12, 0.55);
}

.role-modal {
  display: grid;
  gap: 14px;
  width: min(100%, 560px);
  max-height: min(86vh, 760px);
  overflow: auto;
  padding: 20px 22px 22px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.role-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.role-modal-head h3 {
  margin: 0;
  font-size: 16px;
}

.role-modal-body {
  display: grid;
  gap: 12px;
}

.role-modal-body label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.role-modal-body input,
.role-modal-body textarea,
.role-modal-body select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 400;
}

.role-modal-body .checkbox-line input {
  width: auto;
}

.role-modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.role-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  min-width: 0;
}

.role-toolbar input {
  min-width: 0;
  flex: 1 1 240px;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.role-filter-count {
  flex: 0 0 auto;
  padding: 4px 8px;
  border: 1px solid var(--accent-line);
  border-radius: 3px;
  color: var(--accent);
  background: var(--accent-soft);
  font-family: var(--mono);
  font-size: 10px;
}

.role-empty {
  margin: 0;
  padding: 30px 16px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  color: var(--text-muted);
  text-align: center;
}

@media (max-width: 760px) {
  .role-toolbar {
    align-items: stretch;
  }

  .role-toolbar input {
    width: 100%;
    min-height: 38px;
    flex: 0 0 auto;
  }

  .role-toolbar .button {
    width: 100%;
    flex: 0 0 auto;
  }

  .role-filter-count {
    align-self: flex-start;
  }
}
</style>
