<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'

const { t } = useI18n()

interface SkillItem {
  name: string
  description: string
  tags: string[]
  enabled: boolean
  path: string
  fileCount: number
}

interface SkillDetail extends SkillItem {
  content: string
}

const skills = ref<SkillItem[]>([])
const editing = ref<SkillItem | null>(null)
const content = ref('')
const search = ref('')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const createDraft = reactive({ name: '', description: '', content: '' })
const showCreateModal = ref(false)
const createModalRef = ref<HTMLElement | null>(null)
const createNameInput = ref<HTMLInputElement | null>(null)

const filtered = computed(() => {
  const keyword = search.value.trim().toLowerCase()
  if (!keyword) {
    return skills.value
  }
  return skills.value.filter((skill) =>
    [skill.name, skill.description, skill.tags.join(' ')]
      .join(' ')
      .toLowerCase()
      .includes(keyword),
  )
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<{ items: SkillItem[] }>('/skills')
    skills.value = response.items ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : '读取技能失败'
  } finally {
    loading.value = false
  }
}

async function run(action: () => Promise<void>, successText = '') {
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

function createSkill() {
  if (!createDraft.name.trim()) {
    error.value = '技能名称不能为空'
    return
  }
  void run(async () => {
    await apiPost('/skills', {
      name: createDraft.name.trim(),
      description: createDraft.description.trim(),
      content: createDraft.content,
    })
    createDraft.name = ''
    createDraft.description = ''
    createDraft.content = ''
    showCreateModal.value = false
    await load()
  }, t('skill.created'))
}

function openCreateSkill() {
  createDraft.name = ''
  createDraft.description = ''
  createDraft.content = ''
  showCreateModal.value = true
  void nextTick(() => createNameInput.value?.focus())
}

function closeCreateSkill() {
  showCreateModal.value = false
}

function openSkill(skill: SkillItem) {
  void run(async () => {
    const detail = await apiGet<SkillDetail>(`/skills/${skill.name}`)
    editing.value = detail
    content.value = detail.content
  })
}

function saveSkill() {
  const current = editing.value
  if (!current) {
    return
  }
  void run(async () => {
    await apiPut(`/skills/${current.name}`, { content: content.value })
    editing.value = null
    await load()
  }, t('skill.saved'))
}

function removeSkill(skill: SkillItem) {
  if (!window.confirm(t('skill.confirmDelete', { name: skill.name }))) {
    return
  }
  void run(async () => {
    await apiDelete(`/skills/${skill.name}`)
    await load()
  }, t('skill.deleted'))
}

onMounted(load)
</script>

<template>
  <section class="page factory-page page-skills">
    <header class="page-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="indigo" />
        <div>
          <p class="eyebrow">SKILL LIBRARY</p>
          <h1>{{ t('nav.skills') }}</h1>
          <p class="page-header-hint">{{ t('skill.controlHint') }}</p>
        </div>
      </div>
      <button class="button" type="button" :disabled="loading" @click="load">{{ t('common.refresh') }}</button>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>

    <div class="skill-toolbar">
      <input
        v-model="search"
        type="search"
        :aria-label="t('skill.searchPlaceholder')"
        :placeholder="t('skill.searchPlaceholder')"
      />
      <button class="button" type="button" @click="openCreateSkill">{{ t('skill.create') }}</button>
      <span class="skill-filter-count">{{ filtered.length }} / {{ skills.length }}</span>
    </div>

    <div v-if="filtered.length" class="skill-grid">
      <article v-for="skill in filtered" :key="skill.name" class="skill-card">
        <div class="skill-card-main">
          <div class="skill-module" :class="{ off: !skill.enabled }" aria-hidden="true">
            <span class="skill-module-chip"><span class="skill-module-core"></span></span>
          </div>
          <div class="skill-card-content">
            <div class="skill-card-title">
              <h2 :title="skill.name">{{ skill.name }}</h2>
              <span class="skill-badge">{{ t('skill.fileCount') }} {{ skill.fileCount }}</span>
            </div>
            <div class="skill-tags">
              <span v-for="tag in skill.tags" :key="tag" class="tag">{{ tag }}</span>
              <span v-if="!skill.tags.length" class="tag empty">-</span>
            </div>
          </div>
        </div>
        <p class="skill-description" :title="skill.description || t('role.noDescription')">
          {{ skill.description || t('role.noDescription') }}
        </p>
        <footer>
          <button class="button compact" type="button" @click="openSkill(skill)">
            {{ t('common.view') }}
          </button>
          <button class="button compact danger" type="button" @click="removeSkill(skill)">
            {{ t('common.delete') }}
          </button>
        </footer>
      </article>
    </div>
    <div v-else-if="!loading" class="skill-empty">
      <div class="skill-empty-module" aria-hidden="true">
        <span class="skill-module-chip"><span class="skill-module-core"></span></span>
      </div>
      <p>{{ t('skill.empty') }}</p>
    </div>

    <div v-if="showCreateModal" class="skill-modal-backdrop" @click.self="closeCreateSkill">
      <section
        ref="createModalRef"
        class="skill-modal"
        role="dialog"
        aria-modal="true"
        tabindex="-1"
        @keydown.esc="closeCreateSkill"
      >
        <header class="skill-modal-head">
          <h3>{{ t('skill.create') }}</h3>
          <button class="text-button dark" type="button" @click="closeCreateSkill">
            {{ t('common.close') }}
          </button>
        </header>
        <div class="skill-modal-body">
          <label>
            <span>{{ t('skill.name') }}</span>
            <input
              ref="createNameInput"
              v-model="createDraft.name"
              :placeholder="t('skill.newName')"
            />
          </label>
          <label>
            <span>{{ t('skill.description') }}</span>
            <input
              v-model="createDraft.description"
              :placeholder="t('skill.newDescription')"
            />
          </label>
          <label>
            <span>SKILL.md</span>
            <textarea v-model="createDraft.content" rows="20"></textarea>
          </label>
        </div>
        <footer class="skill-modal-foot">
          <button class="button" type="button" @click="createSkill">{{ t('skill.create') }}</button>
          <button class="button compact" type="button" @click="closeCreateSkill">
            {{ t('common.cancel') }}
          </button>
        </footer>
      </section>
    </div>

    <aside v-if="editing" class="skill-drawer">
      <header class="drawer-header">
        <div class="drawer-heading">
          <div class="skill-module compact" :class="{ off: !editing.enabled }" aria-hidden="true">
            <span class="skill-module-chip"><span class="skill-module-core"></span></span>
          </div>
          <div>
            <h2>{{ editing.name }}</h2>
            <small>{{ editing.path }}</small>
          </div>
        </div>
        <button class="text-button dark" type="button" @click="editing = null">{{ t('common.close') }}</button>
      </header>
      <div class="drawer-body">
        <p class="drawer-description">{{ editing.description || t('role.noDescription') }}</p>
        <label>
          <span>SKILL.md</span>
          <textarea v-model="content" rows="24"></textarea>
        </label>
      </div>
      <footer class="drawer-footer">
        <button class="button" type="button" @click="saveSkill">{{ t('common.save') }}</button>
        <button class="button compact" type="button" @click="editing = null">{{ t('common.cancel') }}</button>
      </footer>
    </aside>
  </section>
</template>

<style scoped>
.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.skill-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  min-width: 0;
}

.skill-toolbar input {
  flex: 1 1 240px;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.skill-filter-count {
  flex: 0 0 auto;
  padding: 4px 8px;
  border: 1px solid var(--accent-line);
  border-radius: 3px;
  color: var(--accent);
  background: var(--accent-soft);
  font-family: var(--mono);
  font-size: 10px;
}

.skill-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
  gap: 14px;
  min-width: 0;
  width: 100%;
}

.skill-card {
  position: relative;
  display: grid;
  grid-template-rows: auto minmax(38px, auto) auto;
  gap: 12px;
  align-content: start;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  min-height: 184px;
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

.skill-card::before {
  position: absolute;
  top: 0;
  left: 16px;
  width: 46px;
  height: 2px;
  content: '';
  background: var(--skill-tone);
  opacity: 0.72;
}

.skill-card:nth-child(4n + 1) {
  --skill-tone: #55c7e8;
}

.skill-card:nth-child(4n + 2) {
  --skill-tone: #f0a43a;
}

.skill-card:nth-child(4n + 3) {
  --skill-tone: #fb7185;
}

.skill-card:nth-child(4n + 4) {
  --skill-tone: #34d399;
}

.skill-card:hover {
  border-color: color-mix(in srgb, var(--skill-tone) 50%, var(--line)) !important;
  transform: translateY(-2px);
}

.skill-card-main {
  display: grid;
  grid-template-columns: 54px minmax(0, 1fr);
  gap: 12px;
  align-items: center;
  min-width: 0;
}

.skill-module {
  position: relative;
  display: grid;
  place-items: center;
  width: 52px;
  height: 52px;
  color: var(--skill-tone, #55c7e8);
  border: 1px solid color-mix(in srgb, var(--skill-tone, #55c7e8) 24%, var(--line));
  border-radius: 6px;
  background:
    linear-gradient(
      90deg,
      transparent 49%,
      color-mix(in srgb, var(--skill-tone, #55c7e8) 9%, transparent) 50%,
      transparent 51%
    ),
    linear-gradient(
      0deg,
      transparent 49%,
      color-mix(in srgb, var(--skill-tone, #55c7e8) 9%, transparent) 50%,
      transparent 51%
    );
  background-size: 12px 12px;
}

.skill-module::before,
.skill-module::after {
  position: absolute;
  top: 12px;
  width: 4px;
  height: 29px;
  content: '';
  background: repeating-linear-gradient(
    180deg,
    currentColor 0 4px,
    transparent 4px 8px
  );
  opacity: 0.6;
}

.skill-module::before {
  left: -3px;
}

.skill-module::after {
  right: -3px;
}

.skill-module-chip {
  position: relative;
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border: 1.5px solid currentColor;
  border-radius: 4px;
  background: color-mix(in srgb, var(--skill-tone, #55c7e8) 8%, var(--surface));
}

.skill-module-chip::before {
  position: absolute;
  inset: 4px;
  content: '';
  border: 1px solid color-mix(in srgb, var(--skill-tone, #55c7e8) 34%, transparent);
  border-radius: 2px;
}

.skill-module-core {
  position: relative;
  z-index: 1;
  width: 8px;
  height: 8px;
  border: 1.5px solid currentColor;
  border-radius: 50%;
  background: color-mix(in srgb, var(--skill-tone, #55c7e8) 28%, var(--surface));
  box-shadow: 0 0 8px color-mix(in srgb, var(--skill-tone, #55c7e8) 52%, transparent);
  animation: skill-module-pulse 3.2s ease-in-out infinite;
}

.skill-module.off {
  color: var(--text-muted);
  opacity: 0.52;
}

.skill-module.off .skill-module-core {
  animation: none;
  box-shadow: none;
}

.skill-card-content {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.skill-card-title {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  justify-content: space-between;
  min-width: 0;
}

.skill-card h2 {
  flex: 1 1 auto;
  min-width: 0;
  margin: 0;
  overflow: hidden;
  font-size: 16px;
  line-height: 1.35;
  text-overflow: ellipsis;
  overflow-wrap: anywhere;
}

.skill-badge {
  flex: 0 0 auto;
  padding: 2px 8px;
  border: 1px solid color-mix(in srgb, var(--line) 82%, transparent);
  border-radius: 999px;
  color: var(--text-muted);
  background: color-mix(in srgb, var(--surface-soft) 68%, transparent);
  font-family: var(--mono);
  font-size: 10px;
  line-height: 1.5;
}

.skill-description {
  display: -webkit-box;
  min-height: 38px;
  margin: 0;
  overflow: hidden;
  color: var(--text-secondary);
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  font-size: 13px;
  line-height: 1.5;
}

.tag {
  display: inline-block;
  padding: 1px 6px;
  border: 1px solid color-mix(in srgb, var(--skill-tone, #55c7e8) 18%, var(--border));
  border-radius: 3px;
  color: color-mix(in srgb, var(--text-secondary) 88%, var(--skill-tone, #55c7e8));
  background: color-mix(in srgb, var(--skill-tone, #55c7e8) 6%, var(--surface-soft));
  font-family: var(--mono);
  font-size: 10px;
  line-height: 1.55;
}

.tag.empty {
  color: var(--text-muted);
  border-color: var(--border);
  background: var(--surface-soft);
}

.skill-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  min-height: 18px;
  color: var(--text-muted);
  font-size: 12px;
}

.skill-card footer {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding-top: 8px;
  border-top: 1px solid color-mix(in srgb, var(--line) 66%, transparent);
}

.skill-card footer .button {
  min-width: 0;
}

.skill-empty {
  display: grid;
  place-items: center;
  gap: 12px;
  padding: 34px 12px;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
}

.skill-empty p {
  margin: 0;
}

.skill-empty-module {
  --skill-tone: var(--text-muted);
  position: relative;
  display: grid;
  place-items: center;
  width: 48px;
  height: 48px;
  color: var(--text-muted);
  border: 1px solid var(--border);
  border-radius: 6px;
  opacity: 0.72;
}

.skill-empty-module::before,
.skill-empty-module::after {
  position: absolute;
  top: 11px;
  width: 4px;
  height: 26px;
  content: '';
  background: repeating-linear-gradient(
    180deg,
    currentColor 0 3px,
    transparent 3px 7px
  );
  opacity: 0.5;
}

.skill-empty-module::before {
  left: -3px;
}

.skill-empty-module::after {
  right: -3px;
}

.skill-empty-module .skill-module-chip {
  width: 26px;
  height: 26px;
}

.skill-empty-module .skill-module-core {
  animation: none;
  box-shadow: none;
}

.skill-drawer {
  position: fixed;
  top: 0;
  right: 0;
  z-index: 20;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(720px, 100%);
  height: 100vh;
  border-left: 1px solid var(--line);
  background: var(--surface);
  box-shadow: -6px 0 0 var(--block-shadow);
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

.drawer-heading {
  display: flex;
  gap: 12px;
  align-items: center;
  min-width: 0;
}

.drawer-heading > div:last-child {
  display: grid;
  gap: 2px;
  min-width: 0;
}

.skill-module.compact {
  --skill-tone: #55c7e8;
  flex: 0 0 auto;
  width: 40px;
  height: 40px;
}

.skill-module.compact::before,
.skill-module.compact::after {
  top: 9px;
  height: 22px;
}

.skill-module.compact .skill-module-chip {
  width: 24px;
  height: 24px;
  border-width: 1px;
}

.skill-module.compact .skill-module-chip::before {
  inset: 4px;
}

.skill-module.compact .skill-module-core {
  width: 6px;
  height: 6px;
  border-width: 1px;
}

.drawer-header small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
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

.drawer-description {
  margin: 0;
  color: var(--text-secondary);
  font-size: 13px;
}

.drawer-body label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.drawer-body textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}

.skill-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 6, 12, 0.55);
}

.skill-modal {
  display: grid;
  gap: 14px;
  width: min(100%, 720px);
  max-height: min(86vh, 760px);
  overflow: auto;
  padding: 20px 22px 22px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.skill-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.skill-modal-head h3 {
  margin: 0;
  font-size: 16px;
}

.skill-modal-body {
  display: grid;
  gap: 12px;
}

.skill-modal-body label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 700;
}

.skill-modal-body input,
.skill-modal-body textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 400;
}

.skill-modal-body textarea {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}

.skill-modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

@keyframes skill-module-pulse {
  0%,
  100% {
    opacity: 0.55;
  }

  50% {
    opacity: 1;
  }
}

@media (max-width: 760px) {
  .skill-toolbar {
    align-items: stretch;
  }

  .skill-toolbar input {
    flex: 0 0 auto;
    width: 100%;
    min-height: 38px;
  }

  .skill-toolbar .button {
    flex: 0 0 auto;
    width: 100%;
  }

  .skill-filter-count {
    align-self: flex-start;
  }

  .skill-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .skill-card {
    padding: 14px;
  }

  .skill-card-main {
    grid-template-columns: 50px minmax(0, 1fr);
    gap: 10px;
  }

  .skill-module {
    width: 46px;
    height: 50px;
  }

  .skill-module::before,
  .skill-module::after {
    top: 11px;
    height: 28px;
  }

  .skill-module-chip {
    width: 26px;
    height: 26px;
  }

  .skill-card footer .button {
    flex: 1 1 calc(50% - 4px);
  }

  .drawer-heading {
    gap: 9px;
  }

  .skill-module.compact {
    width: 38px;
    height: 38px;
  }

  .skill-module.compact::before,
  .skill-module.compact::after {
    top: 8px;
    height: 20px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .skill-module-core {
    animation: none;
  }
}

.main-column .page-skills .skill-toolbar {
  padding: 0 !important;
  border: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
}
</style>
