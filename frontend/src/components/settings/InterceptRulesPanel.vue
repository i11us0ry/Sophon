<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../../api/client'
import { useI18n } from '../../i18n'

const props = defineProps<{ writable: boolean }>()
const { t } = useI18n()

type InterceptAction = 'allow' | 'ask' | 'deny'
type InterceptTarget = 'tool_name' | 'tool_input'
type InterceptMatchType = 'regex' | 'string'

interface InterceptRule {
  id: string
  name: string
  enabled: boolean
  priority: number
  matchTarget: InterceptTarget
  matchType: InterceptMatchType
  pattern: string
  action: InterceptAction
  message: string
  createdAt: string
  updatedAt: string
}

interface RuleDraft {
  id: string
  name: string
  enabled: boolean
  priority: number
  matchTarget: InterceptTarget
  matchType: InterceptMatchType
  pattern: string
  action: InterceptAction
  message: string
}

const rules = ref<InterceptRule[]>([])
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const notice = ref('')
const showModal = ref(false)
const deleteTarget = ref<InterceptRule | null>(null)
const deleting = ref(false)
const draft = reactive<RuleDraft>(emptyDraft())
const testing = ref(false)
const testToolName = ref('exec')
const testArguments = ref('{"command":"rm -rf /tmp/demo"}')
const testResult = ref<'idle' | 'matched' | 'missed' | 'failed'>('idle')

const isEditing = computed(() => Boolean(draft.id))
const actionOptions: InterceptAction[] = ['allow', 'ask', 'deny']
const targetOptions: InterceptTarget[] = ['tool_input', 'tool_name']
const matchTypeOptions: InterceptMatchType[] = ['regex', 'string']

function emptyDraft(): RuleDraft {
  return {
    id: '',
    name: '',
    enabled: true,
    priority: 50,
    matchTarget: 'tool_input',
    matchType: 'regex',
    pattern: '',
    action: 'ask',
    message: '',
  }
}

function resetDraft() {
  Object.assign(draft, emptyDraft())
  testToolName.value = 'exec'
  testArguments.value = '{"command":"rm -rf /tmp/demo"}'
  testResult.value = 'idle'
}

function openCreate() {
  resetDraft()
  showModal.value = true
}

function openEdit(rule: InterceptRule) {
  Object.assign(draft, {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    priority: rule.priority,
    matchTarget: rule.matchTarget,
    matchType: rule.matchType,
    pattern: rule.pattern,
    action: rule.action,
    message: rule.message,
  })
  testResult.value = 'idle'
  showModal.value = true
}

function closeModal() {
  showModal.value = false
}

function fillExample() {
  Object.assign(draft, {
    name: t('settings.interceptExampleName'),
    enabled: true,
    priority: 100,
    matchTarget: 'tool_input',
    matchType: 'regex',
    pattern: String.raw`(rm\s+-rf\s+/|DROP\s+DATABASE|kubectl\s+delete\s+namespace)`,
    action: 'deny',
    message: t('settings.interceptExampleMessage'),
  })
  testArguments.value = '{"command":"rm -rf /var/lib/data"}'
  testResult.value = 'idle'
}

function validatePattern(): string {
  if (!draft.name.trim()) {
    return t('settings.interceptNameRequired')
  }
  if (!draft.pattern.trim()) {
    return t('settings.interceptPatternRequired')
  }
  if (draft.matchType === 'regex') {
    try {
      new RegExp(draft.pattern)
    } catch (err) {
      return t('settings.interceptRegexInvalid', {
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }
  return ''
}

async function loadRules() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiGet<{ items: InterceptRule[] }>('/intercept/rules')
    rules.value = response.items ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.interceptLoadFailed')
  } finally {
    loading.value = false
  }
}

async function saveRule() {
  error.value = ''
  notice.value = ''
  const validation = validatePattern()
  if (validation) {
    error.value = validation
    return
  }
  saving.value = true
  try {
    const payload = {
      name: draft.name.trim(),
      enabled: draft.enabled,
      priority: Number(draft.priority),
      matchTarget: draft.matchTarget,
      matchType: draft.matchType,
      pattern: draft.pattern.trim(),
      action: draft.action,
      message: draft.message.trim(),
    }
    if (isEditing.value) {
      await apiPut(`/intercept/rules/${encodeURIComponent(draft.id)}`, payload)
    } else {
      await apiPost('/intercept/rules', payload)
    }
    notice.value = isEditing.value ? t('settings.interceptUpdated') : t('settings.interceptCreated')
    closeModal()
    await loadRules()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.interceptSaveFailed')
  } finally {
    saving.value = false
  }
}

async function toggleRule(rule: InterceptRule) {
  if (!props.writable) {
    return
  }
  try {
    await apiPut(`/intercept/rules/${encodeURIComponent(rule.id)}/toggle`, {
      enabled: !rule.enabled,
    })
    rule.enabled = !rule.enabled
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.interceptToggleFailed')
  }
}

function requestRemoveRule(rule: InterceptRule) {
  if (props.writable) {
    deleteTarget.value = rule
  }
}

function closeDeleteDialog() {
  if (!deleting.value) {
    deleteTarget.value = null
  }
}

async function confirmRemoveRule() {
  const rule = deleteTarget.value
  if (!props.writable || !rule || deleting.value) {
    return
  }
  deleting.value = true
  try {
    await apiDelete(`/intercept/rules/${encodeURIComponent(rule.id)}`)
    notice.value = t('settings.interceptDeleted')
    deleteTarget.value = null
    await loadRules()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.interceptDeleteFailed')
    deleteTarget.value = null
  } finally {
    deleting.value = false
  }
}

async function testRule() {
  error.value = ''
  testResult.value = 'idle'
  let parsedArguments: Record<string, unknown>
  try {
    parsedArguments = JSON.parse(testArguments.value || '{}') as Record<string, unknown>
  } catch {
    error.value = t('settings.interceptTestJsonInvalid')
    testResult.value = 'failed'
    return
  }
  testing.value = true
  try {
    const response = await apiPost<{ matched: boolean }>('/intercept/rules/test', {
      rule: {
        name: draft.name || 'draft',
        enabled: true,
        priority: Number(draft.priority) || 0,
        matchTarget: draft.matchTarget,
        matchType: draft.matchType,
        pattern: draft.pattern,
        action: draft.action,
        message: draft.message,
      },
      toolName: testToolName.value,
      arguments: parsedArguments,
    })
    testResult.value = response.matched ? 'matched' : 'missed'
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('settings.interceptTestFailed')
    testResult.value = 'failed'
  } finally {
    testing.value = false
  }
}

function actionLabel(action: InterceptAction) {
  return t(`settings.interceptAction.${action}`)
}

function targetLabel(target: InterceptTarget) {
  return t(`settings.interceptTarget.${target}`)
}

onMounted(loadRules)
</script>

<template>
  <section class="intercept-panel">
    <article class="business-card intercept-card">
      <header class="intercept-header">
        <div>
          <h2>{{ t('settings.interceptSection') }}</h2>
          <p class="field-hint">{{ t('settings.interceptIntro') }}</p>
        </div>
        <button class="button compact" type="button" :disabled="!writable" @click="openCreate">
          {{ t('settings.interceptCreate') }}
        </button>
      </header>

      <div v-if="error" class="alert error">{{ error }}</div>
      <div v-if="notice" class="alert ok">{{ notice }}</div>

      <p v-if="loading" class="intercept-empty">{{ t('common.loading') }}</p>
      <p v-else-if="!rules.length" class="intercept-empty">{{ t('settings.interceptEmpty') }}</p>
      <div v-else class="intercept-table-wrap">
        <table class="intercept-table">
          <thead>
            <tr>
              <th>{{ t('settings.interceptEnabled') }}</th>
              <th>{{ t('settings.interceptName') }}</th>
              <th>{{ t('settings.interceptTargetLabel') }}</th>
              <th>{{ t('settings.interceptType') }}</th>
              <th>{{ t('settings.interceptPattern') }}</th>
              <th>{{ t('settings.interceptActionLabel') }}</th>
              <th>{{ t('settings.interceptPriority') }}</th>
              <th>{{ t('settings.interceptOperations') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="rule in rules" :key="rule.id">
              <td>
                <input
                  type="checkbox"
                  :aria-label="rule.name + ' ' + t('settings.interceptEnabled')"
                  :checked="rule.enabled"
                  :disabled="!writable"
                  @change="toggleRule(rule)"
                />
              </td>
              <td class="intercept-name">{{ rule.name }}</td>
              <td>{{ targetLabel(rule.matchTarget) }}</td>
              <td>{{ rule.matchType }}</td>
              <td><code class="intercept-pattern">{{ rule.pattern }}</code></td>
              <td><span class="intercept-action" :class="`action-${rule.action}`">{{ actionLabel(rule.action) }}</span></td>
              <td>{{ rule.priority }}</td>
              <td class="intercept-row-actions">
                <button class="text-button" type="button" :disabled="!writable" @click="openEdit(rule)">
                  {{ t('common.edit') }}
                </button>
                <button class="text-button danger" type="button" :disabled="!writable" @click="requestRemoveRule(rule)">
                  {{ t('common.delete') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>

    <div v-if="showModal" class="intercept-modal-backdrop" @click.self="closeModal">
      <article class="intercept-modal">
        <header class="intercept-modal-head">
          <div>
            <h3>{{ isEditing ? t('settings.interceptEditTitle') : t('settings.interceptCreateTitle') }}</h3>
            <p class="intercept-modal-subtitle">
              {{ isEditing ? t('settings.interceptEditSubtitle') : t('settings.interceptCreateSubtitle') }}
            </p>
          </div>
          <button class="icon-button" type="button" :aria-label="t('common.cancel')" @click="closeModal">×</button>
        </header>

        <div class="intercept-modal-body">
          <div class="intercept-form">
          <section class="form-section">
            <div class="form-section-head">
              <h4>{{ t('settings.interceptBasics') }}</h4>
              <label class="checkbox-line">
                <input v-model="draft.enabled" type="checkbox" />
                <span>{{ t('settings.interceptEnabled') }}</span>
              </label>
            </div>
            <div class="form-grid">
              <label class="field">
                <span>{{ t('settings.interceptName') }}</span>
                <input v-model="draft.name" maxlength="120" />
              </label>
              <label class="field">
                <span>{{ t('settings.interceptPriority') }}</span>
                <input v-model.number="draft.priority" type="number" min="0" max="10000" />
              </label>
              <label class="field">
                <span>{{ t('settings.interceptActionLabel') }}</span>
                <select v-model="draft.action">
                  <option v-for="action in actionOptions" :key="action" :value="action">
                    {{ actionLabel(action) }}
                  </option>
                </select>
                <small class="action-hint" :class="`action-hint-${draft.action}`">
                  {{ t(`settings.interceptActionHint.${draft.action}`) }}
                </small>
              </label>
            </div>
          </section>

          <section class="form-section">
            <div class="form-section-head">
              <h4>{{ t('settings.interceptMatch') }}</h4>
            </div>
            <div class="form-grid">
              <label class="field">
                <span>{{ t('settings.interceptTargetLabel') }}</span>
                <select v-model="draft.matchTarget">
                  <option v-for="target in targetOptions" :key="target" :value="target">
                    {{ targetLabel(target) }}
                  </option>
                </select>
              </label>
              <label class="field">
                <span>{{ t('settings.interceptType') }}</span>
                <select v-model="draft.matchType">
                  <option v-for="matchType in matchTypeOptions" :key="matchType" :value="matchType">
                    {{ matchType }}
                  </option>
                </select>
              </label>
              <label class="field field-wide">
                <span>{{ t('settings.interceptPattern') }}</span>
                <textarea
                  v-model="draft.pattern"
                  class="pattern-input"
                  rows="4"
                  maxlength="4000"
                  :placeholder="t('settings.interceptPatternPlaceholder')"
                ></textarea>
                <small class="field-hint">{{ t('settings.interceptPatternHint') }}</small>
              </label>
              <label class="field field-wide">
                <span>{{ t('settings.interceptMessage') }}</span>
                <input v-model="draft.message" maxlength="2000" :placeholder="t('settings.interceptMessagePlaceholder')" />
              </label>
            </div>
          </section>
          </div>

          <section class="intercept-test">
          <div class="intercept-test-head">
            <strong>{{ t('settings.interceptTestTitle') }}</strong>
            <button class="text-button" type="button" @click="fillExample">{{ t('settings.interceptFillExample') }}</button>
          </div>
          <div class="intercept-test-grid">
            <label class="field">
              <span>{{ t('settings.interceptTestTool') }}</span>
              <input v-model="testToolName" />
            </label>
            <label class="field">
              <span>{{ t('settings.interceptTestArguments') }}</span>
              <textarea v-model="testArguments" rows="3"></textarea>
            </label>
          </div>
          <div class="intercept-test-actions">
            <button class="button compact" type="button" :disabled="testing" @click="testRule">
              {{ testing ? t('common.loading') : t('settings.interceptTest') }}
            </button>
            <span v-if="testResult === 'matched'" class="test-result matched">{{ t('settings.interceptTestMatched') }}</span>
            <span v-else-if="testResult === 'missed'" class="test-result">{{ t('settings.interceptTestMissed') }}</span>
            <span v-else-if="testResult === 'failed'" class="test-result failed">{{ t('settings.interceptTestFailed') }}</span>
          </div>
          </section>
        </div>

        <footer class="intercept-modal-actions">
          <button class="button compact" type="button" @click="closeModal">{{ t('common.cancel') }}</button>
          <button class="button" type="button" :disabled="saving || !writable" @click="saveRule">
            {{ saving ? t('common.saving') : t('common.save') }}
          </button>
        </footer>
      </article>
    </div>

    <Teleport to="body">
      <div v-if="deleteTarget" class="intercept-delete-layer" @click.self="closeDeleteDialog">
        <aside class="intercept-delete-dialog" role="dialog" aria-modal="true">
          <header>
            <span aria-hidden="true">!</span>
            <div>
              <small>RULE REMOVAL</small>
              <h3>{{ t('common.delete') }}</h3>
            </div>
          </header>
          <p>{{ t('settings.interceptDeleteConfirm', { name: deleteTarget.name }) }}</p>
          <footer>
            <button class="button compact" type="button" :disabled="deleting" @click="closeDeleteDialog">{{ t('common.cancel') }}</button>
            <button class="button compact danger" type="button" :disabled="deleting" @click="confirmRemoveRule">
              {{ deleting ? t('common.loading') : t('common.delete') }}
            </button>
          </footer>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.intercept-panel {
  min-width: 0;
}

.intercept-card {
  display: grid;
  gap: 14px;
}

.intercept-header {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
}

.intercept-header h2 {
  margin: 0 0 6px;
}

.intercept-header .field-hint {
  margin: 0;
}

.intercept-empty {
  margin: 0;
  padding: 26px 12px;
  color: var(--text-muted);
  font-size: 12px;
  text-align: center;
}

.intercept-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.intercept-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.intercept-table th,
.intercept-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}

.intercept-table th {
  color: var(--text-muted);
  background: var(--surface-soft);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  white-space: nowrap;
}

.intercept-table tr:last-child td {
  border-bottom: 0;
}

.intercept-name {
  color: var(--text-primary);
  font-weight: 600;
}

.intercept-pattern {
  display: block;
  max-width: 280px;
  padding: 2px 5px;
  overflow: hidden;
  color: var(--ice-blue);
  background: var(--field-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-family: var(--mono);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.intercept-action {
  padding: 2px 6px;
  border: 1px solid currentColor;
  border-radius: var(--radius);
  font-family: var(--mono);
  font-size: 10px;
  white-space: nowrap;
}

.action-allow {
  color: var(--success);
}

.action-ask {
  color: var(--warning);
}

.action-deny {
  color: var(--danger);
}

.intercept-row-actions {
  display: flex;
  gap: 8px;
  white-space: nowrap;
}

.text-button {
  padding: 0;
  border: 0;
  background: none;
  color: var(--accent);
  font: inherit;
  cursor: pointer;
}

.text-button:hover {
  text-decoration: underline;
}

.text-button.danger {
  color: var(--danger);
}

.text-button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.intercept-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 6, 16, 0.72);
  backdrop-filter: blur(8px);
}

.intercept-modal {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  gap: 16px;
  width: min(900px, 100%);
  max-height: min(90dvh, 940px);
  padding: 22px;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.intercept-modal-body {
  display: grid;
  gap: 16px;
  min-height: 0;
  padding-right: 4px;
  overflow-y: auto;
}

.intercept-modal-head {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  justify-content: space-between;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--line);
}

.intercept-modal-head h3 {
  margin: 0;
}

.intercept-modal-subtitle {
  margin: 5px 0 0;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 400;
  line-height: 1.5;
}

.intercept-form {
  display: grid;
  gap: 18px;
}

.form-section {
  display: grid;
  gap: 12px;
}

.form-section + .form-section {
  padding-top: 16px;
  border-top: 1px solid var(--border);
}

.form-section-head {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.form-section-head h4 {
  margin: 0;
  color: var(--text-primary);
  font-size: 13px;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.field-wide {
  grid-column: 1 / -1;
}

.field {
  display: grid;
  gap: 6px;
  min-width: 0;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}

.field input,
.field select,
.field textarea {
  box-sizing: border-box;
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
  color: var(--text-primary);
  font: inherit;
  font-weight: 400;
}

.field input:focus,
.field select:focus,
.field textarea:focus {
  border-color: var(--accent);
  outline: none;
  box-shadow: none;
}

.field textarea {
  min-height: 90px;
  resize: vertical;
  line-height: 1.55;
}

.intercept-form .pattern-input {
  min-height: 118px;
  color: var(--ice-blue);
  font-family: var(--mono);
  font-size: 12px;
}

.field-hint {
  margin: 0;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 400;
  line-height: 1.5;
}

.checkbox-line {
  display: flex;
  gap: 8px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
}

.checkbox-line input {
  width: auto;
}

.action-hint {
  font-size: 10px;
  font-weight: 400;
}

.action-hint-allow {
  color: var(--success);
}

.action-hint-ask {
  color: var(--warning);
}

.action-hint-deny {
  color: var(--danger);
}

.intercept-test textarea {
  min-height: 74px;
}

.intercept-test {
  display: grid;
  gap: 10px;
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--field-bg);
  box-shadow: none;
}

.intercept-test-head,
.intercept-test-actions {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
}

.intercept-test-head strong {
  color: var(--text-primary);
  font-size: 12px;
}

.intercept-test-grid {
  display: grid;
  grid-template-columns: minmax(160px, 0.55fr) minmax(0, 1.45fr);
  gap: 12px;
}

.test-result {
  color: var(--text-secondary);
  font-size: 12px;
}

.test-result.matched {
  color: var(--warning);
}

.test-result.failed {
  color: var(--danger);
}

.intercept-modal-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  padding: 14px 0 2px;
  border-top: 1px solid var(--border);
}

@media (max-width: 720px) {
  .intercept-header,
  .intercept-test-head,
  .form-section-head {
    align-items: stretch;
    flex-direction: column;
  }

  .form-grid,
  .intercept-test-grid {
    grid-template-columns: 1fr;
  }

  .field-wide {
    grid-column: 1;
  }
}
</style>

<style scoped>
/* Intercept gate rules */
.intercept-panel {
  --gate-accent: #9d8cff;
  --gate-mint: #34d399;
  --gate-amber: #f0a43a;
  --gate-coral: #fb7185;
}

.intercept-card {
  position: relative;
  display: grid;
  gap: 10px;
  padding: 14px !important;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--gate-accent) 20%, var(--border)) !important;
  border-radius: 5px !important;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--gate-accent) 4%, transparent), transparent 120px),
    var(--surface) !important;
}

.intercept-card::before {
  position: absolute;
  top: 0;
  left: 0;
  width: 42px;
  height: 2px;
  content: '';
  background: var(--gate-accent);
}

.intercept-header {
  padding-bottom: 9px;
  border-bottom: 1px solid var(--border);
}

.intercept-header h2 {
  color: var(--text-primary);
  font-size: 13px;
}

.intercept-header .field-hint {
  max-width: 760px;
  font-size: 8px;
}

.intercept-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 3px;
}

.intercept-table {
  min-width: 920px;
}

.intercept-table th {
  padding: 7px 8px;
  background: color-mix(in srgb, var(--field-bg) 78%, var(--gate-accent));
  font-size: 8px;
}

.intercept-table td {
  padding: 7px 8px;
  font-size: 9px;
}

.intercept-table tbody tr:hover {
  background: color-mix(in srgb, var(--gate-accent) 4%, transparent);
}

.intercept-name {
  color: var(--text-primary);
  font-size: 10px;
}

.intercept-pattern {
  max-width: 250px;
  border-radius: 2px;
  font-size: 8px;
}

.intercept-action {
  min-width: 42px;
  padding: 2px 6px;
  border-radius: 2px;
  text-align: center;
}

.action-allow {
  color: var(--gate-mint);
  background: color-mix(in srgb, var(--gate-mint) 7%, transparent);
}

.action-ask {
  color: var(--gate-amber);
  background: color-mix(in srgb, var(--gate-amber) 7%, transparent);
}

.action-deny {
  color: var(--gate-coral);
  background: color-mix(in srgb, var(--gate-coral) 7%, transparent);
}

.intercept-modal-backdrop {
  z-index: 92;
  background: rgba(6, 5, 12, 0.7);
}

.intercept-modal {
  width: min(780px, 100%);
  padding: 16px;
  border-color: color-mix(in srgb, var(--gate-accent) 28%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--gate-accent) 4%, transparent), transparent 130px),
    var(--surface);
}

.intercept-modal-head {
  padding-bottom: 10px;
}

.intercept-modal-head h3 {
  color: var(--text-primary);
  font-size: 16px;
}

.intercept-modal-subtitle {
  font-size: 9px;
}

.intercept-form {
  gap: 10px;
}

.form-section {
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.form-section + .form-section {
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.form-section-head h4 {
  font-size: 10px;
}

.form-grid {
  gap: 9px;
}

.field {
  gap: 4px;
  font-size: 9px;
}

.field > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.field input,
.field select,
.field textarea {
  padding: 7px 8px;
  border-radius: 3px;
}

.intercept-test {
  padding: 10px;
  border-color: color-mix(in srgb, var(--gate-accent) 18%, var(--border));
}

.test-result.matched {
  color: var(--gate-amber);
}

.test-result.failed {
  color: var(--gate-coral);
}

.intercept-delete-layer {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: grid;
  padding: 20px;
  background: rgba(6, 5, 12, 0.68);
  backdrop-filter: blur(4px);
  place-items: center;
}

.intercept-delete-dialog {
  width: min(390px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--gate-coral) 42%, var(--border));
  border-radius: 5px;
  background: var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.44);
}

.intercept-delete-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
}

.intercept-delete-dialog header > span {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--gate-coral);
  border-radius: 50%;
  color: var(--gate-coral);
  font-family: var(--mono);
  font-size: 16px;
  place-items: center;
}

.intercept-delete-dialog small {
  color: var(--gate-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.intercept-delete-dialog h3 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 15px;
}

.intercept-delete-dialog p {
  margin: 12px 0;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.5;
}

.intercept-delete-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
}

@media (max-width: 760px) {
  .intercept-header {
    align-items: stretch;
  }

  .intercept-modal {
    width: 100%;
    padding: 12px;
  }

  .form-grid,
  .intercept-test-grid {
    grid-template-columns: 1fr;
  }
}
</style>
