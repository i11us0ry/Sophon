<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'

import { apiDelete, apiGet, apiPost, apiPut } from '../api/client'
import { useI18n } from '../i18n'

const { t } = useI18n()

interface Item {
  id: string
  projectId?: string
  assetId?: string
  name?: string
  title?: string
  value?: string
  kind?: string
  description?: string
  evidence?: string
  category?: string
  content?: string
  severity?: string
  status?: string
}

const projects = ref<Item[]>([])
const assets = ref<Item[]>([])
const vulnerabilities = ref<Item[]>([])
const knowledge = ref<Item[]>([])
const skills = ref<Record<string, string>[]>([])
const webshells = ref<Item[]>([])
const error = ref('')

const projectForm = reactive({ name: '', description: '' })
const assetForm = reactive({ projectId: '', name: '', kind: 'domain', value: '', criticality: 'medium' })
const assetKinds = ['domain', 'ip', 'url', 'port', 'host']
const vulnerabilityTypes = [
  '跨站脚本（XSS）',
  'SQL 注入',
  '跨站请求伪造（CSRF）',
  '未授权访问',
  '越界读取',
  '命令注入',
  'UAF',
  '路径遍历',
  '文件上传',
  '缓冲区溢出',
  '空指针解引用',
  '文件下载',
  '信息泄露',
  '硬编码凭据',
  '竞态条件',
  '越界写入',
  '点击劫持',
  '文件包含',
  '服务端请求伪造（SSRF）',
]
const vulnerabilityForm = reactive({
  projectId: '',
  assetId: '',
  title: '',
  severity: 'medium',
  vulnerabilityType: '',
  target: '',
  preconditions: '',
  reproductionSteps: '1. 发送验证请求\n\n利用脚本（优先 Python）：\n```python\nimport requests\nprint(requests.get("https://target.example", timeout=10).status_code)\n```',
  description: '',
  evidence: '',
  impact: '',
  recommendation: '',
  retestNotes: '无',
})
const knowledgeForm = reactive({ category: 'general', title: '', content: '' })
const webshellForm = reactive({ projectId: '', name: '', url: '', method: 'POST', password: '', encoding: 'utf-8' })

async function load() {
  error.value = ''
  try {
    const [p, a, v, k, s, w] = await Promise.all([
      apiGet<{ items: Item[] }>('/projects'),
      apiGet<{ items: Item[] }>('/assets'),
      apiGet<{ items: Item[] }>('/vulnerabilities'),
      apiGet<{ items: Item[] }>('/knowledge/items'),
      apiGet<{ items: Record<string, string>[] }>('/skills'),
      apiGet<{ items: Item[] }>('/webshell/connections'),
    ])
    projects.value = p.items
    assets.value = a.items
    vulnerabilities.value = v.items
    knowledge.value = k.items
    skills.value = s.items
    webshells.value = w.items
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.readBusinessFailed')
  }
}

async function createProject() {
  await apiPost('/projects', projectForm)
  projectForm.name = ''
  projectForm.description = ''
  await load()
}

async function createAsset() {
  await apiPost('/assets', assetForm)
  assetForm.name = ''
  assetForm.value = ''
  await load()
}

async function createVulnerability() {
  await apiPost('/vulnerabilities', vulnerabilityForm)
  vulnerabilityForm.title = ''
  vulnerabilityForm.vulnerabilityType = ''
  vulnerabilityForm.target = ''
  vulnerabilityForm.preconditions = ''
  vulnerabilityForm.description = ''
  vulnerabilityForm.evidence = ''
  vulnerabilityForm.impact = ''
  vulnerabilityForm.recommendation = ''
  vulnerabilityForm.retestNotes = '无'
  await load()
}

async function createKnowledge() {
  await apiPost('/knowledge/items', knowledgeForm)
  knowledgeForm.title = ''
  knowledgeForm.content = ''
  await load()
}

async function createWebShell() {
  await apiPost('/webshell/connections', webshellForm)
  webshellForm.name = ''
  webshellForm.url = ''
  webshellForm.password = ''
  await load()
}

async function withReload(action: () => Promise<unknown>) {
  error.value = ''
  try {
    await action()
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('message.operationFailed')
  }
}

function removeItem(label: string, path: string) {
  if (!window.confirm(t('message.confirmDeleteItem', { name: label }))) {
    return
  }
  void withReload(() => apiDelete(path))
}

function updateVulnerabilityStatus(item: Item, status: string) {
  void withReload(() =>
    apiPut(`/vulnerabilities/${item.id}`, {
      projectId: item.projectId ?? '',
      assetId: item.assetId ?? '',
      title: item.title ?? '',
      severity: item.severity ?? 'medium',
      status,
      description: item.description ?? '',
      evidence: item.evidence ?? '',
    }),
  )
}

onMounted(load)
</script>

<template>
  <section class="page factory-page page-business">
    <header class="page-header">
      <div>
        <p class="eyebrow">SECURITY OPERATIONS</p>
        <h1>{{ t('business.opsTitle') }}</h1>
      </div>
      <button class="button" type="button" @click="load">{{ t('common.refresh') }}</button>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>

    <section class="business-grid">
      <article class="business-card">
        <h2>{{ t('vulnerability.project') }}</h2>
        <input
          v-model="projectForm.name"
          :aria-label="t('project.namePlaceholder')"
          :placeholder="t('project.namePlaceholder')"
        />
        <textarea
          v-model="projectForm.description"
          rows="2"
          :aria-label="t('business.projectDescriptionPlaceholder')"
          :placeholder="t('business.projectDescriptionPlaceholder')"
        ></textarea>
        <button class="button" type="button" @click="createProject">{{ t('business.createProject') }}</button>
        <ul class="item-list">
          <li v-for="item in projects" :key="item.id">
            <span>{{ item.name }}</span>
            <button
              class="button compact danger"
              type="button"
              @click="removeItem(t('business.itemProject', { name: item.name }), '/projects/' + item.id)"
            >
              {{ t('common.delete') }}
            </button>
          </li>
        </ul>
      </article>

      <article class="business-card">
        <h2>{{ t('project.assets') }}</h2>
        <input
          v-model="assetForm.projectId"
          :aria-label="t('business.projectIdOptional')"
          :placeholder="t('business.projectIdOptional')"
        />
        <input
          v-model="assetForm.name"
          :aria-label="t('business.assetNamePlaceholder')"
          :placeholder="t('business.assetNamePlaceholder')"
        />
        <select
          v-model="assetForm.kind"
          :aria-label="t('asset.kindPlaceholder')"
        >
          <option v-for="kind in assetKinds" :key="kind" :value="kind">{{ kind }}</option>
        </select>
        <input
          v-model="assetForm.value"
          :aria-label="t('business.assetValuePlaceholder')"
          :placeholder="t('business.assetValuePlaceholder')"
        />
        <button class="button" type="button" @click="createAsset">{{ t('business.createAsset') }}</button>
        <ul class="item-list">
          <li v-for="item in assets" :key="item.id">
            <span>{{ item.name }} · {{ item.value }}</span>
            <button
              class="button compact danger"
              type="button"
              @click="removeItem(t('business.itemAsset', { name: item.name }), '/assets/' + item.id)"
            >
              {{ t('common.delete') }}
            </button>
          </li>
        </ul>
      </article>

      <article class="business-card">
        <h2>{{ t('project.vulnerabilities') }}</h2>
        <input
          v-model="vulnerabilityForm.projectId"
          :aria-label="t('business.projectIdOptional')"
          :placeholder="t('business.projectIdOptional')"
        />
        <input
          v-model="vulnerabilityForm.assetId"
          :aria-label="t('business.assetIdOptional')"
          :placeholder="t('business.assetIdOptional')"
        />
        <input
          v-model="vulnerabilityForm.title"
          :aria-label="t('business.vulnerabilityTitlePlaceholder')"
          :placeholder="t('business.vulnerabilityTitlePlaceholder')"
        />
        <select v-model="vulnerabilityForm.severity" :aria-label="t('vulnerability.severity')">
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
        <select v-model="vulnerabilityForm.vulnerabilityType" :aria-label="t('vulnerability.type')">
          <option value="" disabled>{{ t('vulnerability.typePlaceholder') }}</option>
          <option v-for="type in vulnerabilityTypes" :key="type" :value="type">{{ type }}</option>
        </select>
        <input
          v-model="vulnerabilityForm.target"
          :aria-label="t('vulnerability.target')"
          :placeholder="t('vulnerability.targetPlaceholder')"
        />
        <textarea
          v-model="vulnerabilityForm.preconditions"
          rows="2"
          :aria-label="t('vulnerability.preconditions')"
          :placeholder="t('vulnerability.preconditionsPlaceholder')"
        ></textarea>
        <textarea
          v-model="vulnerabilityForm.description"
          rows="2"
          :aria-label="t('vulnerability.description')"
          :placeholder="t('vulnerability.description')"
        ></textarea>
        <textarea
          v-model="vulnerabilityForm.reproductionSteps"
          rows="6"
          :aria-label="t('vulnerability.reproduction')"
          :placeholder="t('vulnerability.reproductionPlaceholder')"
        ></textarea>
        <textarea
          v-model="vulnerabilityForm.evidence"
          rows="3"
          :aria-label="t('vulnerability.evidence')"
          :placeholder="t('vulnerability.evidencePlaceholder')"
        ></textarea>
        <textarea
          v-model="vulnerabilityForm.impact"
          rows="2"
          :aria-label="t('vulnerability.impact')"
          :placeholder="t('vulnerability.impactPlaceholder')"
        ></textarea>
        <textarea
          v-model="vulnerabilityForm.recommendation"
          rows="2"
          :aria-label="t('vulnerability.recommendation')"
          :placeholder="t('vulnerability.recommendation')"
        ></textarea>
        <input
          v-model="vulnerabilityForm.retestNotes"
          :aria-label="t('vulnerability.retest')"
          :placeholder="t('vulnerability.retestPlaceholder')"
        />
        <button class="button" type="button" @click="createVulnerability">{{ t('business.createVulnerability') }}</button>
        <ul class="item-list">
          <li v-for="item in vulnerabilities" :key="item.id">
            <span>[{{ item.severity }}] {{ item.title }}</span>
            <span class="item-actions">
              <select
                :value="item.status"
                :aria-label="item.title + ' ' + t('common.status')"
                @change="updateVulnerabilityStatus(item, ($event.target as HTMLSelectElement).value)"
              >
                <option value="open">{{ t('vulnStatus.open') }}</option>
                <option value="confirmed">{{ t('vulnStatus.confirmed') }}</option>
                <option value="fixed">{{ t('vulnStatus.fixed') }}</option>
                <option value="ignored">{{ t('vulnStatus.ignored') }}</option>
                <option value="false_positive">{{ t('vulnStatus.false_positive') }}</option>
              </select>
              <button
                class="button compact danger"
                type="button"
                @click="removeItem(t('business.itemVulnerability', { name: item.title }), '/vulnerabilities/' + item.id)"
              >
                {{ t('common.delete') }}
              </button>
            </span>
          </li>
        </ul>
      </article>

      <article class="business-card">
        <h2>{{ t('business.knowledge') }}</h2>
        <input
          v-model="knowledgeForm.category"
          :aria-label="t('business.knowledgeCategoryPlaceholder')"
          :placeholder="t('business.knowledgeCategoryPlaceholder')"
        />
        <input
          v-model="knowledgeForm.title"
          :aria-label="t('vulnerability.name')"
          :placeholder="t('vulnerability.name')"
        />
        <textarea
          v-model="knowledgeForm.content"
          rows="3"
          :aria-label="t('project.factValue')"
          :placeholder="t('project.factValuePlaceholder')"
        ></textarea>
        <button class="button" type="button" @click="createKnowledge">{{ t('business.createKnowledge') }}</button>
        <ul class="item-list">
          <li v-for="item in knowledge" :key="item.id">
            <span>{{ item.title }}</span>
            <button
              class="button compact danger"
              type="button"
              @click="removeItem(t('business.itemKnowledge', { name: item.title }), '/knowledge/items/' + item.id)"
            >
              {{ t('common.delete') }}
            </button>
          </li>
        </ul>
      </article>

      <article class="business-card">
        <h2>{{ t('business.skills') }}</h2>
        <ul>
          <li v-for="skill in skills" :key="skill.name">{{ skill.name }}</li>
        </ul>
      </article>

      <article class="business-card">
        <h2>{{ t('business.webshell') }}</h2>
        <input
          v-model="webshellForm.projectId"
          :aria-label="t('business.projectIdOptional')"
          :placeholder="t('business.projectIdOptional')"
        />
        <input
          v-model="webshellForm.name"
          :aria-label="t('business.connectionNamePlaceholder')"
          :placeholder="t('business.connectionNamePlaceholder')"
        />
        <input
          v-model="webshellForm.url"
          :aria-label="t('business.connectionUrlPlaceholder')"
          :placeholder="t('business.connectionUrlPlaceholder')"
        />
        <input
          v-model="webshellForm.method"
          :aria-label="t('vulnerability.httpMethod')"
          placeholder="HTTP 方法"
        />
        <input
          v-model="webshellForm.password"
          :aria-label="t('business.connectionPasswordPlaceholder')"
          :placeholder="t('business.connectionPasswordPlaceholder')"
        />
        <button class="button" type="button" @click="createWebShell">{{ t('business.saveConnection') }}</button>
        <ul class="item-list">
          <li v-for="item in webshells" :key="item.id">
            <span>{{ item.name }} · {{ item.status }}</span>
            <button
              class="button compact danger"
              type="button"
              @click="removeItem(t('business.itemWebshell', { name: item.name }), '/webshell/connections/' + item.id)"
            >
              {{ t('common.delete') }}
            </button>
          </li>
        </ul>
      </article>
    </section>
  </section>
</template>

<style scoped>
.item-list {
  padding-left: 0;
  list-style: none;
}

.business-grid,
.business-card,
.item-list li > span:first-child {
  min-width: 0;
}

.item-list li > span:first-child {
  overflow-wrap: anywhere;
}

.item-list li {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
}

.item-list li:last-child {
  border-bottom: 0;
}

.item-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 6px;
  align-items: center;
}

.item-actions select {
  width: auto;
  padding: 6px 8px;
  border-radius: var(--radius);
}
</style>
