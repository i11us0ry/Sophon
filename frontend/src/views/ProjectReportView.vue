<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { apiDownload, apiGet } from '../api/client'
import MarkdownContent from '../components/MarkdownContent.vue'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'

interface ReportPreview {
  projectName: string
  markdown: string
  markdownName: string
  assetsCsvName: string
}

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const projectId = String(route.params.id ?? '')
const report = ref<ReportPreview | null>(null)
const markdown = ref('')
const loading = ref(false)
const exporting = ref(false)
const error = ref('')
const notice = ref('')
const lineCount = computed(() => markdown.value.split(/\r?\n/).length)
const characterCount = computed(() => Array.from(markdown.value).length)

async function loadReport() {
  loading.value = true
  error.value = ''
  try {
    report.value = await apiGet<ReportPreview>(`/projects/${projectId}/report`)
    markdown.value = report.value.markdown
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('report.loadFailed')
  } finally {
    loading.value = false
  }
}

async function download(format: 'md' | 'csv' | 'vulnerabilities' | 'pdf' | 'package') {
  exporting.value = true
  error.value = ''
  notice.value = ''
  try {
    const result = await apiDownload(`/projects/${projectId}/report/export`, {
      method: 'POST',
      body: {
        format,
        markdown: markdown.value,
      },
    })
    const href = URL.createObjectURL(result.blob)
    const link = document.createElement('a')
    link.href = href
    link.download = result.filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(href)
    notice.value = t('report.exported')
  } catch (err) {
    error.value = err instanceof Error ? err.message : t('report.exportFailed')
  } finally {
    exporting.value = false
  }
}

onMounted(loadReport)
</script>

<template>
  <section class="page factory-page report-workbench-page">
    <header class="page-header report-header">
      <div class="page-heading-with-robot">
        <PageTitleRobot tone="orange" />
        <div>
          <p class="eyebrow">PROJECT REPORT // REVIEW & EXPORT</p>
          <h1>{{ report?.projectName || t('report.title') }}</h1>
          <p class="report-subtitle">{{ t('report.subtitle') }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="button compact" type="button" @click="router.push({ name: 'projects' })">
          {{ t('report.back') }}
        </button>
        <button
          class="button compact"
          type="button"
          :disabled="loading || exporting"
          @click="loadReport"
        >
          {{ loading ? t('report.loading') : t('common.refresh') }}
        </button>
      </div>
    </header>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="notice" class="alert ok">{{ notice }}</div>

    <section class="report-export-bar">
      <div>
        <strong>{{ t('report.ready') }}</strong>
        <span>{{ t('report.stats', { lines: lineCount, chars: characterCount }) }}</span>
      </div>
      <div class="report-export-actions">
        <button class="button compact" type="button" :disabled="exporting" @click="download('md')">
          MD
          {{ t('report.downloadMarkdown') }}
        </button>
        <button class="button compact" type="button" :disabled="exporting" @click="download('csv')">
          CSV
          {{ t('report.downloadAssets') }}
        </button>
        <button
          class="button compact"
          type="button"
          :disabled="exporting"
          @click="download('vulnerabilities')"
        >
          CSV
          {{ t('report.downloadVulnerabilities') }}
        </button>
        <button class="button compact" type="button" :disabled="exporting" @click="download('pdf')">
          PDF
          {{ t('report.exportPdf') }}
        </button>
        <button class="button compact primary" type="button" :disabled="exporting" @click="download('package')">
          ZIP
          {{ exporting ? t('report.exporting') : t('report.downloadPackage') }}
        </button>
      </div>
    </section>

    <section class="report-workbench" :class="{ loading }">
      <article class="report-editor-pane">
        <header>
          <strong>{{ t('report.editor') }}</strong>
          <span>Markdown</span>
        </header>
        <textarea
          v-model="markdown"
          spellcheck="false"
          :aria-label="t('report.editor')"
        ></textarea>
      </article>
      <article class="report-preview-pane">
        <header>
          <strong>{{ t('report.preview') }}</strong>
          <span>{{ report?.markdownName || 'report.md' }}</span>
        </header>
        <div class="report-preview-scroll">
          <MarkdownContent v-if="markdown" :content="markdown" image-policy="reproduction" />
          <p v-else class="empty-cell">{{ t('report.empty') }}</p>
        </div>
      </article>
    </section>
  </section>
</template>

<style scoped>
.report-header {
  align-items: center;
}

.report-subtitle {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 12px;
}

.report-export-bar {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  margin-bottom: 12px;
  padding: 12px 14px;
  border: 1px solid var(--border);
  background: var(--surface);
}

.report-export-bar strong,
.report-export-bar span {
  display: block;
}

.report-export-bar span {
  margin-top: 2px;
  color: var(--text-muted);
  font-size: 11px;
}

.report-export-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.report-workbench {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  min-height: calc(100vh - 250px);
  border: 1px solid var(--border);
  background: var(--surface);
}

.report-workbench.loading {
  opacity: 0.55;
  pointer-events: none;
}

.report-editor-pane,
.report-preview-pane {
  display: grid;
  min-width: 0;
  grid-template-rows: auto minmax(0, 1fr);
}

.report-editor-pane {
  border-right: 1px solid var(--border);
}

.report-editor-pane header,
.report-preview-pane header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 11px;
}

.report-editor-pane header strong,
.report-preview-pane header strong {
  color: var(--text-primary);
}

.report-editor-pane textarea {
  width: 100%;
  min-height: 620px;
  padding: 14px;
  resize: none;
  border: 0;
  color: var(--text-primary);
  background: var(--field-bg);
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.6;
  outline: none;
  tab-size: 2;
}

.report-preview-scroll {
  min-height: 0;
  padding: 18px 20px;
  overflow: auto;
}

.alert {
  margin-bottom: 10px;
}

@media (max-width: 980px) {
  .report-export-bar {
    align-items: stretch;
    flex-direction: column;
  }

  .report-export-actions {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .report-workbench {
    grid-template-columns: 1fr;
  }

  .report-editor-pane {
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }

  .report-editor-pane textarea {
    min-height: 420px;
  }
}
</style>
