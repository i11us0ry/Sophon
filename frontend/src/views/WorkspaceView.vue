<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'

import { ApiError, apiDelete, apiGet, apiPost, apiTextPut, apiUrl } from '../api/client'
import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useI18n } from '../i18n'
import { useAuthStore } from '../stores/auth'

interface WorkspaceCategory {
  name: string
  label: string
  path: string
}

interface WorkspaceEntry {
  name: string
  path: string
  dir: boolean
  size: number
  mtime: number
}

interface WorkspaceListing {
  path: string
  entries: WorkspaceEntry[]
  total: number
  hasMore: boolean
  nextOffset: number
}

interface WorkspaceFileContent {
  path: string
  content: string
  size: number
  mtime: number
  version: string
  lineEnding: 'lf' | 'crlf'
  editable: boolean
}

interface WorkspaceFileSaveResult {
  ok: boolean
  path: string
  size: number
  mtime: number
  version: string
  lineEnding: 'lf' | 'crlf'
}

const { t } = useI18n()
const auth = useAuthStore()
const canWrite = computed(() => auth.hasPermission('settings:write'))

const categories = ref<WorkspaceCategory[]>([])
const category = ref('workspace')
const currentPath = ref('')
const entries = ref<WorkspaceEntry[]>([])
const total = ref(0)
const hasMore = ref(false)
const nextOffset = ref(0)
const selected = ref<string[]>([])
const loading = ref(false)
const error = ref('')
const search = ref('')
const sortKey = ref<'name' | 'size' | 'mtime'>('name')
const sortDirection = ref<'asc' | 'desc'>('asc')
const deleting = ref(false)
const deleteTarget = ref<{ mode: 'single' | 'batch'; entries: WorkspaceEntry[] } | null>(null)
const editorOpen = ref(false)
const editorLoading = ref(false)
const editorSaving = ref(false)
const editorError = ref('')
const editorLoadFailed = ref(false)
const editorNotice = ref('')
const activeFile = ref<WorkspaceEntry | null>(null)
const activeCategory = ref('workspace')
const editorMode = ref<'text' | 'image'>('text')
const editorContent = ref('')
const originalContent = ref('')
const fileVersion = ref('')
const fileLineEnding = ref<'lf' | 'crlf'>('lf')
const fileEditable = ref(false)
const editorTextarea = ref<HTMLTextAreaElement | null>(null)

const breadcrumbs = computed(() => {
  const parts = currentPath.value.split('/').filter(Boolean)
  const items: Array<{ label: string; path: string }> = [
    { label: t('workspace.root'), path: '' },
  ]
  let path = ''
  for (const part of parts) {
    path = path ? `${path}/${part}` : part
    items.push({ label: part, path })
  }
  return items
})

const visibleEntries = computed(() => {
  const keyword = search.value.trim().toLowerCase()
  const filtered = keyword
    ? entries.value.filter((entry) => entry.name.toLowerCase().includes(keyword))
    : [...entries.value]
  const direction = sortDirection.value === 'asc' ? 1 : -1
  return filtered.sort((left, right) => {
    if (left.dir !== right.dir) {
      return left.dir ? -1 : 1
    }
    if (sortKey.value === 'size') {
      return (left.size - right.size) * direction
    }
    if (sortKey.value === 'mtime') {
      return (left.mtime - right.mtime) * direction
    }
    return left.name.localeCompare(right.name, undefined, { numeric: true }) * direction
  })
})

const allSelected = computed(
  () =>
    visibleEntries.value.length > 0 &&
    visibleEntries.value.every((item) => selected.value.includes(item.path)),
)
const selectedEntries = computed(() =>
  entries.value.filter((entry) => selected.value.includes(entry.path)),
)
const selectedSize = computed(() =>
  selectedEntries.value.reduce((totalBytes, entry) => totalBytes + (entry.dir ? 0 : entry.size), 0),
)
const directoryCount = computed(() => entries.value.filter((entry) => entry.dir).length)
const fileCount = computed(() => entries.value.filter((entry) => !entry.dir).length)
const loadedSize = computed(() =>
  entries.value.reduce((totalBytes, entry) => totalBytes + (entry.dir ? 0 : entry.size), 0),
)
const editorDirty = computed(
  () => editorMode.value === 'text' && editorContent.value !== originalContent.value,
)
const canEditFile = computed(() => canWrite.value && fileEditable.value)
const editorCharacterCount = computed(() => editorContent.value.length)
const imagePreviewUrl = computed(() => {
  const entry = activeFile.value
  if (!entry || editorMode.value !== 'image') {
    return ''
  }
  return apiUrl(
    `/workspace/download?category=${encodeURIComponent(activeCategory.value)}&path=${encodeURIComponent(entry.path)}`,
  )
})

function formatSize(bytes: number) {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`
  }
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)}KB`
  }
  return `${bytes}B`
}

function formatTime(value: number) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }
  return date.toLocaleString()
}

async function loadCategories() {
  const response = await apiGet<{ items: WorkspaceCategory[] }>('/workspace/categories')
  categories.value = response.items ?? []
  if (!categories.value.some((item) => item.name === category.value) && categories.value.length) {
    category.value = categories.value[0].name
  }
}

async function loadList(append = false) {
  if (loading.value) {
    return
  }
  loading.value = true
  error.value = ''
  try {
    const offset = append ? nextOffset.value : 0
    const response = await apiGet<WorkspaceListing>(
      `/workspace/list?category=${encodeURIComponent(category.value)}&path=${encodeURIComponent(currentPath.value)}&limit=500&offset=${offset}`,
    )
    entries.value = append ? [...entries.value, ...(response.entries ?? [])] : response.entries ?? []
    currentPath.value = response.path || ''
    total.value = response.total || 0
    hasMore.value = Boolean(response.hasMore)
    nextOffset.value = response.nextOffset || entries.value.length
    if (append) {
      const available = new Set(entries.value.map((entry) => entry.path))
      selected.value = selected.value.filter((path) => available.has(path))
    } else {
      selected.value = []
    }
  } catch (loadError) {
    error.value = loadError instanceof Error ? loadError.message : t('workspace.loadFailed')
  } finally {
    loading.value = false
  }
}

function switchCategory(name: string) {
  category.value = name
  currentPath.value = ''
  void loadList()
}

function isImageEntry(entry: WorkspaceEntry) {
  const extension = entry.name.split('.').pop()?.toLowerCase() ?? ''
  return ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico'].includes(extension)
}

function isBinaryEntry(entry: WorkspaceEntry) {
  const extension = entry.name.split('.').pop()?.toLowerCase() ?? ''
  return [
    'zip',
    'tar',
    'gz',
    'bz2',
    'xz',
    '7z',
    'rar',
    'jar',
    'apk',
    'exe',
    'dll',
    'so',
    'bin',
    'class',
    'pdf',
    'doc',
    'docx',
    'xls',
    'xlsx',
    'ppt',
    'pptx',
  ].includes(extension)
}

function canPreviewEntry(entry: WorkspaceEntry) {
  return !entry.dir && !isBinaryEntry(entry)
}

function openEntry(entry: WorkspaceEntry) {
  if (entry.dir) {
    currentPath.value = entry.path
    void loadList()
    return
  }
  if (isImageEntry(entry)) {
    openImagePreview(entry)
    return
  }
  if (isBinaryEntry(entry)) {
    downloadEntry(entry)
    return
  }
  void openTextEditor(entry)
}

function navigate(path: string) {
  currentPath.value = path
  void loadList()
}

function goParent() {
  const parts = currentPath.value.split('/').filter(Boolean)
  parts.pop()
  currentPath.value = parts.join('/')
  void loadList()
}

function downloadEntry(entry: WorkspaceEntry, sourceCategory = category.value) {
  const link = document.createElement('a')
  link.href = apiUrl(
    `/workspace/download?category=${encodeURIComponent(sourceCategory)}&path=${encodeURIComponent(entry.path)}`,
  )
  link.download = entry.name
  document.body.appendChild(link)
  link.click()
  link.remove()
}

function openImagePreview(entry: WorkspaceEntry) {
  activeFile.value = entry
  activeCategory.value = category.value
  editorMode.value = 'image'
  fileEditable.value = false
  editorLoading.value = false
  editorError.value = ''
  editorLoadFailed.value = false
  editorNotice.value = ''
  editorOpen.value = true
}

async function openTextEditor(entry: WorkspaceEntry) {
  activeFile.value = entry
  activeCategory.value = category.value
  editorMode.value = 'text'
  editorOpen.value = true
  editorLoading.value = true
  editorError.value = ''
  editorLoadFailed.value = false
  editorNotice.value = ''
  editorContent.value = ''
  originalContent.value = ''
  fileVersion.value = ''
  fileLineEnding.value = 'lf'
  fileEditable.value = false
  try {
    const response = await apiGet<WorkspaceFileContent>(
      `/workspace/content?category=${encodeURIComponent(activeCategory.value)}&path=${encodeURIComponent(entry.path)}`,
    )
    const normalizedContent = response.content.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    editorContent.value = normalizedContent
    originalContent.value = normalizedContent
    fileVersion.value = response.version
    fileLineEnding.value = response.lineEnding === 'crlf' ? 'crlf' : 'lf'
    fileEditable.value = response.editable
    entry.size = response.size
    entry.mtime = response.mtime
    await nextTick()
    editorTextarea.value?.focus()
  } catch (loadError) {
    editorError.value = loadError instanceof Error ? loadError.message : t('workspace.loadFileFailed')
    editorLoadFailed.value = true
  } finally {
    editorLoading.value = false
  }
}

function closeEditor() {
  editorOpen.value = false
  editorLoading.value = false
  editorSaving.value = false
  editorError.value = ''
  editorLoadFailed.value = false
  editorNotice.value = ''
  activeFile.value = null
  editorContent.value = ''
  originalContent.value = ''
  fileVersion.value = ''
  fileEditable.value = false
}

function requestCloseEditor() {
  if (editorSaving.value) {
    return
  }
  if (editorDirty.value && !window.confirm(t('workspace.discardConfirm'))) {
    return
  }
  closeEditor()
}

async function reloadEditor() {
  const entry = activeFile.value
  if (!entry || editorSaving.value) {
    return
  }
  if (editorDirty.value && !window.confirm(t('workspace.reloadConfirm'))) {
    return
  }
  await openTextEditor(entry)
}

async function saveEditor() {
  const entry = activeFile.value
  if (
    !entry ||
    editorMode.value !== 'text' ||
    editorLoading.value ||
    editorSaving.value ||
    !canEditFile.value
  ) {
    return
  }
  if (!editorDirty.value) {
    return
  }
  editorSaving.value = true
  editorError.value = ''
  editorNotice.value = ''
  try {
    const result = await apiTextPut<WorkspaceFileSaveResult>(
      `/workspace/content?category=${encodeURIComponent(activeCategory.value)}&path=${encodeURIComponent(entry.path)}`,
      editorContent.value,
      {
        'X-Workspace-Version': fileVersion.value,
        'X-Workspace-Line-Ending': fileLineEnding.value,
      },
    )
    originalContent.value = editorContent.value
    fileVersion.value = result.version
    fileLineEnding.value = result.lineEnding === 'crlf' ? 'crlf' : 'lf'
    entry.size = result.size
    entry.mtime = result.mtime
    editorNotice.value = t('workspace.saved')
  } catch (saveError) {
    editorError.value =
      saveError instanceof ApiError && saveError.status === 409
        ? t('workspace.fileConflict')
        : saveError instanceof Error
          ? saveError.message
          : t('workspace.saveFailed')
  } finally {
    editorSaving.value = false
  }
}

function handleEditorKeydown(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
    event.preventDefault()
    void saveEditor()
    return
  }
  if (event.key === 'Escape') {
    event.preventDefault()
    requestCloseEditor()
    return
  }
  if (event.key !== 'Tab' || !canEditFile.value || editorMode.value !== 'text') {
    return
  }
  event.preventDefault()
  const textarea = event.currentTarget as HTMLTextAreaElement
  textarea.setRangeText('  ', textarea.selectionStart, textarea.selectionEnd, 'end')
  editorContent.value = textarea.value
}

function handleEditorInput() {
  editorNotice.value = ''
  editorError.value = ''
}

function handleBeforeUnload(event: BeforeUnloadEvent) {
  if (!editorDirty.value) {
    return
  }
  event.preventDefault()
  event.returnValue = ''
}

function toggleSelect(path: string) {
  const index = selected.value.indexOf(path)
  if (index >= 0) {
    selected.value.splice(index, 1)
  } else {
    selected.value.push(path)
  }
}

function toggleSelectAll() {
  selected.value = allSelected.value ? [] : visibleEntries.value.map((item) => item.path)
}

function sortBy(key: 'name' | 'size' | 'mtime') {
  if (sortKey.value === key) {
    sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
    return
  }
  sortKey.value = key
  sortDirection.value = key === 'name' ? 'asc' : 'desc'
}

function requestDelete(entry: WorkspaceEntry) {
  if (canWrite.value) {
    deleteTarget.value = { mode: 'single', entries: [entry] }
  }
}

function requestBatchDelete() {
  if (canWrite.value && selectedEntries.value.length) {
    deleteTarget.value = { mode: 'batch', entries: [...selectedEntries.value] }
  }
}

function closeDeleteDialog() {
  if (!deleting.value) {
    deleteTarget.value = null
  }
}

function fileKind(entry: WorkspaceEntry) {
  if (entry.dir) {
    return 'folder'
  }
  const extension = entry.name.split('.').pop()?.toLowerCase() ?? ''
  if (['zip', 'tar', 'gz', '7z', 'rar'].includes(extension)) {
    return 'archive'
  }
  if (['js', 'ts', 'go', 'py', 'java', 'php', 'cs', 'sh', 'json', 'yaml', 'yml'].includes(extension)) {
    return 'code'
  }
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(extension)) {
    return 'image'
  }
  if (['log', 'txt', 'md'].includes(extension)) {
    return 'text'
  }
  return 'file'
}

function fileExtension(entry: WorkspaceEntry) {
  if (entry.dir) {
    return ''
  }
  const parts = entry.name.split('.')
  return parts.length > 1 ? parts.pop()!.toUpperCase().slice(0, 5) : 'FILE'
}

async function confirmDelete() {
  const target = deleteTarget.value
  if (!target || !canWrite.value || deleting.value) {
    return
  }
  deleting.value = true
  error.value = ''
  try {
    if (target.mode === 'single') {
      await apiDelete(
        `/workspace/delete?category=${encodeURIComponent(category.value)}&path=${encodeURIComponent(target.entries[0].path)}`,
      )
    } else {
      const response = await apiPost<{ deleted: number; failed: Array<{ path: string; reason: string }> }>(
        '/workspace/batch-delete',
        { category: category.value, paths: target.entries.map((entry) => entry.path) },
      )
      if (response.failed?.length) {
        error.value = t('workspace.partialDelete', {
          deleted: response.deleted,
          failed: response.failed.length,
        })
      }
    }
    deleteTarget.value = null
    await loadList()
  } catch (deleteError) {
    error.value = deleteError instanceof Error ? deleteError.message : t('workspace.deleteFailed')
    deleteTarget.value = null
  } finally {
    deleting.value = false
  }
}

onMounted(async () => {
  window.addEventListener('beforeunload', handleBeforeUnload)
  try {
    await loadCategories()
    await loadList()
  } catch (loadError) {
    error.value = loadError instanceof Error ? loadError.message : t('workspace.loadFailed')
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('beforeunload', handleBeforeUnload)
})
</script>

<template>
  <section class="page factory-page page-workspace artifact-depot">
    <header class="page-header depot-header">
      <div class="depot-heading page-heading-with-robot">
        <PageTitleRobot tone="cyan" />
        <div>
          <p class="eyebrow">WORKSPACE FLOOR // ARTIFACT DEPOT</p>
          <h1>{{ t('workspace.depot') }}</h1>
          <p class="depot-page-hint">{{ t('workspace.subtitle') }}</p>
        </div>
      </div>
      <button class="button" type="button" :disabled="loading" @click="loadList()">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" />
        </svg>
        {{ t('workspace.refresh') }}
      </button>
    </header>

    <div v-if="error" class="alert error depot-alert">{{ error }}</div>

    <section class="depot-status-rail">
      <article class="depot-stat">
        <small>
          <svg class="depot-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 7h6l2 2h10v10H3z" />
            <path d="M3 7V5h6l2 2" />
          </svg>
          {{ t('workspace.directories') }}
        </small>
        <strong>{{ directoryCount }}</strong>
      </article>
      <article class="depot-stat tone-file">
        <small>
          <svg class="depot-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M6 3h8l4 4v14H6z" />
            <path d="M14 3v5h4M9 12h6M9 16h6" />
          </svg>
          {{ t('workspace.files') }}
        </small>
        <strong>{{ fileCount }}</strong>
      </article>
      <article class="depot-stat tone-size">
        <small>
          <svg class="depot-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <ellipse cx="12" cy="6" rx="7" ry="3" />
            <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6" />
            <path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
          </svg>
          {{ t('workspace.loadedSize') }}
        </small>
        <strong>{{ formatSize(loadedSize) }}</strong>
      </article>
      <article class="depot-stat tone-selected">
        <small>
          <svg class="depot-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="4" width="16" height="16" rx="2" />
            <path d="m8 12 3 3 5-6" />
          </svg>
          {{ t('workspace.selectedItems') }}
        </small>
        <strong>{{ selected.length }}</strong>
      </article>
      <div class="depot-track" aria-hidden="true"><i></i></div>
    </section>

    <div class="depot-layout">
      <aside class="depot-zones">
        <header>
          <span class="depot-code">ZONES // STORAGE</span>
          <h2>{{ t('workspace.warehouseZones') }}</h2>
        </header>
        <div class="depot-zone-list">
          <button
            v-for="item in categories"
            :key="item.name"
            type="button"
            class="depot-zone"
            :class="{ active: item.name === category }"
            @click="switchCategory(item.name)"
          >
            <span class="zone-rack" aria-hidden="true"><i></i><i></i><i></i></span>
            <span><strong>{{ item.label }}</strong><small>{{ item.path }}</small></span>
          </button>
        </div>
      </aside>

      <section class="depot-panel">
        <header class="depot-path-header">
          <div class="depot-path-block">
            <span class="depot-code">RACK PATH</span>
            <nav class="depot-breadcrumbs">
              <template v-for="(item, index) in breadcrumbs" :key="item.path || 'root'">
                <span v-if="index">/</span>
                <button type="button" @click="navigate(item.path)">{{ item.label }}</button>
              </template>
            </nav>
          </div>
          <div class="depot-path-actions">
            <button class="button compact" type="button" :disabled="!currentPath" @click="goParent">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6" /></svg>
              {{ t('workspace.parent') }}
            </button>
          </div>
        </header>

        <div class="depot-toolbar">
          <label class="depot-search-box">
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg>
            <input v-model="search" type="search" :placeholder="t('workspace.searchPlaceholder')" />
          </label>
          <div class="depot-sort">
            <button type="button" :class="{ active: sortKey === 'name' }" @click="sortBy('name')">
              {{ t('workspace.sortName') }} {{ sortKey === 'name' ? (sortDirection === 'asc' ? '↑' : '↓') : '↕' }}
            </button>
            <button type="button" :class="{ active: sortKey === 'size' }" @click="sortBy('size')">
              {{ t('workspace.sortSize') }} {{ sortKey === 'size' ? (sortDirection === 'asc' ? '↑' : '↓') : '↕' }}
            </button>
            <button type="button" :class="{ active: sortKey === 'mtime' }" @click="sortBy('mtime')">
              {{ t('workspace.sortModified') }} {{ sortKey === 'mtime' ? (sortDirection === 'asc' ? '↑' : '↓') : '↕' }}
            </button>
          </div>
          <span class="depot-count">{{ t('common.total', { count: total }) }}</span>
        </div>

        <div v-if="selected.length" class="depot-bulk-bar">
          <span>{{ t('workspace.selectedSummary', { count: selected.length, size: formatSize(selectedSize) }) }}</span>
          <button type="button" @click="selected = []">{{ t('workspace.cancelSelection') }}</button>
          <button class="danger" type="button" :disabled="!canWrite" @click="requestBatchDelete">
            {{ t('workspace.batchDelete', { count: selected.length }) }}
          </button>
        </div>

        <div v-if="loading && !entries.length" class="depot-loading">
          <i></i><i></i><i></i>
          <span>{{ t('common.loading') }}</span>
        </div>
        <div v-else-if="!entries.length" class="depot-empty-state">
          <span class="empty-depot-robot" aria-hidden="true"><i></i><b></b><b></b><em></em></span>
          <strong>{{ t('workspace.empty') }}</strong>
        </div>
        <div v-else-if="!visibleEntries.length" class="depot-empty-state compact">
          <span class="empty-crate" aria-hidden="true"></span>
          <strong>{{ t('workspace.noMatches') }}</strong>
        </div>
        <div v-else class="depot-file-list">
          <div class="depot-file-head">
            <label class="depot-check"><input type="checkbox" :checked="allSelected" @change="toggleSelectAll" /></label>
            <span>{{ t('workspace.name') }}</span>
            <span>{{ t('workspace.size') }}</span>
            <span>{{ t('workspace.modified') }}</span>
            <span>{{ t('workspace.actions') }}</span>
          </div>
          <div
            v-for="entry in visibleEntries"
            :key="entry.path"
            class="depot-file-row"
            :class="[`kind-${fileKind(entry)}`, { selected: selected.includes(entry.path) }]"
          >
            <label class="depot-check">
              <input type="checkbox" :checked="selected.includes(entry.path)" @change="toggleSelect(entry.path)" />
            </label>
            <button class="depot-file-name" type="button" :title="entry.name" @click="openEntry(entry)">
              <span class="artifact-icon" :class="`kind-${fileKind(entry)}`" aria-hidden="true">
                <svg v-if="entry.dir" viewBox="0 0 24 24"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /></svg>
                <svg v-else-if="fileKind(entry) === 'archive'" viewBox="0 0 24 24"><path d="M4 7h16v13H4zM8 7V4h8v3M9 11h6M9 15h6" /></svg>
                <svg v-else-if="fileKind(entry) === 'code'" viewBox="0 0 24 24"><path d="m8 8-4 4 4 4M16 8l4 4-4 4M13 5l-2 14" /></svg>
                <svg v-else-if="fileKind(entry) === 'image'" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="9" r="2" /><path d="m21 15-5-5L5 20" /></svg>
                <svg v-else viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6" /></svg>
                <b v-if="!entry.dir">{{ fileExtension(entry) }}</b>
              </span>
              <span class="depot-name-copy">
                <strong>{{ entry.name }}</strong>
                <small>{{ entry.dir ? t('workspace.directories') : fileExtension(entry) }}</small>
              </span>
            </button>
            <span class="depot-meta">{{ entry.dir ? '-' : formatSize(entry.size) }}</span>
            <time class="depot-meta">{{ formatTime(entry.mtime) }}</time>
            <div class="depot-row-actions">
              <button v-if="canPreviewEntry(entry)" class="depot-icon-action preview" type="button" :title="t('workspace.preview')" @click="openEntry(entry)">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.5" /></svg>
              </button>
              <button v-if="!entry.dir" class="depot-icon-action download" type="button" :title="t('workspace.download')" @click="downloadEntry(entry)">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 21h14" /></svg>
              </button>
              <button class="depot-icon-action danger" type="button" :disabled="!canWrite" :title="t('workspace.delete')" @click="requestDelete(entry)">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5" /></svg>
              </button>
            </div>
          </div>
        </div>

        <button v-if="hasMore" class="button depot-load-more" type="button" :disabled="loading" @click="loadList(true)">
          {{ loading ? t('common.loading') : t('common.loadMore') }}
        </button>
      </section>
    </div>

    <Teleport to="body">
      <div v-if="deleteTarget" class="depot-dialog-layer" @click.self="closeDeleteDialog">
        <aside class="depot-dialog" role="dialog" aria-modal="true">
          <header>
            <span class="depot-warning-mark" aria-hidden="true"><i></i><b>!</b></span>
            <div>
              <span class="depot-code">DANGER HANDLING</span>
              <h2>{{ t('workspace.deleteConfirmTitle') }}</h2>
            </div>
          </header>
          <p v-if="deleteTarget.mode === 'single'">
            {{ t('workspace.deleteConfirmSingle', { name: deleteTarget.entries[0].name }) }}
          </p>
          <p v-else>
            {{ t('workspace.deleteConfirmBatch', { count: deleteTarget.entries.length }) }}
          </p>
          <div class="depot-dialog-items">
            <span v-for="entry in deleteTarget.entries.slice(0, 5)" :key="entry.path">{{ entry.name }}</span>
            <small v-if="deleteTarget.entries.length > 5">+{{ deleteTarget.entries.length - 5 }}</small>
          </div>
          <footer>
            <button class="button compact" type="button" :disabled="deleting" @click="closeDeleteDialog">{{ t('common.cancel') }}</button>
            <button class="button compact danger" type="button" :disabled="deleting" @click="confirmDelete">
              {{ deleting ? t('workspace.deleting') : t('workspace.deletePermanently') }}
            </button>
          </footer>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="editorOpen && activeFile" class="depot-editor-layer" @click.self="requestCloseEditor">
        <aside
          class="depot-editor-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="workspace-editor-title"
        >
          <header class="depot-editor-header">
            <div class="depot-editor-heading">
              <span class="artifact-icon" :class="`kind-${fileKind(activeFile)}`" aria-hidden="true">
                <svg v-if="editorMode === 'image'" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="9" r="2" /><path d="m21 15-5-5L5 20" /></svg>
                <svg v-else viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6M8 13h8M8 17h6" /></svg>
              </span>
              <div>
                <span class="depot-code">FILE WORKBENCH // {{ fileExtension(activeFile) }}</span>
                <h2 id="workspace-editor-title">{{ activeFile.name }}</h2>
                <p>{{ activeCategory }} / {{ activeFile.path }}</p>
              </div>
            </div>
            <div class="depot-editor-heading-actions">
              <span v-if="editorDirty" class="depot-editor-state dirty">{{ t('workspace.unsaved') }}</span>
              <span v-else-if="editorNotice" class="depot-editor-state saved">{{ editorNotice }}</span>
              <span v-else class="depot-editor-state">{{ canEditFile && editorMode === 'text' ? t('workspace.editable') : t('workspace.readOnly') }}</span>
              <button class="depot-editor-close" type="button" :title="t('workspace.close')" :aria-label="t('workspace.close')" :disabled="editorSaving" @click="requestCloseEditor">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
              </button>
            </div>
          </header>

          <div class="depot-editor-meta">
            <span>{{ t('workspace.editor') }}</span>
            <span>{{ editorMode === 'text' ? t('workspace.characters', { count: editorCharacterCount }) : t('workspace.imagePreview') }}</span>
            <span>{{ formatSize(activeFile.size) }}</span>
            <span v-if="editorMode === 'text'">{{ fileLineEnding.toUpperCase() }}</span>
          </div>

          <div v-if="editorError && !editorLoadFailed" class="depot-editor-inline-error" role="alert">
            <span aria-hidden="true">!</span>
            <p>{{ editorError }}</p>
          </div>
          <div v-if="editorLoadFailed" class="depot-editor-message error">
            <span aria-hidden="true">!</span>
            <p>{{ editorError }}</p>
            <button class="button compact" type="button" @click="downloadEntry(activeFile, activeCategory)">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 21h14" /></svg>
              {{ t('workspace.download') }}
            </button>
          </div>
          <div v-else-if="editorLoading" class="depot-editor-loading">
            <i></i><i></i><i></i>
            <span>{{ t('common.loading') }}</span>
          </div>
          <div v-else-if="editorMode === 'image'" class="depot-image-preview">
            <img :src="imagePreviewUrl" :alt="activeFile.name" @error="editorError = t('workspace.unsupportedPreview')" />
          </div>
          <div v-else class="depot-editor-code">
            <textarea
              ref="editorTextarea"
              v-model="editorContent"
              :readonly="!canEditFile"
              :aria-label="activeFile.name"
              spellcheck="false"
              autocomplete="off"
              autocapitalize="off"
              @input="handleEditorInput"
              @keydown="handleEditorKeydown"
            ></textarea>
          </div>

          <footer class="depot-editor-footer">
            <span v-if="editorError" class="depot-editor-footer-note">{{ editorError }}</span>
            <span v-else-if="editorDirty" class="depot-editor-footer-note">{{ t('workspace.unsaved') }}</span>
            <span v-else class="depot-editor-footer-note">{{ formatTime(activeFile.mtime) }}</span>
            <div>
              <button v-if="editorMode === 'text' && !editorLoading" class="button compact" type="button" :disabled="editorSaving" @click="reloadEditor">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
                {{ t('workspace.reload') }}
              </button>
              <button class="button compact" type="button" @click="downloadEntry(activeFile, activeCategory)">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 21h14" /></svg>
                {{ t('workspace.download') }}
              </button>
              <button
                v-if="editorMode === 'text' && canEditFile && !editorLoading"
                class="button compact primary"
                type="button"
                :disabled="editorSaving || !editorDirty"
                @click="saveEditor"
              >
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 3h11l3 3v15H5zM8 3v6h8V3M8 14h8v7H8z" /></svg>
                {{ editorSaving ? t('common.saving') : t('common.save') }}
              </button>
            </div>
          </footer>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.workspace-page {
  display: grid;
  gap: 14px;
}

.workspace-categories {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.workspace-category {
  padding: 7px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-secondary);
  background: var(--surface);
  cursor: pointer;
}

.workspace-category.active {
  border-color: var(--accent);
  color: #ffffff;
  background: var(--accent-lime);
  box-shadow: none;
}

.workspace-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.workspace-breadcrumbs {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 5px;
  color: var(--text-muted);
  font-size: 12px;
}

.workspace-breadcrumbs button {
  border: 0;
  color: var(--accent);
  background: transparent;
  cursor: pointer;
}

.workspace-actions {
  display: flex;
  gap: 8px;
}

.workspace-table {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.workspace-row {
  display: grid;
  grid-template-columns: 32px minmax(0, 1fr) 110px 180px 90px;
  gap: 10px;
  align-items: center;
  min-height: 42px;
  padding: 5px 10px;
  border-bottom: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 12px;
}

.workspace-row:last-child {
  border-bottom: 0;
}

.workspace-row.selected {
  background: var(--accent-soft);
  box-shadow: inset 3px 0 0 var(--accent);
}

.workspace-head {
  min-height: 34px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-weight: 600;
}

.workspace-name {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  border: 0;
  color: var(--text-primary);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.workspace-name span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.workspace-name svg {
  width: 16px;
  height: 16px;
  flex: 0 0 auto;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
}

.workspace-row-actions {
  display: flex;
  gap: 4px;
}

.workspace-empty {
  padding: 40px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  color: var(--text-muted);
  text-align: center;
}

.workspace-load-more {
  justify-self: center;
}

@media (max-width: 820px) {
  .workspace-row {
    grid-template-columns: 28px minmax(0, 1fr) 80px 70px;
  }

  .workspace-row > :nth-child(4) {
    display: none;
  }
}
</style>

<style scoped>
.depot-editor-layer {
  position: fixed;
  z-index: 1200;
  inset: 0;
  display: flex;
  justify-content: flex-end;
  background: rgba(3, 8, 9, 0.7);
  backdrop-filter: blur(4px);
}

.depot-editor-panel {
  display: flex;
  flex-direction: column;
  width: min(820px, calc(100vw - 44px));
  height: 100dvh;
  overflow: hidden;
  border-left: 1px solid color-mix(in srgb, var(--depot-accent) 46%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--depot-accent) 6%, transparent), transparent 130px),
    var(--surface);
  box-shadow: -24px 0 70px rgba(0, 0, 0, 0.38);
  animation: depot-editor-enter 180ms ease-out;
}

.depot-editor-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  min-width: 0;
  padding: 20px 22px 16px;
  border-bottom: 1px solid var(--depot-line);
}

.depot-editor-heading {
  display: flex;
  align-items: center;
  min-width: 0;
  gap: 12px;
}

.depot-editor-heading .artifact-icon {
  flex: 0 0 43px;
  width: 43px;
  height: 43px;
}

.depot-editor-heading > div {
  min-width: 0;
}

.depot-editor-heading h2 {
  overflow: hidden;
  margin: 2px 0 4px;
  color: var(--text-primary);
  font-size: 19px;
  line-height: 1.25;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-editor-heading p {
  overflow: hidden;
  margin: 0;
  color: var(--text-muted);
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-editor-heading-actions {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 8px;
}

.depot-editor-state {
  padding: 4px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-muted);
  background: var(--field-bg);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

.depot-editor-state.dirty {
  border-color: color-mix(in srgb, var(--depot-amber) 45%, var(--border));
  color: var(--depot-amber);
}

.depot-editor-state.saved {
  border-color: color-mix(in srgb, var(--depot-mint) 45%, var(--border));
  color: var(--depot-mint);
}

.depot-editor-close {
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-secondary);
  background: var(--field-bg);
  cursor: pointer;
}

.depot-editor-close:hover {
  border-color: var(--depot-coral);
  color: var(--depot-coral);
}

.depot-editor-close svg,
.depot-editor-footer svg,
.depot-editor-message svg {
  width: 16px;
  height: 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
}

.depot-editor-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  padding: 9px 22px;
  border-bottom: 1px solid var(--depot-line);
  color: var(--text-muted);
  background: color-mix(in srgb, var(--field-bg) 74%, transparent);
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 10px;
}

.depot-editor-code,
.depot-image-preview,
.depot-editor-message,
.depot-editor-loading {
  flex: 1 1 auto;
  min-height: 0;
  margin: 14px 16px;
}

.depot-editor-inline-error {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 10px 16px 0;
  padding: 9px 12px;
  border: 1px solid color-mix(in srgb, var(--depot-coral) 46%, var(--border));
  border-radius: 3px;
  color: var(--depot-coral);
  background: color-mix(in srgb, var(--depot-coral) 8%, var(--surface));
  font-size: 12px;
}

.depot-editor-inline-error span {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  flex: 0 0 20px;
  border: 1px solid currentColor;
  border-radius: 50%;
  font-family: Consolas, monospace;
  font-size: 11px;
}

.depot-editor-inline-error p {
  margin: 0;
}

.depot-editor-code {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--depot-line);
  border-radius: 4px;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--depot-accent) 5%, transparent), transparent 50px),
    color-mix(in srgb, var(--field-bg) 82%, #050a0b);
}

.depot-editor-code::before {
  position: absolute;
  z-index: 1;
  top: 0;
  bottom: 0;
  left: 0;
  width: 3px;
  background: linear-gradient(var(--depot-accent), var(--depot-mint));
  content: "";
  opacity: 0.7;
  pointer-events: none;
}

.depot-editor-code textarea {
  width: 100%;
  height: 100%;
  min-height: 280px;
  padding: 17px 18px 28px 20px;
  resize: none;
  border: 0;
  outline: 0;
  color: #d7e2e4;
  background: transparent;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 12px;
  line-height: 1.65;
  tab-size: 2;
  white-space: pre;
}

.depot-editor-code textarea[readonly] {
  color: color-mix(in srgb, var(--text-secondary) 88%, transparent);
}

.depot-image-preview {
  display: grid;
  place-items: center;
  overflow: auto;
  border: 1px solid var(--depot-line);
  border-radius: 4px;
  background:
    linear-gradient(45deg, color-mix(in srgb, var(--field-bg) 92%, white) 25%, transparent 25%),
    linear-gradient(-45deg, color-mix(in srgb, var(--field-bg) 92%, white) 25%, transparent 25%),
    linear-gradient(45deg, transparent 75%, color-mix(in srgb, var(--field-bg) 92%, white) 75%),
    linear-gradient(-45deg, transparent 75%, color-mix(in srgb, var(--field-bg) 92%, white) 75%);
  background-position: 0 0, 0 8px, 8px -8px, -8px 0;
  background-size: 16px 16px;
}

.depot-image-preview img {
  display: block;
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}

.depot-editor-message,
.depot-editor-loading {
  display: grid;
  place-items: center;
  align-content: center;
  gap: 12px;
  border: 1px dashed var(--border-strong);
  border-radius: 4px;
  color: var(--text-muted);
  text-align: center;
}

.depot-editor-message.error > span {
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  border: 1px solid color-mix(in srgb, var(--depot-coral) 55%, var(--border));
  border-radius: 50%;
  color: var(--depot-coral);
  font-family: Consolas, monospace;
  font-size: 18px;
}

.depot-editor-message p {
  max-width: 520px;
  margin: 0;
}

.depot-editor-loading {
  grid-template-columns: repeat(3, 8px);
}

.depot-editor-loading span {
  grid-column: 1 / -1;
}

.depot-editor-loading i {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--depot-accent);
  animation: depot-editor-pulse 900ms ease-in-out infinite alternate;
}

.depot-editor-loading i:nth-child(2) {
  animation-delay: 150ms;
}

.depot-editor-loading i:nth-child(3) {
  animation-delay: 300ms;
}

.depot-editor-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  min-width: 0;
  padding: 12px 18px;
  border-top: 1px solid var(--depot-line);
  background: color-mix(in srgb, var(--surface) 94%, var(--field-bg));
}

.depot-editor-footer > div {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 7px;
}

.depot-editor-footer-note {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-editor-footer .button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.depot-editor-footer .button.primary {
  border-color: color-mix(in srgb, var(--depot-mint) 65%, var(--border));
  color: #06100c;
  background: var(--depot-mint);
}

.depot-icon-action.preview:hover {
  color: var(--depot-accent);
}

@keyframes depot-editor-enter {
  from {
    opacity: 0;
    transform: translateX(24px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

@keyframes depot-editor-pulse {
  from {
    opacity: 0.35;
    transform: translateY(2px);
  }
  to {
    opacity: 1;
    transform: translateY(-2px);
  }
}

@media (max-width: 760px) {
  .depot-editor-panel {
    width: 100vw;
    border-left: 0;
  }

  .depot-editor-header {
    padding: 16px 14px 13px;
  }

  .depot-editor-heading .artifact-icon {
    display: none;
  }

  .depot-editor-state {
    display: none;
  }

  .depot-editor-meta {
    padding: 8px 14px;
  }

  .depot-editor-code,
  .depot-image-preview,
  .depot-editor-message,
  .depot-editor-loading {
    margin: 10px;
  }

  .depot-editor-footer {
    align-items: stretch;
    flex-direction: column;
    padding: 10px;
  }

  .depot-editor-footer > div,
  .depot-editor-footer .button {
    width: 100%;
  }

  .depot-editor-footer .button {
    justify-content: center;
  }
}
</style>

<style scoped>
.main-column .page-workspace .depot-header h1 {
  font-size: 26px;
}

.main-column .page-workspace .depot-header .eyebrow {
  font-size: 9px;
}

.main-column .page-workspace .depot-page-hint {
  font-size: 13px;
  line-height: 1.45;
}

.depot-stat small {
  font-size: 10px;
}
</style>

<style scoped>
/* Artifact depot */
.main-column .page-workspace.artifact-depot {
  --depot-accent: #55c7e8;
  --depot-mint: #34d399;
  --depot-amber: #f0a43a;
  --depot-violet: #9d8cff;
  --depot-coral: #fb7185;
  --depot-panel: color-mix(in srgb, var(--surface) 95%, #071012);
  --depot-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-workspace.artifact-depot .depot-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--depot-accent) 24%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--depot-accent) 9%, transparent), transparent 38%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--depot-accent) 5%, transparent) 37px 38px
    ),
    var(--depot-panel) !important;
}

.depot-heading {
  display: flex;
  min-width: 0;
  gap: 13px;
  align-items: center;
}

.depot-heading > div {
  min-width: 0;
}

.depot-robot {
  position: relative;
  display: block;
  flex: 0 0 54px;
  width: 54px;
  height: 52px;
  color: var(--depot-accent);
}

.depot-robot-antenna {
  position: absolute;
  top: 0;
  left: 21px;
  width: 2px;
  height: 8px;
  background: currentColor;
}

.depot-robot-antenna::before {
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

.depot-robot-face {
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

.depot-robot-face b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
  animation: depot-eye 3.2s ease-in-out infinite;
}

.depot-robot-body {
  position: absolute;
  bottom: 3px;
  left: 8px;
  width: 28px;
  height: 13px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

.depot-box {
  position: absolute;
  right: 0;
  bottom: 0;
  width: 18px;
  height: 16px;
  border: 1px solid var(--depot-amber);
  border-radius: 2px;
  background: color-mix(in srgb, var(--depot-amber) 14%, var(--surface));
}

.depot-box::before,
.depot-box::after {
  position: absolute;
  content: '';
  background: var(--depot-amber);
}

.depot-box::before {
  top: 0;
  bottom: 0;
  left: 7px;
  width: 1px;
}

.depot-box::after {
  top: 6px;
  right: 0;
  left: 0;
  height: 1px;
}

.main-column .page-workspace .depot-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.depot-header .button {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.depot-header .button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.depot-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.depot-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(4, minmax(110px, 1fr));
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--depot-line);
  border-radius: 5px;
  background: var(--depot-line);
}

.depot-stat {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 8px;
  min-height: 65px;
  padding: 9px 11px;
  background: var(--depot-panel);
}

.depot-stat::after {
  position: absolute;
  bottom: 0;
  left: 11px;
  width: 28px;
  height: 2px;
  content: '';
  background: var(--depot-amber);
}

.depot-stat.tone-file::after {
  background: var(--depot-accent);
}

.depot-stat.tone-size::after {
  background: var(--depot-violet);
}

.depot-stat.tone-selected::after {
  background: var(--depot-mint);
}

.depot-stat > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.depot-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 500;
}

.depot-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 9px;
}

.depot-track {
  position: absolute;
  right: 12px;
  bottom: 8px;
  width: 43px;
  height: 8px;
  overflow: hidden;
  opacity: 0.45;
}

.depot-track::before {
  position: absolute;
  inset: 0;
  content: '';
  background: repeating-linear-gradient(
    90deg,
    var(--depot-accent) 0 3px,
    transparent 3px 7px
  );
}

.depot-track i {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--depot-mint);
  box-shadow: 0 0 7px var(--depot-mint);
  animation: depot-track-scan 4s linear infinite;
}

.depot-layout {
  display: grid;
  grid-template-columns: 210px minmax(0, 1fr);
  gap: 10px;
  align-items: start;
}

.depot-zones,
.depot-panel {
  border: 1px solid color-mix(in srgb, var(--depot-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--depot-panel);
}

.depot-zones {
  position: sticky;
  top: 10px;
  overflow: hidden;
}

.depot-zones > header {
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
}

.depot-code {
  color: var(--depot-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.depot-zones h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 600;
}

.depot-zone-list {
  display: grid;
  gap: 4px;
  padding: 8px;
}

.depot-zone {
  display: grid;
  grid-template-columns: 29px minmax(0, 1fr);
  gap: 8px;
  align-items: center;
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-secondary);
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.depot-zone:hover {
  border-color: color-mix(in srgb, var(--depot-accent) 30%, var(--border));
  background: color-mix(in srgb, var(--depot-accent) 4%, transparent);
}

.depot-zone.active {
  border-color: color-mix(in srgb, var(--depot-accent) 48%, var(--border));
  background: color-mix(in srgb, var(--depot-accent) 8%, transparent);
  box-shadow: inset 2px 0 0 var(--depot-accent);
}

.zone-rack {
  position: relative;
  display: flex;
  width: 27px;
  height: 25px;
  align-items: flex-end;
  justify-content: center;
  gap: 2px;
  border: 1px solid color-mix(in srgb, var(--depot-amber) 52%, var(--border));
  border-radius: 2px;
  background: color-mix(in srgb, var(--depot-amber) 7%, var(--surface));
}

.zone-rack i {
  width: 5px;
  height: 12px;
  border: 1px solid var(--depot-amber);
  border-bottom: 0;
}

.zone-rack i:nth-child(2) {
  height: 17px;
}

.depot-zone > span:last-child {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.depot-zone strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-zone small {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-panel {
  min-width: 0;
  overflow: hidden;
}

.depot-path-header {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--depot-accent) 5%, transparent), transparent 45%),
    var(--depot-panel);
}

.depot-path-block {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.depot-breadcrumbs {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 9px;
}

.depot-breadcrumbs button {
  padding: 0;
  border: 0;
  color: var(--depot-accent);
  background: transparent;
  font-family: var(--mono);
  font-size: 9px;
  cursor: pointer;
}

.depot-path-actions .button {
  display: inline-flex;
  gap: 4px;
  align-items: center;
}

.depot-path-actions svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
}

.depot-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 52%, transparent);
}

.depot-search-box {
  display: flex;
  flex: 1 1 240px;
  min-width: 180px;
  gap: 6px;
  align-items: center;
  padding: 0 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.depot-search-box svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: var(--text-muted);
  stroke-width: 1.7;
}

.depot-search-box input {
  min-width: 0;
  padding: 7px 0 !important;
  border: 0 !important;
  outline: 0;
  background: transparent !important;
}

.depot-sort {
  display: inline-flex;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.depot-sort button {
  min-height: 28px;
  padding: 3px 7px;
  border: 0;
  border-right: 1px solid var(--border);
  color: var(--text-muted);
  background: transparent;
  font-size: 8px;
  cursor: pointer;
}

.depot-sort button:last-child {
  border-right: 0;
}

.depot-sort button.active {
  color: var(--depot-accent);
  background: color-mix(in srgb, var(--depot-accent) 9%, transparent);
}

.depot-count {
  margin-left: auto;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.depot-bulk-bar {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding: 7px 10px;
  border-bottom: 1px solid color-mix(in srgb, var(--depot-mint) 35%, var(--border));
  color: var(--depot-mint);
  background: color-mix(in srgb, var(--depot-mint) 8%, var(--depot-panel));
  font-family: var(--mono);
  font-size: 8px;
}

.depot-bulk-bar > button {
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-secondary);
  background: transparent;
  font-size: 8px;
  cursor: pointer;
}

.depot-bulk-bar > button.danger {
  margin-left: auto;
  border-color: color-mix(in srgb, var(--depot-coral) 48%, var(--border));
  color: var(--depot-coral);
}

.depot-file-list {
  min-width: 700px;
}

.depot-file-head,
.depot-file-row {
  display: grid;
  grid-template-columns: 31px minmax(200px, 1fr) 100px 152px 76px;
  gap: 8px;
  align-items: center;
}

.depot-file-head {
  min-height: 31px;
  padding: 5px 9px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  background: color-mix(in srgb, var(--field-bg) 78%, var(--depot-accent));
  font-family: var(--mono);
  font-size: 8px;
}

.depot-file-row {
  min-height: 43px;
  padding: 4px 9px;
  border-bottom: 1px solid var(--border);
  color: var(--text-secondary);
}

.depot-file-row:hover {
  background: color-mix(in srgb, var(--depot-accent) 4%, transparent);
}

.depot-file-row.selected {
  background: color-mix(in srgb, var(--depot-mint) 7%, transparent);
  box-shadow: inset 2px 0 0 var(--depot-mint);
}

.depot-check {
  display: grid;
  place-items: center;
}

.depot-check input {
  width: auto;
}

.depot-file-name {
  display: flex;
  min-width: 0;
  gap: 8px;
  align-items: center;
  padding: 0;
  border: 0;
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.artifact-icon {
  --artifact-color: var(--depot-accent);
  position: relative;
  display: grid;
  flex: 0 0 31px;
  width: 31px;
  height: 31px;
  border: 1px solid color-mix(in srgb, var(--artifact-color) 42%, var(--border));
  border-radius: 4px;
  color: var(--artifact-color);
  background: color-mix(in srgb, var(--artifact-color) 7%, var(--surface));
  place-items: center;
}

.artifact-icon.kind-folder {
  --artifact-color: var(--depot-amber);
}

.artifact-icon.kind-archive {
  --artifact-color: var(--depot-violet);
}

.artifact-icon.kind-code {
  --artifact-color: var(--depot-accent);
}

.artifact-icon.kind-image {
  --artifact-color: var(--depot-mint);
}

.artifact-icon.kind-text {
  --artifact-color: var(--text-muted);
}

.artifact-icon svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.artifact-icon b {
  position: absolute;
  right: 2px;
  bottom: 1px;
  padding: 0 2px;
  border-radius: 1px;
  color: var(--artifact-color);
  background: var(--surface);
  font-family: var(--mono);
  font-size: 5px;
  font-weight: 600;
}

.depot-name-copy {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.depot-name-copy strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-name-copy small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 7px;
}

.depot-meta {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.depot-row-actions {
  display: flex;
  gap: 3px;
  justify-content: flex-end;
}

.depot-icon-action {
  display: grid;
  width: 26px;
  height: 26px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
  place-items: center;
}

.depot-icon-action:hover {
  border-color: color-mix(in srgb, var(--depot-accent) 38%, var(--border));
  color: var(--depot-accent);
  background: color-mix(in srgb, var(--depot-accent) 7%, transparent);
}

.depot-icon-action.danger:hover {
  border-color: color-mix(in srgb, var(--depot-coral) 45%, var(--border));
  color: var(--depot-coral);
}

.depot-icon-action:disabled {
  opacity: 0.28;
  cursor: not-allowed;
}

.depot-icon-action svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.depot-loading,
.depot-empty-state {
  display: grid;
  min-height: 180px;
  gap: 10px;
  place-items: center;
  align-content: center;
  color: var(--text-muted);
  font-size: 10px;
}

.depot-loading {
  grid-template-columns: repeat(3, 28px);
}

.depot-loading i {
  width: 24px;
  height: 3px;
  background: var(--depot-accent);
  animation: depot-load 1.4s ease-in-out infinite;
}

.depot-loading i:nth-child(2) {
  animation-delay: 0.18s;
}

.depot-loading i:nth-child(3) {
  animation-delay: 0.36s;
}

.depot-loading span {
  grid-column: 1 / -1;
}

.depot-empty-state.compact {
  min-height: 100px;
}

.empty-depot-robot,
.empty-crate {
  position: relative;
  display: block;
  width: 42px;
  height: 35px;
  border: 1px solid var(--text-muted);
  border-radius: 7px;
  opacity: 0.55;
}

.empty-depot-robot::before {
  position: absolute;
  top: -8px;
  left: 19px;
  width: 1px;
  height: 7px;
  content: '';
  background: var(--text-muted);
}

.empty-depot-robot b {
  position: absolute;
  top: 12px;
  width: 5px;
  height: 1px;
  background: var(--text-muted);
}

.empty-depot-robot b:first-of-type {
  left: 10px;
}

.empty-depot-robot b:nth-of-type(2) {
  right: 10px;
}

.empty-depot-robot i {
  position: absolute;
  bottom: 7px;
  left: 13px;
  width: 14px;
  height: 1px;
  background: var(--text-muted);
}

.empty-depot-robot em {
  position: absolute;
  right: -6px;
  bottom: -2px;
  width: 18px;
  height: 16px;
  border: 1px solid var(--depot-amber);
  background: color-mix(in srgb, var(--depot-amber) 12%, transparent);
}

.empty-crate {
  width: 40px;
  height: 30px;
  border-color: var(--depot-amber);
}

.empty-crate::before,
.empty-crate::after {
  position: absolute;
  content: '';
  background: var(--depot-amber);
}

.empty-crate::before {
  top: 0;
  bottom: 0;
  left: 19px;
  width: 1px;
}

.empty-crate::after {
  top: 14px;
  right: 0;
  left: 0;
  height: 1px;
}

.depot-load-more {
  display: flex;
  margin: 10px auto;
}

.depot-dialog-layer {
  position: fixed;
  inset: 0;
  z-index: 95;
  display: grid;
  padding: 20px;
  background: rgba(5, 8, 9, 0.66);
  backdrop-filter: blur(4px);
  place-items: center;
}

.depot-dialog {
  width: min(430px, 100%);
  padding: 16px;
  border: 1px solid color-mix(in srgb, var(--depot-coral) 42%, var(--border));
  border-radius: 5px;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--depot-coral) 5%, transparent), transparent 90px),
    var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
  animation: depot-dialog-in 0.18s ease-out both;
}

.depot-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 12px;
}

.depot-dialog h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 16px;
}

.depot-warning-mark {
  position: relative;
  display: grid;
  width: 35px;
  height: 35px;
  border: 1px solid var(--depot-coral);
  border-radius: 50%;
  color: var(--depot-coral);
  place-items: center;
}

.depot-warning-mark b {
  font-family: var(--mono);
  font-size: 17px;
}

.depot-dialog > p {
  margin: 0 0 10px;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.55;
}

.depot-dialog-items {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  max-height: 110px;
  padding: 7px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.depot-dialog-items span,
.depot-dialog-items small {
  padding: 2px 5px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.depot-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  margin-top: 14px;
}

@keyframes depot-eye {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@keyframes depot-track-scan {
  from {
    left: 0;
  }
  to {
    left: 100%;
  }
}

@keyframes depot-load {
  0%,
  100% {
    opacity: 0.25;
    transform: scaleX(0.7);
  }
  50% {
    opacity: 1;
    transform: scaleX(1);
  }
}

@keyframes depot-dialog-in {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@media (max-width: 980px) {
  .depot-layout {
    grid-template-columns: 1fr;
  }

  .depot-zones {
    position: static;
  }

  .depot-zone-list {
    display: flex;
    overflow-x: auto;
  }

  .depot-zone {
    flex: 0 0 160px;
  }
}

@media (max-width: 760px) {
  .main-column .page-workspace.artifact-depot {
    overflow-x: hidden;
  }

  .depot-header {
    align-items: stretch;
  }

  .depot-heading {
    align-items: flex-start;
  }

  .depot-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .depot-layout,
  .depot-panel,
  .depot-zones {
    width: 100%;
    min-width: 0;
    max-width: 100%;
  }

  .depot-path-header,
  .depot-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .depot-path-actions,
  .depot-path-actions .button,
  .depot-search-box,
  .depot-sort {
    width: 100%;
    min-width: 0;
  }

  .depot-search-box {
    flex: 0 0 auto;
    min-height: 34px;
  }

  .depot-sort {
    flex: 0 0 auto;
  }

  .depot-sort {
    overflow-x: auto;
  }

  .depot-count {
    margin-left: 0;
  }

  .depot-file-list {
    min-width: 0;
  }

  .depot-file-head {
    display: none;
  }

  .depot-file-row {
    grid-template-columns: 28px minmax(0, 1fr) auto;
    gap: 6px;
    min-height: 58px;
    padding: 7px 9px;
  }

  .depot-file-row > .depot-meta {
    display: none;
  }

  .depot-name-copy small {
    display: block;
  }

  .depot-row-actions {
    grid-column: 3;
  }

  .depot-bulk-bar {
    align-items: flex-start;
  }

  .depot-bulk-bar > span {
    width: 100%;
  }

  .depot-bulk-bar > button.danger {
    margin-left: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .depot-robot-face b,
  .depot-track i,
  .depot-loading i,
  .depot-dialog {
    animation: none;
  }
}
</style>

<style scoped>
/* Workspace in the Vulnerability Management visual system */
.main-column .page-workspace.artifact-depot .depot-header {
  min-height: 78px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-workspace .depot-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-workspace .depot-header .button {
  min-height: 30px;
  padding: 5px 9px;
  border-radius: 3px;
  font-size: 10px;
}

.depot-status-rail {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  padding: 0;
  border: 0;
  background: transparent;
}

.depot-stat {
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

.depot-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: #55c7e8;
  font-size: 12px;
}

.depot-stat-icon {
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

.depot-stat strong {
  color: #55c7e8;
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.depot-stat::after,
.depot-track {
  display: none;
}

.depot-stat.tone-file {
  border-left-color: #9d8cff;
}

.depot-stat.tone-file small,
.depot-stat.tone-file strong {
  color: #9d8cff;
}

.depot-stat.tone-size {
  border-left-color: var(--warning);
}

.depot-stat.tone-size small,
.depot-stat.tone-size strong {
  color: var(--warning);
}

.depot-stat.tone-selected {
  border-left-color: var(--success);
}

.depot-stat.tone-selected small,
.depot-stat.tone-selected strong {
  color: var(--success);
}

.depot-layout {
  gap: 10px;
}

.depot-zones,
.depot-panel {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.depot-zones > header,
.depot-path-header,
.depot-toolbar {
  border-bottom: 1px solid var(--border);
  background: var(--surface-soft);
}

.depot-zone {
  border: 1px solid var(--border);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: var(--surface);
}

.depot-zone.active {
  border-left-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 6%, var(--surface));
}

.depot-toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 8px 10px;
}

.depot-search-box {
  height: 34px;
  border-radius: var(--radius);
  background: var(--field-bg);
}

.depot-search-box input {
  height: 32px;
  padding: 0;
  border: 0;
  background: transparent;
}

.depot-sort button {
  min-height: 30px;
  border-radius: 3px;
  background: var(--surface);
}

.depot-sort button.active {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-soft);
}

.depot-bulk-bar {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
}

.depot-file-list {
  border: 0;
  background: var(--surface);
}

.depot-file-head {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.depot-file-row {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
}

.depot-file-row:hover {
  background: color-mix(in srgb, var(--accent) 4%, transparent);
}

.depot-dialog-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.depot-dialog {
  width: min(430px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--danger) 42%, var(--border));
  border-radius: 4px;
  background: var(--surface);
}

@media (max-width: 760px) {
  .depot-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .depot-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .depot-search-box,
  .depot-sort {
    width: 100%;
  }

  .depot-sort button {
    flex: 1;
  }
}
</style>
