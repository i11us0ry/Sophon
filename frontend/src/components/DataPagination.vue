<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { useI18n } from '../i18n'

const props = withDefaults(
  defineProps<{
    total: number
    page: number
    pageSize: number
    totalPages: number
    disabled?: boolean
  }>(),
  {
    disabled: false,
  },
)

const emit = defineEmits<{
  pageChange: [page: number]
  pageSizeChange: [pageSize: number]
}>()

const { t } = useI18n()
const PAGE_SIZES = [10, 20, 50, 100]
const pageInput = ref(String(props.page))
const safeTotalPages = computed(() => Math.max(1, props.totalPages || 1))

watch(
  () => props.page,
  (value) => {
    pageInput.value = String(value)
  },
)

function changePage(next: number) {
  const page = Math.min(safeTotalPages.value, Math.max(1, next))
  if (page === props.page || props.disabled) {
    return
  }
  emit('pageChange', page)
}

function changePageSize(event: Event) {
  const value = Number((event.target as HTMLSelectElement).value)
  if (!PAGE_SIZES.includes(value) || value === props.pageSize || props.disabled) {
    return
  }
  emit('pageSizeChange', value)
}

function jumpToPage() {
  const parsed = Number.parseInt(pageInput.value, 10)
  if (!Number.isFinite(parsed)) {
    pageInput.value = String(props.page)
    return
  }
  changePage(parsed)
  pageInput.value = String(Math.min(safeTotalPages.value, Math.max(1, parsed)))
}
</script>

<template>
  <footer class="data-pagination">
    <span class="data-pagination-summary">
      {{
        t('pagination.summary', {
          total,
          page,
          totalPages: safeTotalPages,
        })
      }}
    </span>
    <div class="data-pagination-controls">
      <label class="data-pagination-size">
        <span>{{ t('pagination.pageSize') }}</span>
        <select
          :value="pageSize"
          :disabled="disabled"
          :aria-label="t('pagination.pageSize')"
          @change="changePageSize"
        >
          <option v-for="size in PAGE_SIZES" :key="size" :value="size">{{ size }}</option>
        </select>
      </label>
      <div class="data-pagination-actions">
        <button
          type="button"
          :disabled="disabled || page <= 1"
          :title="t('pagination.prev')"
          :aria-label="t('pagination.prev')"
          @click="changePage(page - 1)"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6" /></svg>
        </button>
        <label class="data-pagination-jump">
          <span>{{ t('pagination.pageLabel') }}</span>
          <input
            v-model="pageInput"
            type="number"
            min="1"
            :max="safeTotalPages"
            :disabled="disabled"
            :aria-label="t('pagination.jumpHint')"
            @keydown.enter.prevent="jumpToPage"
          />
          <span>/ {{ safeTotalPages }}</span>
        </label>
        <button
          class="data-pagination-go"
          type="button"
          :disabled="disabled"
          @click="jumpToPage"
        >
          {{ t('pagination.jump') }}
        </button>
        <button
          type="button"
          :disabled="disabled || page >= safeTotalPages"
          :title="t('pagination.next')"
          :aria-label="t('pagination.next')"
          @click="changePage(page + 1)"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 18 6-6-6-6" /></svg>
        </button>
      </div>
    </div>
  </footer>
</template>

<style scoped>
.data-pagination {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 16px;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
  color: var(--text-muted);
  font-size: 12px;
}

.data-pagination-summary {
  font-family: var(--mono);
  white-space: nowrap;
}

.data-pagination-controls,
.data-pagination-actions,
.data-pagination-size,
.data-pagination-jump {
  display: flex;
  align-items: center;
}

.data-pagination-controls {
  flex-wrap: wrap;
  gap: 8px;
}

.data-pagination-actions {
  gap: 6px;
}

.data-pagination-size,
.data-pagination-jump {
  gap: 5px;
  white-space: nowrap;
}

.data-pagination select,
.data-pagination input,
.data-pagination button {
  min-height: 30px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  color: var(--text-secondary);
  font: inherit;
}

.data-pagination select {
  padding: 3px 6px;
}

.data-pagination input {
  width: 56px;
  padding: 3px 5px;
  text-align: center;
}

.data-pagination button {
  display: inline-grid;
  width: 30px;
  padding: 0;
  cursor: pointer;
  place-items: center;
}

.data-pagination button:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent);
}

.data-pagination button:disabled {
  cursor: not-allowed;
  opacity: 0.4;
}

.data-pagination button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2;
}

.data-pagination .data-pagination-go {
  width: auto;
  padding: 0 9px;
}

@media (max-width: 720px) {
  .data-pagination,
  .data-pagination-controls {
    align-items: flex-start;
    justify-content: flex-start;
  }
}
</style>
