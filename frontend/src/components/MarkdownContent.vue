<script setup lang="ts">
import { computed } from 'vue'
import DOMPurify from 'dompurify'
import { markdownRenderer } from '../utils/markdown'

const props = defineProps<{
  content: string
  imagePolicy?: 'any' | 'reproduction'
}>()

const reproductionImagePattern =
  /^\/api\/vulnerabilities\/[A-Za-z0-9_-]+\/reproduction-images\/[A-Za-z0-9_-]+$/

function sanitizeMarkdown(content: string) {
  const sanitized = DOMPurify.sanitize(markdownRenderer.render(content), {
    USE_PROFILES: { html: true },
    FORBID_TAGS: [
      'style',
      'iframe',
      'form',
      'input',
      'button',
      'textarea',
      'select',
      'option',
      'object',
      'embed',
      'svg',
      'math',
    ],
    FORBID_ATTR: ['style'],
  })
  if (props.imagePolicy !== 'reproduction' || typeof document === 'undefined') {
    return sanitized
  }
  const template = document.createElement('template')
  template.innerHTML = sanitized
  template.content.querySelectorAll('img').forEach((image) => {
    const src = image.getAttribute('src') || ''
    if (
      reproductionImagePattern.test(src) ||
      /^data:image\/(?:png|jpeg|webp);base64,/i.test(src)
    ) {
      return
    }
    const replacement = document.createElement('span')
    replacement.textContent = '[图片不可用]'
    image.replaceWith(replacement)
  })
  return template.innerHTML
}

const rendered = computed(() => sanitizeMarkdown(props.content || ''))
</script>

<template>
  <div class="markdown-body" v-html="rendered"></div>
</template>

<style scoped>
.markdown-body {
  min-width: 0;
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.72;
  overflow-wrap: anywhere;
}

.markdown-body :deep(:first-child) {
  margin-top: 0;
}

.markdown-body :deep(:last-child) {
  margin-bottom: 0;
}

.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4) {
  margin: 1.25em 0 0.55em;
  color: var(--text-primary);
  font-weight: 650;
  line-height: 1.3;
}

.markdown-body :deep(h1) {
  padding-bottom: 0.35em;
  border-bottom: 1px solid var(--border);
  font-size: 21px;
}

.markdown-body :deep(h2) {
  font-size: 18px;
}

.markdown-body :deep(h3) {
  font-size: 16px;
}

.markdown-body :deep(h4) {
  font-size: 14px;
}

.markdown-body :deep(p) {
  margin: 0.65em 0;
}

.markdown-body :deep(strong) {
  color: var(--text-primary);
  font-weight: 650;
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  margin: 0.65em 0;
  padding-left: 1.65em;
}

.markdown-body :deep(li + li) {
  margin-top: 0.25em;
}

.markdown-body :deep(blockquote) {
  margin: 0.8em 0;
  padding: 0.2em 0 0.2em 0.9em;
  border-left: 3px solid var(--accent-line);
  color: var(--text-secondary);
}

.markdown-body :deep(code) {
  padding: 0.12em 0.35em;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 0.9em;
}

.markdown-body :deep(pre) {
  max-width: 100%;
  margin: 0.8em 0;
  padding: 10px 12px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--field-bg);
  line-height: 1.55;
}

.markdown-body :deep(pre code) {
  padding: 0;
  border: 0;
  background: transparent;
  font-size: 12px;
  white-space: pre;
}

.markdown-body :deep(table) {
  display: block;
  width: max-content;
  max-width: 100%;
  margin: 0.85em 0;
  overflow-x: auto;
  border-collapse: collapse;
  font-size: 13px;
}

.markdown-body :deep(th),
.markdown-body :deep(td) {
  min-width: 90px;
  padding: 7px 9px;
  border: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}

.markdown-body :deep(th) {
  background: var(--surface-soft);
  color: var(--text-primary);
  font-weight: 650;
}

.markdown-body :deep(a) {
  color: var(--accent);
  text-decoration: underline;
  text-underline-offset: 2px;
}

.markdown-body :deep(img) {
  display: block;
  max-width: 100%;
  max-height: 560px;
  margin: 10px auto;
  border: 1px solid var(--border);
  border-radius: 4px;
  object-fit: contain;
}

.markdown-body :deep(hr) {
  margin: 1.1em 0;
  border: 0;
  border-top: 1px solid var(--border);
}
</style>
