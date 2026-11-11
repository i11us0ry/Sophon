import { ref } from 'vue'

import enUS from './en-US'
import zhCN from './zh-CN'

export type Locale = 'zh-CN' | 'en-US'

const STORAGE_KEY = 'sophon.locale'
const dictionaries: Record<Locale, Record<string, string>> = {
  'zh-CN': zhCN,
  'en-US': enUS,
}

function detectLocale(): Locale {
  if (typeof window === 'undefined') {
    return 'zh-CN'
  }
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (stored === 'zh-CN' || stored === 'en-US') {
    return stored
  }
  const browser = (navigator.language || '').toLowerCase()
  return browser.startsWith('en') ? 'en-US' : 'zh-CN'
}

export const locale = ref<Locale>(detectLocale())

function applyDocumentLocale() {
  if (typeof document === 'undefined') {
    return
  }
  document.documentElement.lang = locale.value
  document.title = translate('app.browserTitle')
}

export function translate(key: string, params?: Record<string, string | number>): string {
  const dictionary = dictionaries[locale.value] ?? dictionaries['zh-CN']
  let value = dictionary[key] ?? dictionaries['zh-CN'][key] ?? key
  if (params) {
    Object.entries(params).forEach(([name, replacement]) => {
      value = value.split(`{${name}}`).join(String(replacement))
    })
  }
  return value
}

export function setLocale(next: Locale) {
  locale.value = next
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, next)
  }
  applyDocumentLocale()
}

export function initI18n() {
  applyDocumentLocale()
}

export function useI18n() {
  return {
    locale,
    setLocale,
    t: translate,
  }
}
