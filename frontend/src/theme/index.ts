import { ref } from 'vue'

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'sophon.theme'
const THEME_COLORS: Record<Theme, string> = {
  dark: '#1d1d1d',
  light: '#f5f5f5',
}

function detectTheme(): Theme {
  if (typeof window === 'undefined') {
    return 'dark'
  }
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (stored === 'dark' || stored === 'light') {
    return stored
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export const theme = ref<Theme>(detectTheme())

function applyTheme() {
  if (typeof document === 'undefined') {
    return
  }
  document.documentElement.dataset.theme = theme.value
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) {
    meta.setAttribute('content', THEME_COLORS[theme.value])
  }
}

export function setTheme(next: Theme) {
  theme.value = next
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, next)
  }
  applyTheme()
}

export function toggleTheme() {
  setTheme(theme.value === 'dark' ? 'light' : 'dark')
}

export function initTheme() {
  applyTheme()
}

export function useTheme() {
  return {
    theme,
    setTheme,
    toggleTheme,
  }
}
