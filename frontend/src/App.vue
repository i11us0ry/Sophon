<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { RouterLink, RouterView } from 'vue-router'

import { useAuthStore } from './stores/auth'
import { useI18n } from './i18n'
import { useTheme } from './theme'
import brandIcon from '../img/icon.png'

const { t, locale, setLocale } = useI18n()
const { theme, toggleTheme } = useTheme()

function onLocaleChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  setLocale(value === 'en-US' ? 'en-US' : 'zh-CN')
}

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const userInitial = computed(() => (auth.user?.username || '?').slice(0, 1).toUpperCase())
const themeLabel = computed(() =>
  theme.value === 'dark' ? t('theme.switchToLight') : t('theme.switchToDark'),
)

async function logout() {
  await auth.logout()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <div
    v-if="auth.isAuthenticated"
    class="app-shell"
    :class="{ 'chat-shell': route.name === 'chat' }"
  >
    <header class="top-bar">
      <div class="top-bar-left">
        <RouterLink class="top-bar-brand" to="/dashboard">
          <img class="top-bar-brand-icon" :src="brandIcon" alt="Sophon" />
          <span class="top-bar-brand-copy">
            <strong>{{ t('app.title') }}</strong>
            <small>SECURITY OPERATIONS</small>
          </span>
        </RouterLink>
      </div>
      <div class="top-bar-controls">
        <button
          class="icon-button"
          type="button"
          :title="themeLabel"
          :aria-label="themeLabel"
          @click="toggleTheme"
        >
          <svg v-if="theme === 'dark'" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41" />
            <path d="M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
          </svg>
          <svg v-else viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
          </svg>
        </button>
        <select
          class="language-select"
          :value="locale"
          :aria-label="t('lang.label')"
          @change="onLocaleChange"
        >
          <option value="zh-CN">{{ t('lang.zh') }}</option>
          <option value="en-US">{{ t('lang.en') }}</option>
        </select>
        <div class="top-bar-user">
          <span class="user-badge">{{ userInitial }}</span>
          <span>
            <small>{{ t('nav.currentUser') }}</small>
            <strong>{{ auth.user?.username }}</strong>
          </span>
        </div>
        <button class="text-button" type="button" @click="logout">{{ t('nav.logout') }}</button>
      </div>
    </header>

    <aside class="sidebar">
      <nav class="nav">
        <RouterLink v-if="auth.hasPermission('dashboard:read')" class="nav-dashboard" to="/dashboard">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="3" width="7" height="9" rx="1" />
            <rect x="14" y="3" width="7" height="5" rx="1" />
            <rect x="14" y="12" width="7" height="9" rx="1" />
            <rect x="3" y="16" width="7" height="5" rx="1" />
          </svg>
          <span>{{ t('nav.dashboard') }}</span>
        </RouterLink>
        <RouterLink class="nav-chat" to="/chat">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
          <span>{{ t('nav.chat') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('project:read')" class="nav-projects" to="/projects">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" />
            <path d="M8 10v4" />
            <path d="M12 10v2" />
            <path d="M16 10v6" />
          </svg>
          <span>{{ t('nav.projects') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('vulnerability:read')" class="nav-vulnerabilities" to="/vulnerabilities">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
            <path d="M12 8v4" />
            <path d="M12 16h.01" />
          </svg>
          <span>{{ t('nav.vulnerabilities') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('asset:read')" class="nav-assets" to="/asset-management">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="18" height="6" rx="2" />
            <rect x="3" y="14" width="18" height="6" rx="2" />
            <path d="M7 7h.01M7 17h.01" />
          </svg>
          <span>{{ t('nav.assets') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('agentRole:read')" class="nav-roles" to="/roles">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
          <span>{{ t('nav.roles') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('skills:read')" class="nav-skills" to="/skills">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
            <path d="M20 3v4" />
            <path d="M22 5h-4" />
            <path d="M4 17v2" />
            <path d="M5 18H3" />
          </svg>
          <span>{{ t('nav.skills') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('mcp:read')" class="nav-mcp" to="/mcp-servers">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
            <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
            <line x1="6" x2="6.01" y1="6" y2="6" />
            <line x1="6" x2="6.01" y1="18" y2="18" />
          </svg>
          <span>{{ t('nav.mcp') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('zhizi:read')" class="nav-zhizi" to="/zhizi">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="7" height="7" rx="1" />
            <rect x="14" y="4" width="7" height="7" rx="1" />
            <rect x="3" y="13" width="7" height="7" rx="1" />
            <rect x="14" y="13" width="7" height="7" rx="1" />
          </svg>
          <span>{{ t('nav.zhizi') }}</span>
        </RouterLink>
        <RouterLink class="nav-governance" to="/governance">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />
          </svg>
          <span>{{ t('nav.governance') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('settings:read')" class="nav-workspace" to="/workspace">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
          </svg>
          <span>{{ t('nav.workspace') }}</span>
        </RouterLink>
        <RouterLink v-if="auth.hasPermission('rbac:read')" class="nav-rbac" to="/rbac">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <span>{{ t('nav.rbac') }}</span>
        </RouterLink>
        <RouterLink class="nav-settings" to="/settings">
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
          <span>{{ t('nav.settings') }}</span>
        </RouterLink>
      </nav>
    </aside>

    <div class="main-column">
      <main class="main-content">
        <RouterView />
      </main>
    </div>
  </div>

  <RouterView v-else />
</template>
