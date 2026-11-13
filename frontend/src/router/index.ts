import { createRouter, createWebHistory } from 'vue-router'

import AssetView from '../views/AssetView.vue'
import BusinessView from '../views/BusinessView.vue'
import ChatView from '../views/ChatView.vue'
import DashboardView from '../views/DashboardView.vue'
import GovernanceView from '../views/GovernanceView.vue'
import HomeView from '../views/HomeView.vue'
import LoginView from '../views/LoginView.vue'
import McpView from '../views/McpView.vue'
import ProjectDetailView from '../views/ProjectDetailView.vue'
import ProjectListView from '../views/ProjectListView.vue'
import RbacView from '../views/RbacView.vue'
import RoleView from '../views/RoleView.vue'
import SettingsView from '../views/SettingsView.vue'
import SkillView from '../views/SkillView.vue'
import VulnerabilityView from '../views/VulnerabilityView.vue'
import WorkspaceView from '../views/WorkspaceView.vue'
import ZhiziView from '../views/ZhiziView.vue'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/dashboard',
      name: 'dashboard',
      component: DashboardView,
      meta: { requiresAuth: true, permission: 'dashboard:read' },
    },
    {
      path: '/chat',
      name: 'chat',
      component: ChatView,
      meta: { requiresAuth: true },
    },
    {
      path: '/',
      name: 'home',
      component: HomeView,
      meta: { requiresAuth: true },
    },
    {
      path: '/business',
      name: 'business',
      component: BusinessView,
      meta: { requiresAuth: true },
    },
    {
      path: '/projects',
      name: 'projects',
      component: ProjectListView,
      meta: { requiresAuth: true, permission: 'project:read' },
    },
    {
      path: '/projects/:id',
      name: 'project-detail',
      component: ProjectDetailView,
      meta: { requiresAuth: true, permission: 'project:read' },
    },
    {
      path: '/vulnerabilities',
      name: 'vulnerabilities',
      component: VulnerabilityView,
      meta: { requiresAuth: true, permission: 'vulnerability:read' },
    },
    {
      path: '/asset-management',
      name: 'asset-management',
      component: AssetView,
      meta: { requiresAuth: true, permission: 'asset:read' },
    },
    {
      path: '/roles',
      name: 'roles',
      component: RoleView,
      meta: { requiresAuth: true, permission: 'agentRole:read' },
    },
    {
      path: '/skills',
      name: 'skills',
      component: SkillView,
      meta: { requiresAuth: true, permission: 'skills:read' },
    },
    {
      path: '/mcp-servers',
      name: 'mcp',
      component: McpView,
      meta: { requiresAuth: true, permission: 'mcp:read' },
    },
    {
      path: '/zhizi',
      name: 'zhizi',
      component: ZhiziView,
      meta: { requiresAuth: true, permission: 'zhizi:read' },
    },
    {
      path: '/governance',
      name: 'governance',
      component: GovernanceView,
      meta: { requiresAuth: true },
    },
    {
      path: '/workspace',
      name: 'workspace',
      component: WorkspaceView,
      meta: { requiresAuth: true, permission: 'settings:read' },
    },
    {
      path: '/settings',
      name: 'settings',
      component: SettingsView,
      meta: { requiresAuth: true },
    },
    {
      path: '/rbac',
      name: 'rbac',
      component: RbacView,
      meta: { requiresAuth: true, permission: 'rbac:read' },
    },
    {
      path: '/login',
      name: 'login',
      component: LoginView,
    },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  await auth.initialize()

  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return {
      name: 'login',
      query: {
        redirect: to.fullPath,
      },
    }
  }
  if (to.name === 'login' && auth.isAuthenticated) {
    return { name: 'chat' }
  }
  const permission = to.meta.permission as string | undefined
  if (permission && !auth.hasPermission(permission)) {
    return { name: 'home' }
  }
  return true
})

export default router
