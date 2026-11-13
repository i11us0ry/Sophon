<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'

import PageTitleRobot from '../components/PageTitleRobot.vue'
import { useAuthStore } from '../stores/auth'
import { useRbacStore, type Role, type RoleUser } from '../stores/rbac'
import { useI18n } from '../i18n'

const { t } = useI18n()

const auth = useAuthStore()
const rbac = useRbacStore()

const message = ref('')
const messageKind = ref<'ok' | 'error'>('ok')
const editingRole = ref('')
const activeTab = ref<'users' | 'roles'>('users')
const userDrawerOpen = ref(false)
const roleDrawerOpen = ref(false)
const userSearch = ref('')
const userStatusFilter = ref<'' | 'enabled' | 'disabled'>('')
const roleSearch = ref('')
const permissionSearch = ref('')
const deleteTarget = ref<{ type: 'user'; user: RoleUser } | { type: 'role'; role: Role } | null>(
  null,
)
const deleting = ref(false)

const userDraft = reactive({
  username: '',
  displayName: '',
  password: '',
  role: 'viewer',
})

const roleDraft = reactive({
  description: '',
  permissions: [] as string[],
})

const canWrite = computed(() => auth.hasPermission('rbac:write'))
const activeUsers = computed(() => rbac.users.filter((user) => user.enabled).length)
const filteredUsers = computed(() => {
  const keyword = userSearch.value.trim().toLowerCase()
  return rbac.users.filter((user) => {
    if (userStatusFilter.value === 'enabled' && !user.enabled) {
      return false
    }
    if (userStatusFilter.value === 'disabled' && user.enabled) {
      return false
    }
    if (!keyword) {
      return true
    }
    return `${user.username} ${user.displayName} ${user.role}`
      .toLowerCase()
      .includes(keyword)
  })
})
const filteredRoles = computed(() => {
  const keyword = roleSearch.value.trim().toLowerCase()
  if (!keyword) {
    return rbac.roles
  }
  return rbac.roles.filter((role) =>
    `${role.name} ${roleDescription(role)}`.toLowerCase().includes(keyword),
  )
})
const permissionGroups = computed(() => {
  const groups = new Map<string, string[]>()
  const keyword = permissionSearch.value.trim().toLowerCase()
  for (const permission of rbac.permissionList) {
    if (keyword && !permission.toLowerCase().includes(keyword)) {
      continue
    }
    const group = permission.includes(':') ? permission.split(':')[0] : 'general'
    const items = groups.get(group) ?? []
    items.push(permission)
    groups.set(group, items)
  }
  return Array.from(groups, ([key, permissions]) => ({
    key,
    label: permissionGroupLabel(key),
    permissions,
  }))
})

function setMessage(text: string, kind: 'ok' | 'error' = 'ok') {
  message.value = text
  messageKind.value = kind
}

async function run(action: () => Promise<void>, successText: string) {
  setMessage('')
  try {
    await action()
    setMessage(successText)
  } catch (error) {
    setMessage(error instanceof Error ? error.message : t('message.operationFailed'), 'error')
  }
}

function createUser() {
  if (!userDraft.username.trim()) {
    setMessage('用户名不能为空', 'error')
    return
  }
  if (userDraft.password.length < 8) {
    setMessage('密码至少 8 位', 'error')
    return
  }
  void run(async () => {
    await rbac.createUser({
      username: userDraft.username.trim(),
      displayName: userDraft.displayName.trim(),
      password: userDraft.password,
      role: userDraft.role,
      enabled: true,
    })
    userDraft.username = ''
    userDraft.displayName = ''
    userDraft.password = ''
    userDrawerOpen.value = false
  }, t('rbac.userCreated'))
}

function updateUser(user: RoleUser, changes: Partial<RoleUser>) {
  void run(
    () =>
      rbac.updateUser(user.id, {
        username: user.username,
        displayName: changes.displayName ?? user.displayName,
        password: '',
        role: changes.role ?? user.role,
        enabled: changes.enabled ?? user.enabled,
      }),
    t('rbac.userUpdated'),
  )
}

function roleDescription(role: Role) {
  const key = `rbac.roleDesc.${role.name}`
  const translated = t(key)
  return translated === key ? role.description || '-' : translated
}

function permissionGroupLabel(group: string) {
  const key = `rbac.permissionGroup.${group}`
  const translated = t(key)
  return translated === key ? group : translated
}

function userInitial(user: RoleUser) {
  return (user.displayName || user.username || '?').slice(0, 1).toUpperCase()
}

function roleTone(roleName: string) {
  if (roleName === 'admin') {
    return 'admin'
  }
  if (roleName === 'operator') {
    return 'operator'
  }
  return 'viewer'
}

function openCreateUser() {
  activeTab.value = 'users'
  userDrawerOpen.value = true
  setMessage('')
}

function closeUserDrawer() {
  userDrawerOpen.value = false
}

function startCreateRole() {
  editingRole.value = ''
  roleDraft.description = ''
  roleDraft.permissions = []
  roleDrawerOpen.value = false
  permissionSearch.value = ''
  setMessage('')
}

function startEditRole(role: Role) {
  activeTab.value = 'roles'
  editingRole.value = role.name
  roleDraft.description = role.description
  roleDraft.permissions = [...role.permissions]
  roleDrawerOpen.value = true
  permissionSearch.value = ''
  setMessage('')
}

function togglePermission(permission: string) {
  if (roleDraft.permissions.includes(permission)) {
    roleDraft.permissions = roleDraft.permissions.filter((item) => item !== permission)
    return
  }
  roleDraft.permissions = [...roleDraft.permissions, permission]
}

function permissionGroupSelected(group: string[]) {
  return group.every((permission) => roleDraft.permissions.includes(permission))
}

function togglePermissionGroup(group: string[]) {
  if (permissionGroupSelected(group)) {
    roleDraft.permissions = roleDraft.permissions.filter(
      (permission) => !group.includes(permission),
    )
    return
  }
  roleDraft.permissions = Array.from(new Set([...roleDraft.permissions, ...group]))
}

function saveRole() {
  const permissions = roleDraft.permissions.filter((item) => item !== '*')
  void run(async () => {
    await rbac.updateRole(editingRole.value, {
      name: editingRole.value,
      description: roleDraft.description,
      permissions,
    })
    startCreateRole()
  }, `角色 ${editingRole.value} 已保存`)
}

function requestDeleteUser(user: RoleUser) {
  if (canWrite.value && user.id !== auth.user?.id) {
    deleteTarget.value = { type: 'user', user }
  }
}

function requestDeleteRole(role: Role) {
  if (canWrite.value && !role.builtin && !role.permissions.includes('*')) {
    deleteTarget.value = { type: 'role', role }
  }
}

function closeDeleteDialog() {
  if (!deleting.value) {
    deleteTarget.value = null
  }
}

async function confirmDelete() {
  const target = deleteTarget.value
  if (!target || deleting.value) {
    return
  }
  deleting.value = true
  setMessage('')
  try {
    if (target.type === 'user') {
      await rbac.deleteUser(target.user.id)
      setMessage(t('rbac.userDeleted'))
    } else {
      await rbac.deleteRole(target.role.name)
      setMessage(t('rbac.roleDeleted'))
    }
    deleteTarget.value = null
  } catch (error) {
    setMessage(error instanceof Error ? error.message : t('message.operationFailed'), 'error')
    deleteTarget.value = null
  } finally {
    deleting.value = false
  }
}

onMounted(() => {
  void rbac.load()
})
</script>

<template>
  <section class="page factory-page page-rbac access-control">
    <header class="page-header access-header">
      <div class="access-heading page-heading-with-robot">
        <PageTitleRobot tone="magenta" />
        <div>
          <p class="eyebrow">ACCESS GATE // IDENTITY CONTROL</p>
          <h1>{{ t('rbac.title') }}</h1>
          <p class="access-page-hint">{{ t('rbac.accessHint') }}</p>
        </div>
      </div>
      <button class="button" type="button" :disabled="rbac.loading" @click="rbac.load">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
        {{ t('common.refresh') }}
      </button>
    </header>

    <div v-if="message" class="alert access-alert" :class="messageKind">{{ message }}</div>
    <div v-if="rbac.error" class="alert error access-alert">{{ rbac.error }}</div>

    <section class="access-status-rail">
      <article class="access-stat tone-users">
        <small>
          <svg class="access-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="9" cy="8" r="3" />
            <path d="M3 20v-2a6 6 0 0 1 12 0v2" />
            <path d="M16 5.5a3 3 0 0 1 0 5.5M18 14a4 4 0 0 1 3 4v2" />
          </svg>
          {{ t('rbac.users') }}
        </small>
        <strong>{{ rbac.users.length }}</strong>
      </article>
      <article class="access-stat tone-active">
        <small>
          <svg class="access-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 3a9 9 0 1 0 9 9" />
            <path d="m8 12 3 3 8-9" />
          </svg>
          {{ t('common.enabled') }}
        </small>
        <strong>{{ activeUsers }}</strong>
      </article>
      <article class="access-stat tone-roles">
        <small>
          <svg class="access-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d="m12 3 7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z" />
            <circle cx="12" cy="10" r="2" />
            <path d="M8 17a4 4 0 0 1 8 0" />
          </svg>
          {{ t('rbac.roles') }}
        </small>
        <strong>{{ rbac.roles.length }}</strong>
      </article>
      <article class="access-stat tone-permissions">
        <small>
          <svg class="access-stat-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="8" cy="12" r="4" />
            <path d="M12 12h9M17 12v3M20 12v2" />
          </svg>
          {{ t('rbac.permissionCount') }}
        </small>
        <strong>{{ rbac.permissionList.length }}</strong>
      </article>
      <div class="access-scan" aria-hidden="true"><i></i></div>
    </section>

    <nav class="access-tabs">
      <button type="button" :class="{ active: activeTab === 'users' }" @click="activeTab = 'users'">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" /></svg>
        <span><strong>{{ t('rbac.users') }}</strong><small>{{ t('rbac.userGateHint') }}</small></span>
        <b>{{ rbac.users.length }}</b>
      </button>
      <button type="button" :class="{ active: activeTab === 'roles' }" @click="activeTab = 'roles'">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4 7v5c0 5 3.4 8 8 9 4.6-1 8-4 8-9V7Z" /><path d="M9 12h6M12 9v6" /></svg>
        <span><strong>{{ t('rbac.roles') }}</strong><small>{{ t('rbac.roleMatrixHint') }}</small></span>
        <b>{{ rbac.roles.length }}</b>
      </button>
    </nav>

    <section v-if="activeTab === 'users'" class="access-panel">
      <header class="access-panel-head">
        <div><span class="access-code">01 // USER GATE</span><h2>{{ t('rbac.users') }}</h2></div>
        <button v-if="canWrite" class="button access-primary" type="button" @click="openCreateUser">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          {{ t('rbac.createUser') }}
        </button>
      </header>
      <div class="access-toolbar">
        <label class="access-search"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg><input v-model="userSearch" type="search" :placeholder="t('rbac.searchUsers')" /></label>
        <div class="access-segmented">
          <button type="button" :class="{ active: userStatusFilter === '' }" @click="userStatusFilter = ''">{{ t('rbac.all') }}</button>
          <button type="button" :class="{ active: userStatusFilter === 'enabled' }" @click="userStatusFilter = 'enabled'">{{ t('common.enabled') }}</button>
          <button type="button" :class="{ active: userStatusFilter === 'disabled' }" @click="userStatusFilter = 'disabled'">{{ t('common.disabled') }}</button>
        </div>
      </div>
      <div class="access-user-list">
        <article v-for="user in filteredUsers" :key="user.id" class="access-user-row" :class="{ 'is-current': user.id === auth.user?.id, disabled: !user.enabled }">
          <span class="access-avatar" :class="`tone-${roleTone(user.role)}`">{{ userInitial(user) }}</span>
          <span class="access-user-id"><strong>{{ user.displayName || user.username }}</strong><small>@{{ user.username }}</small></span>
          <span class="access-role-badge" :class="`tone-${roleTone(user.role)}`">{{ user.role }}</span>
          <span class="access-user-state"><i></i>{{ user.enabled ? t('common.enabled') : t('common.disabled') }}</span>
          <label v-if="canWrite" class="access-role-select">
            <span>{{ t('rbac.role') }}</span>
            <select :value="user.role" :disabled="user.id === auth.user?.id" @change="updateUser(user, { role: ($event.target as HTMLSelectElement).value })">
              <option v-for="role in rbac.roles" :key="role.name" :value="role.name">{{ role.name }}</option>
            </select>
          </label>
          <span v-if="user.id === auth.user?.id" class="access-self-badge">{{ t('rbac.currentAccount') }}</span>
          <div v-if="canWrite" class="access-row-actions">
            <button type="button" :disabled="user.id === auth.user?.id" :title="user.enabled ? t('common.disable') : t('common.enable')" @click="updateUser(user, { enabled: !user.enabled })">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v9M6.3 5.8a8 8 0 1 0 11.4 0" /></svg>
            </button>
            <button class="danger" type="button" :disabled="user.id === auth.user?.id" :title="t('common.delete')" @click="requestDeleteUser(user)">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5" /></svg>
            </button>
          </div>
        </article>
        <div v-if="!filteredUsers.length" class="access-empty"><span class="empty-gate" aria-hidden="true"></span><strong>{{ t('rbac.noMatchingUsers') }}</strong></div>
      </div>
    </section>

    <section v-else class="access-panel">
      <header class="access-panel-head">
        <div><span class="access-code">02 // ROLE MATRIX</span><h2>{{ t('rbac.roles') }}</h2></div>
        <span class="access-panel-count">{{ rbac.roles.length }}</span>
      </header>
      <div class="access-toolbar">
        <label class="access-search"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg><input v-model="roleSearch" type="search" :placeholder="t('rbac.searchRoles')" /></label>
      </div>
      <div class="access-role-list">
        <article v-for="role in filteredRoles" :key="role.name" class="access-role-row" :class="`tone-${roleTone(role.name)}`">
          <span class="role-shield" aria-hidden="true"><i></i><b></b></span>
          <span class="access-role-id"><strong>{{ role.name }}</strong><small>{{ roleDescription(role) }}</small></span>
          <span class="access-permission-count"><strong>{{ role.permissions.includes('*') ? 'ALL' : role.permissions.length }}</strong><small>{{ t('rbac.permissionCount') }}</small></span>
          <span v-if="role.builtin || role.permissions.includes('*')" class="access-lock-badge">系统角色</span>
          <div class="access-row-actions">
            <button type="button" :disabled="!canWrite || role.permissions.includes('*')" :title="t('common.edit')" @click="startEditRole(role)">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 20 4.5-1 10-10-3.5-3.5-10 10zM13.5 7l3.5 3.5" /></svg>
            </button>
            <button class="danger" type="button" :disabled="!canWrite || role.builtin || role.permissions.includes('*')" :title="t('common.delete')" @click="requestDeleteRole(role)">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5" /></svg>
            </button>
          </div>
        </article>
        <div v-if="!filteredRoles.length" class="access-empty"><strong>{{ t('rbac.noMatchingRoles') }}</strong></div>
      </div>
    </section>

    <Teleport to="body">
      <div v-if="userDrawerOpen" class="access-drawer-layer" @click.self="closeUserDrawer">
        <aside class="access-drawer" role="dialog" aria-modal="true">
          <header class="access-drawer-head"><div><span class="access-code">USER ONBOARDING</span><h2>{{ t('rbac.createUser') }}</h2></div><button type="button" @click="closeUserDrawer"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></svg></button></header>
          <form class="access-user-form" @submit.prevent="createUser">
            <section><span>01</span><label><b>{{ t('login.username') }}</b><input v-model="userDraft.username" :placeholder="t('rbac.usernamePlaceholder')" /></label></section>
            <section><span>02</span><label><b>{{ t('rbac.displayName') }}</b><input v-model="userDraft.displayName" :placeholder="t('rbac.displayNamePlaceholder')" /></label></section>
            <section><span>03</span><label><b>{{ t('settings.newPassword') }}</b><input v-model="userDraft.password" type="password" :placeholder="t('rbac.passwordPlaceholder')" /></label></section>
            <section><span>04</span><label><b>{{ t('rbac.role') }}</b><select v-model="userDraft.role"><option v-for="role in rbac.roles" :key="role.name" :value="role.name">{{ role.name }}</option></select></label></section>
            <p class="field-hint">{{ t('rbac.passwordHint') }}</p>
            <footer><button class="button compact" type="button" @click="closeUserDrawer">{{ t('common.cancel') }}</button><button class="button access-primary" type="submit">{{ t('rbac.createUser') }}</button></footer>
          </form>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="roleDrawerOpen && editingRole" class="access-drawer-layer" @click.self="startCreateRole">
        <aside class="access-drawer role-editor-drawer" role="dialog" aria-modal="true">
          <header class="access-drawer-head"><div><span class="access-code">PERMISSION MATRIX</span><h2>{{ t('rbac.editRole', { name: editingRole }) }}</h2></div><button type="button" @click="startCreateRole"><svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></svg></button></header>
          <div class="role-editor-body">
            <label class="role-description-field"><span>{{ t('rbac.roleDescription') }}</span><input v-model="roleDraft.description" :placeholder="t('role.descriptionPlaceholder')" /></label>
            <label class="access-search permission-search"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></svg><input v-model="permissionSearch" type="search" :placeholder="t('rbac.searchPermissions')" /></label>
            <section v-for="group in permissionGroups" :key="group.key" class="permission-group">
              <header><label><input type="checkbox" :checked="permissionGroupSelected(group.permissions)" @change="togglePermissionGroup(group.permissions)" /><strong>{{ group.label }}</strong></label><span>{{ group.permissions.length }}</span></header>
              <div class="permission-grid">
                <label v-for="permission in group.permissions" :key="permission"><input type="checkbox" :checked="roleDraft.permissions.includes(permission)" @change="togglePermission(permission)" /><span>{{ permission }}</span></label>
              </div>
            </section>
          </div>
          <footer class="access-drawer-foot"><button class="button compact" type="button" @click="startCreateRole">{{ t('common.cancel') }}</button><button class="button access-primary" type="button" @click="saveRole">{{ t('rbac.saveRole') }}</button></footer>
        </aside>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="deleteTarget" class="access-dialog-layer" @click.self="closeDeleteDialog">
        <aside class="access-dialog" role="dialog" aria-modal="true">
          <header><span class="access-warning" aria-hidden="true">!</span><div><span class="access-code">DANGER GATE</span><h2>{{ t('common.confirm') }}</h2></div></header>
          <p v-if="deleteTarget.type === 'user'">{{ t('rbac.confirmDeleteUser', { name: deleteTarget.user.username }) }}</p>
          <p v-else>{{ t('rbac.confirmDeleteRole', { name: deleteTarget.role.name }) }}</p>
          <footer><button class="button compact" type="button" @click="closeDeleteDialog">{{ t('common.cancel') }}</button><button class="button compact danger" type="button" :disabled="deleting" @click="confirmDelete">{{ deleting ? t('common.loading') : t('common.delete') }}</button></footer>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<style scoped>
.alert.ok {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 10%, var(--surface));
}

.rbac-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
  gap: 14px;
}

.rbac-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  background: var(--surface);
  box-shadow: none;
}

.rbac-form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 8px;
}

.rbac-table {
  width: 100%;
  min-width: 560px;
  border-collapse: collapse;
  background: var(--surface);
}

.rbac-table th,
.rbac-table td {
  padding: 8px 6px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 13px;
}

.rbac-table th {
  color: var(--text-secondary);
  background: var(--surface-soft);
}

.rbac-table select {
  padding: 6px 8px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
}

.rbac-actions {
  display: flex;
  gap: 6px;
}

.rbac-permissions {
  display: grid;
  gap: 10px;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}

.rbac-permissions h3 {
  margin: 0;
  font-size: 15px;
}

.rbac-permissions input[type='text'],
.rbac-permissions > input {
  width: 100%;
  padding: 9px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  background: var(--field-bg);
}

.permission-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 6px 12px;
}

.permission-grid label {
  display: flex;
  gap: 8px;
  align-items: center;
  font-size: 13px;
}

@media (max-width: 760px) {
  .rbac-grid,
  .rbac-form {
    grid-template-columns: minmax(0, 1fr);
  }

  .rbac-table {
    display: table;
    overflow: visible;
  }
}
</style>

<style scoped>
/* Access gate */
.main-column .page-rbac.access-control {
  --access-accent: #34d399;
  --access-cyan: #55c7e8;
  --access-amber: #f0a43a;
  --access-violet: #9d8cff;
  --access-coral: #fb7185;
  --access-panel: color-mix(in srgb, var(--surface) 95%, #07110b);
  --access-line: color-mix(in srgb, var(--border-strong) 62%, transparent);
  padding-bottom: 24px;
}

.main-column .page-rbac.access-control .access-header {
  align-items: center;
  min-height: 88px;
  margin-bottom: 10px;
  border-color: color-mix(in srgb, var(--access-accent) 24%, var(--border)) !important;
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--access-accent) 9%, transparent), transparent 38%),
    repeating-linear-gradient(
      90deg,
      transparent 0 37px,
      color-mix(in srgb, var(--access-accent) 5%, transparent) 37px 38px
    ),
    var(--access-panel) !important;
}

.access-heading {
  display: flex;
  min-width: 0;
  gap: 13px;
  align-items: center;
}

.access-heading > div {
  min-width: 0;
}

.access-gate-robot {
  position: relative;
  display: block;
  flex: 0 0 52px;
  width: 52px;
  height: 52px;
  color: var(--access-accent);
}

.access-robot-antenna {
  position: absolute;
  top: 0;
  left: 21px;
  width: 2px;
  height: 8px;
  background: currentColor;
}

.access-robot-antenna::before {
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

.access-robot-face {
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

.access-robot-face b {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 6px currentColor;
  animation: access-scan-eye 3.2s ease-in-out infinite;
}

.access-robot-face em {
  position: absolute;
  bottom: 3px;
  width: 8px;
  height: 1px;
  background: currentColor;
}

.access-robot-body {
  position: absolute;
  bottom: 2px;
  left: 8px;
  width: 28px;
  height: 13px;
  border: 1px solid currentColor;
  border-radius: 2px 2px 4px 4px;
  background: color-mix(in srgb, currentColor 5%, var(--surface));
}

.access-gate {
  position: absolute;
  right: 0;
  bottom: 0;
  width: 18px;
  height: 21px;
  border: 1px solid var(--access-amber);
  border-radius: 2px;
}

.access-gate::before,
.access-gate::after {
  position: absolute;
  content: '';
  background: var(--access-amber);
}

.access-gate::before {
  top: -1px;
  bottom: -1px;
  left: 5px;
  width: 1px;
}

.access-gate::after {
  top: 8px;
  right: 2px;
  width: 4px;
  height: 4px;
  border-radius: 50%;
}

.main-column .page-rbac .access-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 11px;
}

.access-header .button {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.access-header .button svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
}

.access-alert {
  margin: 0 0 9px;
  border-radius: 4px;
}

.access-status-rail {
  position: relative;
  display: grid;
  grid-template-columns: repeat(4, minmax(110px, 1fr));
  gap: 1px;
  margin-bottom: 10px;
  overflow: hidden;
  border: 1px solid var(--access-line);
  border-radius: 5px;
  background: var(--access-line);
}

.access-stat {
  --access-tone: var(--access-accent);
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 8px;
  min-height: 65px;
  padding: 9px 11px;
  background: var(--access-panel);
}

.access-stat::after {
  position: absolute;
  bottom: 0;
  left: 11px;
  width: 28px;
  height: 2px;
  content: '';
  background: var(--access-tone);
}

.access-stat.tone-active {
  --access-tone: var(--access-cyan);
}

.access-stat.tone-roles {
  --access-tone: var(--access-violet);
}

.access-stat.tone-permissions {
  --access-tone: var(--access-amber);
}

.access-stat > span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.access-stat strong {
  grid-row: span 2;
  align-self: center;
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 500;
}

.access-stat small {
  align-self: end;
  color: var(--text-muted);
  font-size: 9px;
}

.access-scan {
  position: absolute;
  right: 12px;
  bottom: 8px;
  width: 43px;
  height: 8px;
  overflow: hidden;
  opacity: 0.42;
}

.access-scan::before {
  position: absolute;
  inset: 0;
  content: '';
  background: repeating-linear-gradient(
    90deg,
    var(--access-accent) 0 3px,
    transparent 3px 7px
  );
}

.access-scan i {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--access-cyan);
  box-shadow: 0 0 7px var(--access-cyan);
  animation: access-scan-line 4s linear infinite;
}

.access-tabs {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
  margin-bottom: 10px;
}

.access-tabs button {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  min-width: 0;
  min-height: 54px;
  padding: 8px 11px;
  border: 1px solid var(--access-line);
  border-radius: 4px;
  color: var(--text-secondary);
  background: var(--access-panel);
  text-align: left;
  cursor: pointer;
}

.access-tabs button.active {
  border-color: color-mix(in srgb, var(--access-accent) 66%, var(--border));
  color: var(--text-primary);
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--access-accent) 9%, transparent), transparent),
    var(--access-panel);
  box-shadow: inset 3px 0 0 var(--access-accent);
}

.access-tabs svg {
  width: 18px;
  height: 18px;
  fill: none;
  stroke: var(--access-accent);
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.access-tabs span {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.access-tabs strong {
  font-size: 11px;
}

.access-tabs small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.access-tabs b {
  color: var(--access-accent);
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 500;
}

.access-panel {
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--access-accent) 18%, var(--border));
  border-radius: 5px;
  background: var(--access-panel);
}

.access-panel-head {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  padding: 11px 13px;
  border-bottom: 1px solid var(--border);
}

.access-code {
  color: var(--access-accent);
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
}

.access-panel-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 14px;
}

.access-primary {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  border-color: color-mix(in srgb, var(--access-accent) 66%, var(--border)) !important;
  color: #06120c !important;
  background: var(--access-accent) !important;
}

.access-primary svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
}

.access-panel-count {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid color-mix(in srgb, var(--access-accent) 38%, var(--border));
  border-radius: 50%;
  color: var(--access-accent);
  font-family: var(--mono);
  font-size: 13px;
  place-items: center;
}

.access-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  align-items: center;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--field-bg) 52%, transparent);
}

.access-search {
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

.access-search svg {
  width: 13px;
  height: 13px;
  fill: none;
  stroke: var(--text-muted);
  stroke-width: 1.7;
}

.access-search input {
  min-width: 0;
  padding: 7px 0 !important;
  border: 0 !important;
  outline: 0;
  background: transparent !important;
}

.access-segmented {
  display: inline-flex;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.access-segmented button {
  min-height: 26px;
  padding: 3px 8px;
  border: 0;
  border-radius: 2px;
  color: var(--text-muted);
  background: transparent;
  font-size: 9px;
  cursor: pointer;
}

.access-segmented button.active {
  color: var(--text-primary);
  background: color-mix(in srgb, var(--access-accent) 11%, var(--surface));
  box-shadow: inset 0 -2px 0 var(--access-accent);
}

.access-user-list,
.access-role-list {
  display: grid;
  gap: 4px;
  padding: 9px;
}

.access-user-row {
  display: grid;
  grid-template-columns: 38px minmax(150px, 1fr) 90px 82px minmax(100px, 130px) auto;
  gap: 9px;
  align-items: center;
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-left: 2px solid var(--access-accent);
  border-radius: 3px;
  background: var(--surface);
}

.access-user-row.disabled {
  opacity: 0.62;
  border-left-color: var(--text-muted);
}

.access-user-row.is-current {
  background:
    linear-gradient(90deg, color-mix(in srgb, var(--access-accent) 6%, transparent), transparent 24%),
    var(--surface);
}

.access-avatar {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--access-accent);
  border-radius: 7px;
  color: var(--access-accent);
  background: color-mix(in srgb, var(--access-accent) 7%, var(--surface));
  font-family: var(--mono);
  font-size: 13px;
  place-items: center;
}

.access-avatar.tone-operator {
  border-color: var(--access-cyan);
  color: var(--access-cyan);
  background: color-mix(in srgb, var(--access-cyan) 7%, var(--surface));
}

.access-avatar.tone-viewer {
  border-color: var(--access-violet);
  color: var(--access-violet);
  background: color-mix(in srgb, var(--access-violet) 7%, var(--surface));
}

.access-user-id {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.access-user-id strong {
  overflow: hidden;
  color: var(--text-primary);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.access-user-id small {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.access-role-badge,
.access-lock-badge,
.access-self-badge {
  display: inline-flex;
  width: fit-content;
  min-height: 18px;
  align-items: center;
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: 2px;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.access-role-badge.tone-admin,
.tone-admin .access-lock-badge {
  border-color: color-mix(in srgb, var(--access-accent) 48%, var(--border));
  color: var(--access-accent);
}

.access-role-badge.tone-operator {
  border-color: color-mix(in srgb, var(--access-cyan) 48%, var(--border));
  color: var(--access-cyan);
}

.access-role-badge.tone-viewer {
  border-color: color-mix(in srgb, var(--access-violet) 48%, var(--border));
  color: var(--access-violet);
}

.access-self-badge {
  border-color: color-mix(in srgb, var(--access-amber) 42%, var(--border));
  color: var(--access-amber);
}

.access-user-state {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--access-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.access-user-state i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 5px currentColor;
}

.disabled .access-user-state {
  color: var(--text-muted);
}

.access-role-select {
  display: grid;
  gap: 2px;
  color: var(--text-muted);
  font-size: 8px;
}

.access-role-select select {
  min-width: 0;
  padding: 4px 6px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
  font-size: 9px;
}

.access-row-actions {
  display: flex;
  gap: 3px;
  justify-content: flex-end;
}

.access-row-actions button,
.access-drawer-head > button {
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

.access-row-actions button:hover {
  border-color: color-mix(in srgb, var(--access-accent) 40%, var(--border));
  color: var(--access-accent);
  background: color-mix(in srgb, var(--access-accent) 7%, transparent);
}

.access-row-actions button.danger:hover {
  border-color: color-mix(in srgb, var(--access-coral) 45%, var(--border));
  color: var(--access-coral);
}

.access-row-actions button:disabled {
  opacity: 0.25;
  cursor: not-allowed;
}

.access-row-actions svg,
.access-drawer-head svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.access-role-row {
  display: grid;
  grid-template-columns: 36px minmax(180px, 1fr) 82px auto auto;
  gap: 9px;
  align-items: center;
  min-width: 0;
  padding: 8px;
  border: 1px solid var(--border);
  border-left: 2px solid var(--access-accent);
  border-radius: 3px;
  background: var(--surface);
}

.access-role-row.tone-operator {
  border-left-color: var(--access-cyan);
}

.access-role-row.tone-viewer {
  border-left-color: var(--access-violet);
}

.role-shield {
  position: relative;
  display: grid;
  width: 32px;
  height: 34px;
  border: 1px solid currentColor;
  border-radius: 7px 7px 11px 11px;
  color: var(--access-accent);
  place-items: center;
}

.tone-operator .role-shield {
  color: var(--access-cyan);
}

.tone-viewer .role-shield {
  color: var(--access-violet);
}

.role-shield i {
  width: 10px;
  height: 6px;
  border-right: 1px solid currentColor;
  border-bottom: 1px solid currentColor;
  transform: rotate(45deg) translate(-1px, -1px);
}

.access-role-id {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.access-role-id strong {
  color: var(--text-primary);
  font-size: 10px;
}

.access-role-id small {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.access-permission-count {
  display: grid;
  gap: 1px;
  justify-items: end;
}

.access-permission-count strong {
  color: var(--text-primary);
  font-family: var(--mono);
  font-size: 14px;
  font-weight: 500;
}

.access-permission-count small {
  color: var(--text-muted);
  font-size: 7px;
}

.access-empty {
  display: grid;
  min-height: 130px;
  gap: 10px;
  place-items: center;
  align-content: center;
  color: var(--text-muted);
  font-size: 9px;
}

.empty-gate {
  position: relative;
  display: block;
  width: 34px;
  height: 37px;
  border: 1px solid var(--text-muted);
  border-radius: 2px;
  opacity: 0.55;
}

.empty-gate::before {
  position: absolute;
  top: 4px;
  right: 4px;
  width: 5px;
  height: 5px;
  content: '';
  border: 1px solid var(--text-muted);
  border-radius: 50%;
}

.access-drawer-layer,
.access-dialog-layer {
  position: fixed;
  inset: 0;
  z-index: 90;
  display: flex;
  justify-content: flex-end;
  background: rgba(4, 10, 7, 0.62);
  backdrop-filter: blur(3px);
}

.access-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  width: min(560px, 100%);
  height: 100%;
  border-left: 1px solid color-mix(in srgb, var(--access-accent) 30%, var(--border));
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--access-accent) 4%, transparent), transparent 170px),
    var(--surface);
  box-shadow: -18px 0 50px rgba(0, 0, 0, 0.36);
  animation: access-drawer-in 0.22s ease-out both;
}

.role-editor-drawer {
  width: min(680px, 100%);
  grid-template-rows: auto minmax(0, 1fr) auto;
}

.access-drawer-head {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface-soft) 76%, transparent);
}

.access-drawer-head h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 16px;
}

.access-drawer-head > button {
  border-color: var(--border);
}

.access-drawer-head > button:hover {
  border-color: color-mix(in srgb, var(--access-coral) 45%, var(--border));
  color: var(--access-coral);
}

.access-user-form,
.role-editor-body {
  display: grid;
  gap: 9px;
  align-content: start;
  padding: 14px;
  overflow: auto;
}

.access-user-form section {
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr);
  gap: 8px;
  padding: 9px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--field-bg);
}

.access-user-form section > span {
  color: var(--access-accent);
  font-family: var(--mono);
  font-size: 8px;
}

.access-user-form label,
.role-description-field {
  display: grid;
  gap: 5px;
  color: var(--text-muted);
  font-size: 9px;
}

.access-user-form label b {
  color: var(--text-secondary);
  font-weight: 500;
}

.access-user-form input,
.access-user-form select,
.role-description-field input {
  min-width: 0;
  padding: 7px 8px;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--surface);
}

.access-user-form footer,
.access-drawer-foot {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
  padding: 10px 14px;
  border-top: 1px solid var(--border);
}

.permission-search {
  width: 100%;
}

.permission-group {
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 3px;
}

.permission-group > header {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: space-between;
  padding: 6px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--field-bg);
}

.permission-group > header label {
  display: flex;
  gap: 6px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 9px;
}

.permission-group > header span {
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.permission-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 5px 10px;
  padding: 8px;
}

.permission-grid label {
  display: flex;
  min-width: 0;
  gap: 6px;
  align-items: center;
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 8px;
}

.permission-grid input {
  width: auto;
}

.access-dialog-layer {
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.access-dialog {
  width: min(400px, 100%);
  padding: 15px;
  border: 1px solid color-mix(in srgb, var(--access-coral) 42%, var(--border));
  border-radius: 5px;
  background: var(--surface);
  box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
  animation: access-dialog-in 0.18s ease-out both;
}

.access-dialog header {
  display: flex;
  gap: 10px;
  align-items: center;
}

.access-dialog h2 {
  margin: 2px 0 0;
  color: var(--text-primary);
  font-size: 15px;
}

.access-warning {
  display: grid;
  width: 34px;
  height: 34px;
  border: 1px solid var(--access-coral);
  border-radius: 50%;
  color: var(--access-coral);
  font-family: var(--mono);
  font-size: 16px;
  place-items: center;
}

.access-dialog > p {
  margin: 12px 0;
  color: var(--text-secondary);
  font-size: 10px;
  line-height: 1.5;
}

.access-dialog footer {
  display: flex;
  gap: 7px;
  justify-content: flex-end;
}

@keyframes access-scan-eye {
  0%,
  100% {
    opacity: 0.55;
  }
  50% {
    opacity: 1;
  }
}

@keyframes access-scan-line {
  from {
    left: 0;
  }
  to {
    left: 100%;
  }
}

@keyframes access-drawer-in {
  from {
    opacity: 0;
    transform: translateX(24px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

@keyframes access-dialog-in {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: none;
  }
}

@media (max-width: 760px) {
  .main-column .page-rbac.access-control {
    overflow-x: hidden;
  }

  .access-header {
    align-items: stretch;
  }

  .access-heading {
    align-items: flex-start;
  }

  .access-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .access-tabs {
    grid-template-columns: 1fr;
  }

  .access-tabs button {
    min-width: 0;
    overflow: hidden;
  }

  .access-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .access-search,
  .access-segmented {
    width: 100%;
    min-width: 0;
  }

  .access-search {
    flex: 0 0 auto;
    min-height: 34px;
  }

  .access-segmented {
    overflow-x: auto;
  }

  .access-user-row {
    grid-template-columns: 36px minmax(0, 1fr) 76px;
    gap: 6px;
  }

  .access-user-state,
  .access-role-select,
  .access-self-badge {
    grid-column: 2;
  }

  .access-self-badge {
    width: fit-content;
  }

  .access-row-actions {
    grid-column: 3;
    grid-row: 1;
  }

  .access-role-row {
    grid-template-columns: 34px minmax(0, 1fr) auto;
  }

  .access-permission-count,
  .access-lock-badge {
    grid-column: 2;
  }

  .access-role-row .access-row-actions {
    grid-column: 3;
    grid-row: 1;
  }

  .access-drawer {
    width: 100%;
  }

  .permission-grid {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  .access-robot-face b,
  .access-scan i,
  .access-drawer,
  .access-dialog {
    animation: none;
  }
}
</style>

<style scoped>
/* Users & Access in the Vulnerability Management visual system */
.main-column .page-rbac.access-control .access-header {
  min-height: 78px;
  padding: 14px 16px;
  border-color: var(--line) !important;
  border-radius: 4px !important;
  background: var(--surface) !important;
  box-shadow: none !important;
}

.main-column .page-rbac .access-page-hint {
  margin: 4px 0 0;
  color: var(--text-muted);
  font-size: 10px;
}

.main-column .page-rbac .access-header .button {
  min-height: 30px;
  padding: 5px 9px;
  border-radius: 3px;
  font-size: 10px;
}

.access-status-rail {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
  padding: 0;
  border: 0;
  background: transparent;
}

.access-stat {
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

.access-stat small {
  display: flex;
  gap: 6px;
  align-items: center;
  color: #55c7e8;
  font-size: 12px;
}

.access-stat-icon {
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

.access-stat strong {
  color: #55c7e8;
  font-family: var(--mono);
  font-size: 20px;
  font-variant-numeric: tabular-nums;
}

.access-stat::after,
.access-scan {
  display: none;
}

.access-stat.tone-active {
  border-left-color: var(--success);
}

.access-stat.tone-active small,
.access-stat.tone-active strong {
  color: var(--success);
}

.access-stat.tone-roles {
  border-left-color: #9d8cff;
}

.access-stat.tone-roles small,
.access-stat.tone-roles strong {
  color: #9d8cff;
}

.access-stat.tone-permissions {
  border-left-color: var(--warning);
}

.access-stat.tone-permissions small,
.access-stat.tone-permissions strong {
  color: var(--warning);
}

.access-tabs {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}

.access-tabs button {
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr) auto;
  min-height: 44px;
  width: 100%;
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-left: 3px solid transparent;
  border-radius: var(--radius);
  background: var(--surface);
}

.access-tabs button.active {
  border-left-color: #34d399;
  background: color-mix(in srgb, #34d399 6%, var(--surface));
}

.access-tabs button small {
  display: none;
}

.access-panel {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
}

.access-panel-head,
.access-toolbar {
  border-bottom: 1px solid var(--border);
  background: var(--surface-soft);
}

.access-toolbar {
  padding: 8px 10px;
}

.access-search {
  height: 34px;
  border-radius: var(--radius);
  background: var(--field-bg);
}

.access-search input {
  height: 32px;
  padding: 0;
  border: 0;
  background: transparent;
}

.access-segmented {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}

.access-user-list,
.access-role-list {
  border: 1px solid var(--line);
  background: var(--surface);
}

.access-user-row,
.access-role-row {
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
}

.access-user-row:hover,
.access-role-row:hover {
  background: color-mix(in srgb, #34d399 4%, transparent);
}

.access-drawer-layer,
.access-dialog-layer {
  background: rgba(4, 9, 10, 0.62);
  backdrop-filter: blur(3px);
}

.access-drawer {
  width: min(720px, 100%);
  border-left-color: color-mix(in srgb, #34d399 32%, var(--border));
  background: var(--surface);
}

.access-drawer-head,
.access-drawer-foot {
  background: var(--surface-soft);
}

.access-dialog {
  border-radius: 4px;
  background: var(--surface);
}

@media (max-width: 760px) {
  .access-status-rail {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .access-tabs {
    grid-template-columns: minmax(0, 1fr);
  }

  .access-drawer {
    width: 100%;
  }
}
</style>
