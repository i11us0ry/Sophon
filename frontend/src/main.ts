import { createApp } from 'vue'
import { createPinia } from 'pinia'

import App from './App.vue'
import { initI18n } from './i18n'
import router from './router'
import { initTheme } from './theme'
import './styles/main.css'
import './styles/factory-pages.css'

initTheme()
initI18n()

createApp(App)
  .use(createPinia())
  .use(router)
  .mount('#app')
