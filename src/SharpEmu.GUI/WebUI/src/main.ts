import { createApp } from 'vue'
import App from './App.vue'
import './styles/theme.css'

// On load, ask the host for the initial state. The host also begins pushing
// library/settings/localization once the WebView finishes navigating, but this
// request guarantees we get data even if the NavigationCompleted push races.
import { send } from './bridge'
send({ type: 'requestState' })

createApp(App).mount('#app')

// The browser preview can opt into a representative library without changing
// packaged launcher behavior. Useful for iterating on cover-heavy layouts.
if (import.meta.env.DEV && new URLSearchParams(location.search).has('demo')) {
  void import('./demo').then(({ installDemoState }) => installDemoState())
}
