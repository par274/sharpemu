<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useStore, setSearch } from './store'
import LibraryView from './views/LibraryView.vue'
import OptionsView from './views/OptionsView.vue'
import ConsoleView from './views/ConsoleView.vue'

const { state, t, setView } = useStore()
const now = ref('')
let clockTimer: number | undefined

const tabs = [
  { id: 'library', label: 'Page.Library' },
  { id: 'options', label: 'Page.Options' },
] as const

function cycleView(direction: -1 | 1) {
  const current = tabs.findIndex((tab) => tab.id === state.view)
  const next = current < 0
    ? 0
    : (current + direction + tabs.length) % tabs.length
  setView(tabs[next]!.id)
}

function updateClock() {
  now.value = new Intl.DateTimeFormat([], {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date())
}

onMounted(() => {
  updateClock()
  clockTimer = window.setInterval(updateClock, 15_000)
})

onBeforeUnmount(() => window.clearInterval(clockTimer))
</script>

<template>
  <div class="shell" :class="{ 'shell--library': state.view === 'library' }">
    <header class="topbar">
      <button class="brand" aria-label="SharpEmu" @click="setView('library')">
        <svg class="brand-mark" viewBox="0 0 42 42" aria-hidden="true">
          <path d="M21 3 36.6 12v18L21 39 5.4 30V12L21 3Z" />
          <path d="m13 24 8-13v10h8l-8 10V24h-8Z" class="brand-bolt" />
        </svg>
        <span>SHARP<span>EMU</span></span>
      </button>

      <nav class="tabs" aria-label="Primary">
        <button class="shoulder-key" aria-label="Previous section" @click="cycleView(-1)">
          <svg viewBox="0 0 38 28" aria-hidden="true">
            <path d="M7 2h29v24H4c-1.8 0-3-1.5-2.7-3.2L4 5.2C4.3 3.3 5.2 2 7 2Z" />
            <text x="19" y="18">L1</text>
          </svg>
        </button>
        <div class="tab-list">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            class="nav-item"
            :class="{ active: state.view === tab.id }"
            @click="setView(tab.id)"
          >
            {{ t(tab.label) }}
          </button>
        </div>
        <button class="shoulder-key" aria-label="Next section" @click="cycleView(1)">
          <svg viewBox="0 0 38 28" aria-hidden="true">
            <path d="M2 2h29c1.8 0 2.7 1.3 3 3.2l2.7 17.6c.3 1.7-.9 3.2-2.7 3.2H2V2Z" />
            <text x="19" y="18">R1</text>
          </svg>
        </button>
      </nav>

      <div class="topbar-right">
        <label v-if="state.view === 'library'" class="quick-search">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="11" cy="11" r="6.5" />
            <path d="m16 16 4 4" />
          </svg>
          <input
            type="search"
            :placeholder="t('Library.SearchWatermark')"
            @input="setSearch(($event.target as HTMLInputElement).value)"
          />
        </label>

        <button
          class="icon-button"
          :class="{ active: state.view === 'console' }"
          :aria-label="t('Console.Title')"
          :title="t('Console.Title')"
          @click="setView('console')"
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="18" height="16" rx="3" />
            <path d="m7 9 3 3-3 3m6 0h4" />
          </svg>
        </button>

        <span v-if="state.session.isRunning" class="session-dot" :title="state.session.title ?? ''" />
        <time>{{ now }}</time>
      </div>
    </header>

    <main class="content">
      <LibraryView v-show="state.view === 'library'" />
      <div v-if="state.view === 'options'" class="page-frame">
        <div class="page-heading">
          <span class="kicker">SHARPEMU / SYSTEM</span>
          <h1>{{ t('Page.Options') }}</h1>
        </div>
        <OptionsView />
      </div>
      <div v-if="state.view === 'console'" class="page-frame page-frame--console">
        <div class="page-heading page-heading--row">
          <div>
            <span class="kicker">SHARPEMU / RUNTIME</span>
            <h1>{{ t('Console.Title') }}</h1>
          </div>
          <span class="live-state" :class="{ online: state.session.isRunning }">
            {{ state.session.isRunning ? state.session.title : 'IDLE' }}
          </span>
        </div>
        <ConsoleView />
      </div>
    </main>
  </div>
</template>

<style scoped>
.shell {
  min-height: 100%;
  background: var(--bg-base);
}

.topbar {
  position: fixed;
  z-index: 50;
  top: 0;
  left: 0;
  right: 0;
  height: 92px;
  padding: 0 clamp(26px, 4vw, 72px);
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  gap: 32px;
  background: linear-gradient(to bottom, rgba(5, 8, 15, 0.58), transparent);
}

.brand {
  justify-self: start;
  display: flex;
  align-items: center;
  gap: 11px;
  font-size: 15px;
  font-weight: 800;
  letter-spacing: 0.08em;
}

.brand span span {
  color: var(--accent);
}

.brand-mark {
  width: 38px;
  height: 38px;
  fill: rgba(255, 255, 255, 0.1);
  stroke: rgba(255, 255, 255, 0.75);
  stroke-width: 1.2;
}

.brand-bolt {
  fill: var(--accent);
  stroke: none;
}

.tabs {
  display: flex;
  align-items: center;
  gap: 14px;
}

.tab-list {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0;
}

.shoulder-key {
  width: 38px;
  height: 28px;
  padding: 0;
  filter: drop-shadow(0 2px 5px rgba(0, 0, 0, 0.32));
  transition: transform 160ms var(--ease-out), filter 160ms ease;
}

.shoulder-key svg {
  display: block;
  width: 100%;
  height: 100%;
}

.shoulder-key path {
  fill: rgba(255, 255, 255, 0.96);
}

.shoulder-key text {
  fill: #0b1019;
  font-family: "Google Sans", sans-serif;
  font-size: 10px;
  font-weight: 700;
  text-anchor: middle;
}

.shoulder-key:hover {
  transform: translateY(-1px);
  filter: drop-shadow(0 4px 7px rgba(0, 0, 0, 0.4));
}

.nav-item {
  min-width: 112px;
  padding: 11px 20px;
  border-radius: 999px;
  color: #fff;
  font-size: 14px;
  font-weight: 650;
  transition: color 180ms ease, background 180ms ease;
}

.nav-item:hover {
  color: #fff;
}

.nav-item.active {
  color: #fff;
  background: rgba(255, 255, 255, 0.14);
}

.topbar-right {
  justify-self: end;
  display: flex;
  align-items: center;
  gap: 14px;
}

.topbar-right time {
  min-width: 54px;
  font-size: 14px;
  font-weight: 650;
  color: rgba(255, 255, 255, 0.78);
}

.quick-search {
  width: 40px;
  height: 40px;
  padding: 0 11px;
  display: flex;
  align-items: center;
  gap: 9px;
  overflow: hidden;
  border-radius: 999px;
  color: #fff;
  background: transparent;
  transition: width 260ms var(--ease-out);
}

.quick-search:focus-within,
.quick-search:hover {
  width: 220px;
}

.quick-search svg,
.icon-button svg {
  width: 18px;
  height: 18px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  flex: 0 0 auto;
}

.quick-search input {
  width: 160px;
  border: 0;
  outline: 0;
  color: #fff;
  background: transparent;
  font-size: 13px;
}

.quick-search input::placeholder {
  color: rgba(255, 255, 255, 0.45);
}

.icon-button {
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  color: #fff;
  background: transparent;
  transition: opacity 160ms ease, transform 160ms var(--ease-out);
}

.icon-button:hover,
.icon-button.active {
  color: #fff;
  background: transparent;
  opacity: 0.72;
  transform: translateY(-1px);
}

.session-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #66f2a3;
  box-shadow: 0 0 12px #66f2a3;
}

.content {
  min-height: 100vh;
}

.page-frame {
  min-height: 100vh;
  padding: 132px clamp(28px, 7vw, 120px) 64px;
  background:
    radial-gradient(circle at 90% 0%, rgba(72, 112, 180, 0.13), transparent 38%),
    var(--bg-base);
}

.page-frame--console {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.page-heading {
  margin-bottom: 42px;
}

.page-heading--row {
  display: flex;
  align-items: end;
  justify-content: space-between;
}

.kicker {
  color: var(--accent);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.22em;
}

.page-heading h1 {
  margin-top: 8px;
  font-size: clamp(40px, 5vw, 70px);
  font-weight: 650;
  line-height: 0.96;
  letter-spacing: -0.055em;
}

.live-state {
  color: var(--muted);
  font-size: 11px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.live-state.online {
  color: #66f2a3;
}

@media (max-width: 820px) {
  .topbar {
    grid-template-columns: auto 1fr auto;
    padding-inline: 20px;
  }

  .brand > span,
  .topbar-right time,
  .quick-search {
    display: none;
  }

  .nav-item {
    min-width: 0;
  }

  .tabs {
    gap: 7px;
  }

  .shoulder-key {
    display: none;
  }
}
</style>
