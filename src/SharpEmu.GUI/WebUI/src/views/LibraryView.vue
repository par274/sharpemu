<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useStore, filteredGames, requestBackground } from '../store'
import { send } from '../bridge'
import GameTile from '../components/GameTile.vue'
import type { GameEntry } from '../types'

const { state, t } = useStore()
const selectedPath = ref<string | null>(null)
const showActions = ref(false)
const actionMenu = ref<HTMLElement | null>(null)
const optionsHint = ref<HTMLButtonElement | null>(null)
const actionMenuPosition = ref({ left: '0px', top: '0px' })

const orderedGames = computed(() => {
  const recentPaths = new Set(state.recent.map((game) => game.ebootPath))
  return [
    ...state.recent.filter((game) =>
      filteredGames.value.some((candidate) => candidate.ebootPath === game.ebootPath),
    ),
    ...filteredGames.value.filter((game) => !recentPaths.has(game.ebootPath)),
  ]
})

const selectedGame = computed(() =>
  orderedGames.value.find((game) => game.ebootPath === selectedPath.value)
  ?? state.lastPlayed
  ?? orderedGames.value[0]
  ?? null,
)

const selectedBackdrop = computed(() => {
  const game = selectedGame.value
  if (!game) {
    return null
  }

  const fullSizeBackground = state.backgrounds[game.ebootPath]
  if (fullSizeBackground) {
    return fullSizeBackground
  }

  return game.hasBackground === true ? null : game.coverDataUri
})

const hasLoadedBackground = computed(() => {
  const game = selectedGame.value
  return game ? Boolean(state.backgrounds[game.ebootPath]) : false
})

watch(
  orderedGames,
  (games) => {
    if (!games.some((game) => game.ebootPath === selectedPath.value)) {
      selectedPath.value = state.lastPlayed?.ebootPath ?? games[0]?.ebootPath ?? null
    }
  },
  { immediate: true },
)

watch(
  selectedGame,
  (game) => {
    if (game) {
      requestBackground(game)
    }
  },
  { immediate: true },
)

function selectGame(game: GameEntry) {
  selectedPath.value = game.ebootPath
  closeActions()
}

function launchSelected() {
  if (state.session.isRunning) {
    send({ type: 'stop' })
  } else if (selectedGame.value) {
    send({ type: 'launch', ebootPath: selectedGame.value.ebootPath })
  }
}

function positionActionMenu() {
  const selectedTile = document.querySelector<HTMLElement>('.game-tile.is-selected')
  if (!selectedTile) return

  const tile = selectedTile.getBoundingClientRect()
  const menuWidth = Math.min(390, window.innerWidth - 40)
  const menuHeight = Math.min(390, window.innerHeight - 40)
  const gap = 18
  const preferredLeft = tile.right + gap
  const left = preferredLeft + menuWidth <= window.innerWidth - 20
    ? preferredLeft
    : tile.left - menuWidth - gap

  actionMenuPosition.value = {
    left: `${Math.max(20, Math.min(left, window.innerWidth - menuWidth - 20))}px`,
    top: `${Math.max(104, Math.min(tile.top, window.innerHeight - menuHeight - 20))}px`,
  }
}

async function openActions() {
  if (!selectedGame.value) return

  positionActionMenu()
  showActions.value = true
  await nextTick()
  actionMenu.value?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus()
}

function closeActions(restoreFocus = false) {
  showActions.value = false
  if (restoreFocus) {
    void nextTick(() => optionsHint.value?.focus())
  }
}

function toggleActions() {
  if (showActions.value) {
    closeActions(true)
  } else {
    void openActions()
  }
}

function runAction(action: () => void) {
  action()
  closeActions()
}

function focusSearch() {
  document.querySelector<HTMLInputElement>('.quick-search input')?.focus()
}

async function moveSelection(delta: number) {
  if (!orderedGames.value.length) return
  const current = orderedGames.value.findIndex((game) => game.ebootPath === selectedGame.value?.ebootPath)
  const next = Math.max(0, Math.min(orderedGames.value.length - 1, current + delta))
  selectedPath.value = orderedGames.value[next]!.ebootPath
  await nextTick()
  document.querySelector<HTMLElement>('.game-tile.is-selected')?.focus()
}

function onKeydown(event: KeyboardEvent) {
  if (state.view !== 'library') return

  if (showActions.value) {
    const items = Array.from(
      actionMenu.value?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [],
    )
    const current = Math.max(0, items.indexOf(document.activeElement as HTMLButtonElement))

    if (event.key === 'Escape' || event.key === 'ContextMenu' || event.key === 'F10') {
      event.preventDefault()
      closeActions(true)
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Tab') {
      event.preventDefault()
      const direction = event.key === 'ArrowUp' || (event.key === 'Tab' && event.shiftKey) ? -1 : 1
      items[(current + direction + items.length) % items.length]?.focus()
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault()
      items[event.key === 'Home' ? 0 : items.length - 1]?.focus()
    }
    return
  }

  if (event.key === 'ContextMenu' || event.key === 'F10') {
    event.preventDefault()
    void openActions()
    return
  }

  const target = event.target as HTMLElement
  if (target?.matches('input, select, textarea')) return
  if (target?.matches('button:not(.game-tile)')) return

  if (event.key === 'ArrowLeft') {
    event.preventDefault()
    void moveSelection(-1)
  } else if (event.key === 'ArrowRight') {
    event.preventDefault()
    void moveSelection(1)
  } else if (event.key === 'Enter' && selectedGame.value) {
    event.preventDefault()
    launchSelected()
  }
}

function onResize() {
  if (showActions.value) {
    positionActionMenu()
  }
}

watch(
  () => state.view,
  (view) => {
    if (view !== 'library') closeActions()
  },
)

onMounted(() => {
  window.addEventListener('keydown', onKeydown)
  window.addEventListener('resize', onResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeydown)
  window.removeEventListener('resize', onResize)
})
</script>

<template>
  <section class="library" :class="{ 'library--empty': !state.games.length && !state.scanning }">
    <Transition name="backdrop" mode="out-in">
      <img
        v-if="selectedBackdrop"
        :key="`${selectedGame?.ebootPath}:${hasLoadedBackground ? 'key-art' : 'cover'}`"
        class="backdrop"
        :class="{ 'backdrop--cover-fallback': !hasLoadedBackground }"
        :src="selectedBackdrop"
        alt=""
      />
      <div v-else key="empty" class="backdrop backdrop--placeholder" />
    </Transition>
    <div class="atmosphere" />
    <div class="grain" />

    <div v-if="state.scanning" class="center-state">
      <span class="scan-orbit" />
      <span class="state-kicker">SHARPEMU</span>
      <h1>{{ t('Library.Loading') }}</h1>
    </div>

    <div v-else-if="state.games.length === 0" class="center-state">
      <span class="state-kicker">YOUR PLAYGROUND AWAITS</span>
      <h1>{{ t('Library.Empty.Title') }}</h1>
      <p>{{ t('Library.Empty.Hint') }}</p>
      <button class="primary-action" @click="send({ type: 'addFolder' })">
        <span class="button-symbol">+</span>
        {{ t('Library.Empty.AddFolder') }}
      </button>
    </div>

    <template v-else-if="selectedGame">
      <Transition name="details" mode="out-in">
        <div :key="selectedGame.ebootPath" class="game-details">
          <div class="title-line">
            <h1>{{ selectedGame.name }}</h1>
          </div>

          <div class="game-stats">
            <div class="game-stat">
              <span class="stat-label">Last played</span>
              <strong>{{ selectedGame.lastPlayedText ?? 'Not played yet' }}</strong>
            </div>
            <div class="game-stat">
              <span class="stat-label">Version</span>
              <strong>{{ selectedGame.version ?? '—' }}</strong>
            </div>
            <div class="game-stat">
              <span class="stat-label">Installed</span>
              <strong>{{ selectedGame.sizeText }}</strong>
            </div>
            <div v-if="selectedGame.titleId" class="game-stat game-stat--id">
              <span class="stat-label">Title ID</span>
              <strong>{{ selectedGame.titleId }}</strong>
            </div>
          </div>
        </div>
      </Transition>

      <div class="library-rail">
        <div class="game-track">
          <GameTile
            v-for="game in orderedGames"
            :key="game.ebootPath"
            :game="game"
            :selected="game.ebootPath === selectedGame.ebootPath"
            @select="selectGame"
          />
          <button class="add-game-tile" @click="send({ type: 'addFolder' })">
            <span>+</span>
            {{ t('Library.AddFolder').replace('＋ ', '') }}
          </button>
        </div>
      </div>

      <Transition name="options-scrim">
        <button
          v-if="showActions"
          class="options-scrim"
          tabindex="-1"
          aria-label="Close game options"
          @click="closeActions(true)"
        />
      </Transition>

      <Transition name="options-menu">
        <section
          v-if="showActions"
          ref="actionMenu"
          class="action-menu"
          :style="actionMenuPosition"
          role="menu"
          :aria-label="`${selectedGame.name} options`"
        >
          <button
            class="action-menu__item"
            role="menuitem"
            @click="runAction(launchSelected)"
          >
            {{ state.session.isRunning ? 'Stop' : (selectedGame.hasPlayed ? t('Library.Hero.Resume') : t('Library.Context.Launch')) }}
          </button>
          <button
            class="action-menu__item"
            role="menuitem"
            @click="runAction(() => send({ type: 'gameSettings', ebootPath: selectedGame.ebootPath }))"
          >
            {{ t('Library.Context.GameSettings') }}
          </button>
          <button
            class="action-menu__item"
            role="menuitem"
            @click="runAction(() => send({ type: 'openGameFolder', ebootPath: selectedGame.ebootPath }))"
          >
            {{ t('Library.Context.OpenFolder') }}
          </button>
          <button
            class="action-menu__item"
            role="menuitem"
            @click="runAction(() => send({ type: 'copyToClipboard', text: selectedGame.ebootPath }))"
          >
            {{ t('Library.Context.CopyPath') }}
          </button>
          <div class="action-menu__divider" />
          <button
            class="action-menu__item action-menu__item--danger"
            role="menuitem"
            @click="runAction(() => send({ type: 'removeGame', ebootPath: selectedGame.ebootPath }))"
          >
            {{ t('Library.Context.Remove') }}
          </button>
        </section>
      </Transition>
    </template>

    <footer class="control-hints">
      <button @click="launchSelected">
        <span class="pad-key">×</span>
        {{ state.session.isRunning ? 'Stop' : 'Play' }}
      </button>
      <button @click="focusSearch">
        <span class="pad-key pad-key--triangle">△</span>
        Search
      </button>
      <button ref="optionsHint" :aria-expanded="showActions" @click="toggleActions">
        <span class="pad-key pad-key--options"><i /></span>
        Options
      </button>
    </footer>
  </section>
</template>

<style scoped>
.library {
  position: relative;
  min-height: 100vh;
  overflow: hidden;
  background: #060912;
}

.backdrop {
  position: absolute;
  z-index: 0;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: center;
  filter: saturate(0.88);
}

.backdrop--cover-fallback {
  left: auto;
  width: 68%;
  object-fit: contain;
  object-position: right center;
  -webkit-mask-image: linear-gradient(to right, transparent 0%, rgba(0, 0, 0, 0.65) 10%, #000 24%);
  mask-image: linear-gradient(to right, transparent 0%, rgba(0, 0, 0, 0.65) 10%, #000 24%);
}

.backdrop--placeholder {
  width: 100%;
  background:
    radial-gradient(circle at 70% 35%, rgba(72, 113, 184, 0.42), transparent 28%),
    linear-gradient(125deg, #152038, #080b12 65%);
}

.atmosphere {
  position: absolute;
  z-index: 1;
  inset: 0;
  background:
    linear-gradient(rgba(3, 6, 12, 0.42), rgba(3, 6, 12, 0.42)),
    linear-gradient(90deg, rgba(5, 8, 15, 0.92) 0%, rgba(5, 8, 15, 0.65) 30%, rgba(5, 8, 15, 0.12) 58%, rgba(5, 8, 15, 0.06) 100%),
    linear-gradient(0deg, #060912 0%, rgba(6, 9, 18, 0.78) 18%, rgba(6, 9, 18, 0.06) 58%, rgba(6, 9, 18, 0.2) 100%);
}

.grain {
  position: absolute;
  z-index: 2;
  inset: 0;
  opacity: 0.16;
  pointer-events: none;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.2'/%3E%3C/svg%3E");
}

.game-details {
  position: absolute;
  z-index: 5;
  top: clamp(430px, 61vh, 660px);
  left: clamp(32px, 5vw, 88px);
  width: min(980px, 86vw);
}

.title-line {
  display: flex;
  align-items: center;
}

.game-details h1 {
  max-width: 880px;
  color: #fff;
  font-size: clamp(34px, 3.6vw, 58px);
  font-weight: 650;
  line-height: 1.04;
  letter-spacing: -0.045em;
  text-shadow: 0 3px 32px rgba(0, 0, 0, 0.32);
}

.game-stats {
  display: flex;
  align-items: start;
  gap: clamp(28px, 4vw, 68px);
  margin-top: 30px;
}

.game-stat {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.stat-label {
  color: rgba(255, 255, 255, 0.48);
  font-size: 11px;
  font-weight: 400;
  letter-spacing: 0;
}

.game-stat strong {
  color: #fff;
  font-size: 16px;
  font-weight: 300;
}

.game-stat--id strong {
  color: rgba(255, 255, 255, 0.7);
  font-size: 14px;
  font-weight: 300;
  letter-spacing: 0.04em;
}

.primary-action {
  min-height: 42px;
  padding: 0 21px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  border-radius: 999px;
  color: #07101d;
  background: #fff;
  font-size: 13px;
  font-weight: 750;
  box-shadow: 0 10px 34px rgba(0, 0, 0, 0.28);
  transition: transform 180ms var(--ease-out), box-shadow 180ms ease;
}

.primary-action:hover,
.primary-action:focus-visible {
  transform: scale(1.04);
  box-shadow: 0 12px 42px rgba(255, 255, 255, 0.18);
}

.button-symbol {
  font-size: 20px;
  font-weight: 400;
}

.options-scrim {
  position: fixed;
  z-index: 60;
  inset: 0;
  width: 100%;
  height: 100%;
  background: rgba(2, 5, 10, 0.28);
  cursor: default;
}

.action-menu {
  position: fixed;
  z-index: 61;
  width: min(390px, calc(100vw - 40px));
  padding: 8px;
  display: flex;
  flex-direction: column;
  border: 0;
  border-radius: 8px;
  background: rgba(32, 32, 35, 0.98);
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.34);
  backdrop-filter: blur(20px);
}

.action-menu__item {
  min-height: 50px;
  padding: 0 14px;
  display: flex;
  align-items: center;
  gap: 12px;
  border: 1px solid transparent;
  border-radius: 6px;
  text-align: left;
  color: rgba(255, 255, 255, 0.82);
  font-size: 18px;
  font-weight: 350;
  transition: color 120ms ease, background 120ms ease, border-color 120ms ease;
}

.action-menu__item:hover,
.action-menu__item:focus-visible {
  outline: 0;
  color: #fff;
  border-color: rgba(218, 228, 241, 0.58);
  background: rgba(255, 255, 255, 0.045);
}

.action-menu__item--danger {
  color: rgba(255, 181, 184, 0.9);
}

.action-menu__divider {
  height: 1px;
  margin: 5px 14px;
  background: rgba(255, 255, 255, 0.08);
}

.library-rail {
  position: absolute;
  z-index: 6;
  top: clamp(150px, 21vh, 228px);
  left: 0;
  right: 0;
}

.game-track {
  display: flex;
  gap: 14px;
  overflow-x: auto;
  overflow-y: hidden;
  padding: 14px clamp(32px, 5vw, 88px) 30px;
  scroll-padding-left: clamp(32px, 5vw, 88px);
  scroll-snap-type: x proximity;
}

.game-track::-webkit-scrollbar {
  display: none;
}

.add-game-tile {
  width: var(--tile-w);
  height: var(--tile-h);
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  border: 1px dashed rgba(255, 255, 255, 0.16);
  border-radius: var(--tile-radius);
  color: rgba(255, 255, 255, 0.42);
  font-size: 11px;
}

.add-game-tile span {
  font-size: 30px;
  font-weight: 250;
}

.add-game-tile:hover {
  color: #fff;
  border-color: rgba(255, 255, 255, 0.4);
  background: rgba(255, 255, 255, 0.05);
}

.control-hints {
  position: absolute;
  z-index: 8;
  left: clamp(32px, 5vw, 88px);
  right: auto;
  bottom: 22px;
  display: flex;
  align-items: center;
  gap: 22px;
}

.control-hints button {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: #fff;
  font-size: 13px;
  font-weight: 450;
  transition: color 160ms ease;
}

.control-hints button:hover {
  color: #fff;
}

.pad-key {
  width: 17px;
  height: 17px;
  display: inline-grid;
  place-items: center;
  flex: 0 0 auto;
  border-radius: 50%;
  color: #101722;
  background: rgba(255, 255, 255, 0.88);
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.28);
  font-size: 13px;
  font-weight: 650;
  line-height: 1;
}

.pad-key--triangle {
  padding-bottom: 1px;
  font-size: 11px;
}

.pad-key--options {
  background: transparent;
  box-shadow: none;
}

.pad-key--options i {
  width: 6px;
  height: 15px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.9);
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.28);
}

.center-state {
  position: relative;
  z-index: 5;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.state-kicker {
  margin-bottom: 12px;
  color: var(--accent);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.24em;
}

.center-state h1 {
  max-width: 720px;
  font-size: clamp(44px, 6vw, 82px);
  line-height: 0.96;
  letter-spacing: -0.055em;
}

.center-state p {
  margin: 18px 0 28px;
  color: var(--muted);
}

.scan-orbit {
  width: 46px;
  height: 46px;
  margin-bottom: 28px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 900ms linear infinite;
}

.backdrop-enter-active,
.backdrop-leave-active {
  transition: opacity 460ms ease, filter 460ms ease;
}

.backdrop-enter-from {
  opacity: 0;
  filter: blur(12px) saturate(0.8);
}

.backdrop-leave-to {
  opacity: 0;
}

.details-enter-active,
.details-leave-active {
  transition: opacity 240ms ease, transform 340ms var(--ease-out);
}

.details-enter-from {
  opacity: 0;
  transform: translateY(18px);
}

.details-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

.options-scrim-enter-active,
.options-scrim-leave-active {
  transition: opacity 140ms ease;
}

.options-scrim-enter-from,
.options-scrim-leave-to {
  opacity: 0;
}

.options-menu-enter-active,
.options-menu-leave-active {
  transform-origin: top left;
  transition: opacity 140ms ease, transform 180ms var(--ease-out);
}

.options-menu-enter-from,
.options-menu-leave-to {
  opacity: 0;
  transform: translateY(-6px) scale(0.985);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

@media (max-height: 760px) {
  .game-details {
    top: 425px;
  }

  .game-details h1 {
    font-size: clamp(32px, 3.2vw, 46px);
  }

  .library-rail {
    top: 138px;
  }

  .game-stats {
    margin-top: 20px;
  }

}

@media (max-width: 760px) {
  .game-details {
    width: calc(100vw - 56px);
    left: 28px;
    top: 58vh;
  }

  .game-details h1 {
    font-size: 34px;
  }

  .backdrop {
    width: 100%;
    height: 100%;
    object-position: center;
  }

  .backdrop--cover-fallback {
    height: 72%;
    object-fit: contain;
    object-position: center top;
    -webkit-mask-image: linear-gradient(to bottom, #000 0%, rgba(0, 0, 0, 0.65) 48%, transparent 78%);
    mask-image: linear-gradient(to bottom, #000 0%, rgba(0, 0, 0, 0.65) 48%, transparent 78%);
  }

  .atmosphere {
    background:
      linear-gradient(rgba(3, 6, 12, 0.42), rgba(3, 6, 12, 0.42)),
      linear-gradient(0deg, #060912 0%, rgba(6, 9, 18, 0.82) 62%, rgba(6, 9, 18, 0.45) 100%);
  }

  .control-hints {
    display: none;
  }

  .game-stats {
    gap: 20px;
    overflow: hidden;
  }

  .game-stat--id {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .backdrop-enter-active,
  .backdrop-leave-active,
  .details-enter-active,
  .details-leave-active {
    transition-duration: 1ms;
  }
}
</style>
