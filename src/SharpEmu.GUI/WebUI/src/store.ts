import { reactive, computed, readonly } from 'vue'
import {
  onLibrary,
  onBackground,
  onLocalization,
  onLogBatch,
  onRecent,
  onScanning,
  onSession,
  onSettings,
  send,
} from './bridge'
import type {
  GameEntry,
  LocalizationBundle,
  LogLine,
  SessionState,
  Settings,
} from './types'

/**
 * The single source of truth for the launcher UI. Subscribes to host events
 * once at startup and exposes reactive state the views bind to. All mutations
 * come from the bridge — the views only read (and send commands back).
 */
const state = reactive({
  games: [] as GameEntry[],
  recent: [] as GameEntry[],
  lastPlayed: null as GameEntry | null,
  settings: null as Settings | null,
  localization: { code: 'en', strings: {} } as LocalizationBundle,
  session: {
    isRunning: false,
    isStopping: false,
    title: null,
    exitCode: null,
  } as SessionState,
  scanning: false,
  log: [] as LogLine[],
  /** Full-size pic0/pic1 key art, loaded lazily for selected games. */
  backgrounds: {} as Record<string, string | null>,
  /** Active view: 'library' | 'options' | 'console'. */
  view: 'library' as 'library' | 'options' | 'console',
})

// Cap the in-memory log so a long, noisy session cannot exhaust memory.
const MAX_LOG_LINES = 5000

// The C# bridge wraps each push's data in a named-field object (e.g.
// { isScanning: true }); unpack it here so the reactive state gets the raw
// value, not the wrapper.
onLibrary((p: any) => {
  state.games = p.games ?? []
})

onRecent((p: any) => {
  state.recent = p.games ?? []
  state.lastPlayed = p.lastPlayed ?? null
})

onSettings((p: any) => {
  state.settings = p
})

onLocalization((p: any) => {
  state.localization = { code: p.code ?? 'en', strings: p.strings ?? {} }
})

onSession((p: any) => {
  state.session = p
})

onScanning((p: any) => {
  state.scanning = p?.isScanning === true
})

onBackground((p: any) => {
  const ebootPath = p?.ebootPath
  if (typeof ebootPath === 'string') {
    state.backgrounds[ebootPath] = p?.backgroundDataUri ?? null
  }
})

onLogBatch((p: any) => {
  const lines: LogLine[] = p?.lines ?? []
  state.log.push(...lines)
  if (state.log.length > MAX_LOG_LINES) {
    state.log.splice(0, state.log.length - MAX_LOG_LINES)
  }
})

/** Translate a localization key; falls back to the key itself if missing. */
export function t(key: string, ...args: (string | number)[]): string {
  let s = state.localization.strings[key] ?? key
  if (args.length > 0) {
    s = s.replace(/\{(\d+)\}/g, (_, i: string) => String(args[Number(i)] ?? ''))
  }
  return s
}

/** Filtered games for the library view, driven by the search box. */
const searchText = reactive({ value: '' })

export const filteredGames = computed<GameEntry[]>(() => {
  const q = searchText.value.trim().toLowerCase()
  if (!q) return state.games
  return state.games.filter(
    (g) =>
      g.name.toLowerCase().includes(q) ||
      g.ebootPath.toLowerCase().includes(q) ||
      (g.titleId?.toLowerCase().includes(q) ?? false),
  )
})

export function setSearch(q: string): void {
  searchText.value = q
  send({ type: 'searchLibrary', query: q })
}

const requestedBackgrounds = new Set<string>()

export function requestBackground(game: GameEntry): void {
  if (game.hasBackground !== true || requestedBackgrounds.has(game.ebootPath)) {
    return
  }

  requestedBackgrounds.add(game.ebootPath)
  send({ type: 'requestBackground', ebootPath: game.ebootPath })
}

export function setView(view: 'library' | 'options' | 'console'): void {
  state.view = view
}

export function useStore() {
  return {
    state: readonly(state),
    t,
    filteredGames,
    setSearch,
    setView,
  }
}
