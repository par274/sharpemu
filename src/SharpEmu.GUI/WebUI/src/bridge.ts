// The single channel between the Vue frontend and the C# LauncherBridge.
//
// JS → C#: every action is a JSON message sent via invokeCSharpAction(), the
//         built-in NativeWebView bridge function. The C# side routes by `type`.
//
// C# → JS: the host calls window.__sharpemu.receive(event, payload) (registered
//         below), which dispatches to subscribers. This avoids polling.

import type {
  GameEntry,
  LocalizationBundle,
  LogLine,
  SessionState,
  Settings,
} from './types'

/** Command types the frontend can send to C#. Keep in sync with LauncherBridge. */
export type Command =
  | { type: 'launch'; ebootPath: string }
  | { type: 'stop' }
  | { type: 'rescan' }
  | { type: 'addFolder' }
  | { type: 'openFile' }
  | { type: 'removeGame'; ebootPath: string }
  | { type: 'openGameFolder'; ebootPath: string }
  | { type: 'copyToClipboard'; text: string }
  | { type: 'gameSettings'; ebootPath: string }
  | { type: 'setSettings'; settings: Partial<Settings> }
  | { type: 'openExternal'; url: string }
  | { type: 'selectLogFilePath' }
  | { type: 'toggleEnv'; name: string; enabled: boolean }
  | { type: 'clearLog' }
  | { type: 'copyLog' }
  | { type: 'detachConsole' }
  | { type: 'checkUpdates' }
  | { type: 'searchLibrary'; query: string }
  | { type: 'requestBackground'; ebootPath: string }
  | { type: 'navigate'; direction: 'left' | 'right' | 'up' | 'down' }
  | { type: 'requestState' }

/** Events C# pushes into the frontend. */
export type BridgeEvent =
  | { event: 'library'; games: GameEntry[] }
  | { event: 'recent'; games: GameEntry[]; lastPlayed: GameEntry | null }
  | { event: 'settings'; settings: Settings }
  | { event: 'localization'; bundle: LocalizationBundle }
  | { event: 'log'; line: LogLine }
  | { event: 'logBatch'; lines: LogLine[] }
  | { event: 'session'; state: SessionState }
  | { event: 'scanning'; isScanning: boolean }
  | { event: 'background'; ebootPath: string; backgroundDataUri: string | null }

type Listener = (payload: any) => void

const listeners = new Map<string, Set<Listener>>()

// Register the global receive hook the C# host calls via InvokeScript.
;(globalThis as any).__sharpemu ??= {}
;(globalThis as any).__sharpemu.receive = (event: string, payload: unknown) => {
  const subs = listeners.get(event)
  if (subs) {
    for (const fn of subs) {
      try {
        fn(payload)
      } catch (err) {
        console.error(`[bridge] listener for "${event}" threw`, err)
      }
    }
  }
}

/** Send a command to C#. Silently ignored if the host bridge is unavailable
 *  (e.g. when running under `vite dev` in a plain browser). */
export function send(command: Command): void {
  const invoke = (globalThis as any).invokeCSharpAction
  if (typeof invoke === 'function') {
    invoke(JSON.stringify(command))
  } else {
    // Dev-mode fallback: log so the dev console shows what would be sent.
    console.debug('[bridge] (no host) →', command)
  }
}

/** Subscribe to a host-pushed event. Returns an unsubscribe function. */
export function on<T>(
  event:
    | 'library'
    | 'recent'
    | 'settings'
    | 'localization'
    | 'log'
    | 'logBatch'
    | 'session'
    | 'scanning'
    | 'background',
  cb: (payload: T) => void,
): () => void {
  let subs = listeners.get(event)
  if (!subs) {
    subs = new Set()
    listeners.set(event, subs)
  }
  subs.add(cb as Listener)
  return () => subs!.delete(cb as Listener)
}

/** Convenience wrappers for the most common events. */
export const onLibrary = (cb: (games: GameEntry[]) => void) => on<GameEntry[]>('library', cb)
export const onRecent = (cb: (r: { games: GameEntry[]; lastPlayed: GameEntry | null }) => void) =>
  on<{ games: GameEntry[]; lastPlayed: GameEntry | null }>('recent', cb)
export const onSettings = (cb: (s: Settings) => void) => on<Settings>('settings', cb)
export const onLocalization = (cb: (b: LocalizationBundle) => void) =>
  on<LocalizationBundle>('localization', cb)
export const onLog = (cb: (l: LogLine) => void) => on<LogLine>('log', cb)
export const onLogBatch = (cb: (l: LogLine[]) => void) => on<LogLine[]>('logBatch', cb)
export const onSession = (cb: (s: SessionState) => void) => on<SessionState>('session', cb)
export const onScanning = (cb: (isScanning: boolean) => void) => on<boolean>('scanning', cb)
export const onBackground = (
  cb: (b: { ebootPath: string; backgroundDataUri: string | null }) => void,
) => on<{ ebootPath: string; backgroundDataUri: string | null }>('background', cb)
