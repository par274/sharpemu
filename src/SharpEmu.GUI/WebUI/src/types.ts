// Mirrors the C# DTOs serialized by LauncherBridge. Kept in sync by contract —
// a field renamed on the C# side must be renamed here too.

/** A scanned game, pushed from C# after a library scan. */
export interface GameEntry {
  /** Absolute eboot.bin path — the stable identity of a game. */
  ebootPath: string
  name: string
  titleId: string | null
  version: string | null
  /** Formatted install size, e.g. "12.4 GiB". */
  sizeText: string
  /** Cover art as a data URI ("data:image/png;base64,...") or null. */
  coverDataUri: string | null
  /** Whether full-size key art (pic0/pic1) can be requested lazily. */
  hasBackground?: boolean
  /** Last-played relative label, e.g. "Played 2h ago". Null if never played. */
  lastPlayedText: string | null
  hasPlayed: boolean
}

/** The whole settings block, round-tripped between Vue and ISettingsService. */
export interface Settings {
  logLevel: string
  importTraceLimit: number
  renderResolutionScale: number
  strictDynlibResolution: boolean
  logToFile: boolean
  logFilePath: string | null
  overrideLogFile: boolean
  playTitleMusic: boolean
  discordRichPresence: boolean
  checkForUpdatesOnStartup: boolean
  language: string
  environmentToggles: string[]
}

/** A single localized string dictionary + its code. */
export interface LocalizationBundle {
  code: string
  strings: Record<string, string>
}

/** One log line pushed from the emulator output stream. */
export interface LogLine {
  text: string
  isError: boolean
}

/** Running-session state pushed while a game is active. */
export interface SessionState {
  isRunning: boolean
  isStopping: boolean
  title: string | null
  exitCode: number | null
}
