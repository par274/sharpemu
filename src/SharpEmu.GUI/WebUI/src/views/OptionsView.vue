<script setup lang="ts">
import { computed } from 'vue'
import { useStore } from '../store'
import { send } from '../bridge'
import SettingRow from '../components/SettingRow.vue'
import type { Settings } from '../types'

const { state, t } = useStore()

// A writable copy of settings so v-model works without mutating the readonly
// store directly. Every change is pushed to C# via setSettings.
const s = computed(() => state.settings)

function patch(partial: Partial<Settings>) {
  send({ type: 'setSettings', settings: partial })
}

// --- Log level / render scale map to indexes the C# side expects ---
const logLevels = [
  { idx: 0, key: 'Options.LogLevel.Trace' },
  { idx: 1, key: 'Options.LogLevel.Debug' },
  { idx: 2, key: 'Options.LogLevel.Info' },
  { idx: 3, key: 'Options.LogLevel.Warning' },
  { idx: 4, key: 'Options.LogLevel.Error' },
  { idx: 5, key: 'Options.LogLevel.Critical' },
]
function logLevelIndex(name: string): number {
  return logLevels.find((l) => l.key.endsWith(name.toLowerCase()))?.idx ?? 2
}
function onLogLevel(ev: Event) {
  const idx = Number((ev.target as HTMLSelectElement).value)
  patch({ logLevel: ['trace', 'debug', 'info', 'warning', 'error', 'critical'][idx] })
}

const renderScales = [1.0, 0.75, 0.5, 0.25]
function renderScaleIndex(scale: number): number {
  return renderScales.findIndex((v) => Math.abs(v - scale) < 0.01)
}
function onRenderScale(ev: Event) {
  patch({ renderResolutionScale: renderScales[Number((ev.target as HTMLSelectElement).value)] })
}

// --- Environment toggles (each is a named SHARPEMU_* switch) ---
const envToggles = [
  { name: 'SHARPEMU_BTHID_UNAVAILABLE', descKey: 'Options.Env.Bthid.Desc' },
  { name: 'SHARPEMU_DISABLE_IMPORT_LOOP_GUARD', descKey: 'Options.Env.LoopGuard.Desc' },
  { name: 'SHARPEMU_WRITABLE_APP0', descKey: 'Options.Env.WritableApp0.Desc' },
  { name: 'SHARPEMU_VK_VALIDATION', descKey: 'Options.Env.VkValidation.Desc' },
  { name: 'SHARPEMU_DUMP_SPIRV', descKey: 'Options.Env.DumpSpirv.Desc' },
  { name: 'SHARPEMU_LOG_DIRECT_MEMORY', descKey: 'Options.Env.LogDirectMemory.Desc' },
  { name: 'SHARPEMU_LOG_IO', descKey: 'Options.Env.LogIo.Desc' },
  { name: 'SHARPEMU_LOG_NP', descKey: 'Options.Env.LogNp.Desc' },
]
function envOn(name: string): boolean {
  return s.value?.environmentToggles.includes(name) ?? false
}
function toggleEnv(name: string) {
  // The C# side owns the persistent toggles list and re-pushes settings.
  send({ type: 'toggleEnv', name, enabled: !envOn(name) })
}
</script>

<template>
  <div v-if="s" class="options">
    <!-- EMULATION -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.Section.Emulation') }}</h3>
      <SettingRow :label="t('Options.CpuEngine.Label')" :description="t('Options.CpuEngine.Desc')">
        <select class="select" disabled>
          <option>{{ t('Options.CpuEngine.Native') }}</option>
        </select>
      </SettingRow>
      <SettingRow :label="t('Options.Strict.Label')" :description="t('Options.Strict.Desc')">
        <button class="switch" :class="{ on: s.strictDynlibResolution }"
                @click="patch({ strictDynlibResolution: !s.strictDynlibResolution })" />
      </SettingRow>
    </section>

    <!-- LOGGING -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.Section.Logging') }}</h3>
      <SettingRow :label="t('Options.LogLevel.Label')" :description="t('Options.LogLevel.Desc')">
        <select class="select" :value="logLevelIndex(s.logLevel)" @change="onLogLevel">
          <option v-for="l in logLevels" :key="l.idx" :value="l.idx">{{ t(l.key) }}</option>
        </select>
      </SettingRow>
      <SettingRow :label="t('Options.TraceImports.Label')" :description="t('Options.TraceImports.Desc')">
        <div class="num-input">
          <button @click="patch({ importTraceLimit: Math.max(0, s.importTraceLimit - 16) })">−</button>
          <input type="number" min="0" max="4096" :value="s.importTraceLimit" readonly />
          <button @click="patch({ importTraceLimit: Math.min(4096, s.importTraceLimit + 16) })">+</button>
        </div>
      </SettingRow>
      <SettingRow :label="t('Options.LogToFile.Label')" :description="t('Options.LogToFile.Desc')">
        <button class="switch" :class="{ on: s.logToFile }"
                @click="patch({ logToFile: !s.logToFile })" />
      </SettingRow>
      <SettingRow :label="t('Options.LogFilePath.Label')" :description="s.logFilePath || t('Options.LogFilePath.Default')">
        <button class="btn btn--ghost" @click="send({ type: 'selectLogFilePath' })">
          {{ t('Options.LogFilePath.Select') }}
        </button>
      </SettingRow>
      <SettingRow :label="t('Options.OverrideLogFile.Label')" :description="t('Options.OverrideLogFile.Desc')">
        <button class="switch" :class="{ on: s.overrideLogFile }"
                @click="patch({ overrideLogFile: !s.overrideLogFile })" />
      </SettingRow>
    </section>

    <!-- LAUNCHER -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.Section.Launcher') }}</h3>
      <SettingRow :label="t('Options.Language.Label')" :description="t('Options.Language.Desc')">
        <select class="select" :value="s.language" @change="patch({ language: ($event.target as HTMLSelectElement).value })">
          <option v-for="lang in state.localization.code ? [{ c: 'en', n: 'English' }] : []" :key="lang.c" :value="lang.c">{{ lang.n }}</option>
        </select>
      </SettingRow>
      <SettingRow :label="t('Options.TitleMusic.Label')" :description="t('Options.TitleMusic.Desc')">
        <button class="switch" :class="{ on: s.playTitleMusic }"
                @click="patch({ playTitleMusic: !s.playTitleMusic })" />
      </SettingRow>
      <SettingRow :label="t('Options.Discord.Label')" :description="t('Options.Discord.Desc')">
        <button class="switch" :class="{ on: s.discordRichPresence }"
                @click="patch({ discordRichPresence: !s.discordRichPresence })" />
      </SettingRow>
      <SettingRow :label="t('Updater.Auto.Label')" :description="t('Updater.Auto.Desc')">
        <button class="switch" :class="{ on: s.checkForUpdatesOnStartup }"
                @click="patch({ checkForUpdatesOnStartup: !s.checkForUpdatesOnStartup })" />
      </SettingRow>
    </section>

    <!-- GRAPHICS -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.Graphics.Rendering') }}</h3>
      <SettingRow :label="t('Options.RenderResolution.Label')" :description="t('Options.RenderResolution.Desc')">
        <select class="select" :value="renderScaleIndex(s.renderResolutionScale)" @change="onRenderScale">
          <option value="0">100% (native)</option>
          <option value="1">75%</option>
          <option value="2">50%</option>
          <option value="3">25%</option>
        </select>
      </SettingRow>
    </section>

    <!-- ENVIRONMENT -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.Section.Environment') }}</h3>
      <p class="env-intro">{{ t('Options.Env.Desc') }}</p>
      <SettingRow
        v-for="env in envToggles"
        :key="env.name"
        mono
        :label="env.name"
        :description="t(env.descKey)"
      >
        <button class="switch" :class="{ on: envOn(env.name) }" @click="toggleEnv(env.name)" />
      </SettingRow>
    </section>

    <!-- ABOUT -->
    <section class="card">
      <h3 class="section-title">{{ t('Options.About') }}</h3>
      <div class="about-row">
        <div>
          <div class="about-label">{{ t('Updater.Label') }}</div>
          <div class="about-desc">{{ t('Updater.Status.Ready', 'dev') }}</div>
        </div>
        <button class="btn btn--ghost" @click="send({ type: 'checkUpdates' })">{{ t('Updater.Check') }}</button>
      </div>
      <div class="about-row">
        <div>
          <div class="about-label">{{ t('About.Github.Label') }}</div>
          <div class="about-desc">{{ t('About.Github.Desc') }}</div>
        </div>
        <button class="btn btn--ghost" @click="send({ type: 'openExternal', url: 'https://github.com/sharpemu/sharpemu' })">{{ t('About.GithubButton') }}</button>
      </div>
      <div class="about-row">
        <div>
          <div class="about-label">{{ t('About.Discord.Label') }}</div>
          <div class="about-desc">{{ t('About.Discord.Desc') }}</div>
        </div>
        <button class="btn btn--ghost" @click="send({ type: 'openExternal', url: 'https://discord.com/invite/6GejPEDqpc' })">{{ t('About.DiscordButton') }}</button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.options {
  display: flex;
  flex-direction: column;
  max-width: 1040px;
  border-radius: 22px;
  background: rgba(255, 255, 255, 0.025);
  backdrop-filter: blur(18px);
}
.env-intro {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.4;
  margin-bottom: 4px;
}
.about-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}
.about-label {
  font-size: 13px;
  color: var(--text);
}
.about-desc {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.4;
  margin-top: 2px;
}
</style>
