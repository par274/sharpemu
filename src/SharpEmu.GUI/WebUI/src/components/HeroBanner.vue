<script setup lang="ts">
import type { GameEntry } from '../types'
import { send } from '../bridge'
import { useStore } from '../store'

defineProps<{ game: GameEntry | null }>()
const { t } = useStore()

function resume(game: GameEntry) {
  send({ type: 'launch', ebootPath: game.ebootPath })
}
</script>

<template>
  <section v-if="game" class="hero" @click="resume(game)">
    <img v-if="game.coverDataUri" :src="game.coverDataUri" class="hero-art" :alt="game.name" />
    <div class="hero-scrim" />
    <div class="hero-text">
      <span class="eyebrow">{{ t('Library.Hero.JumpBackIn') }}</span>
      <h1 class="title">{{ game.name }}</h1>
      <div class="meta">
        <span v-if="game.lastPlayedText" class="last-played">{{ game.lastPlayedText }}</span>
        <button class="btn btn--accent" @click.stop="resume(game)">
          {{ t('Library.Hero.Resume') }}
        </button>
      </div>
    </div>
  </section>

  <!-- Empty hero: first-run welcome so the top of the library is not bare. -->
  <section v-else class="hero hero--empty">
    <div class="hero-text">
      <h1 class="title">{{ t('Library.Hero.NoRecent') }}</h1>
      <p class="hint">{{ t('Library.Hero.NoRecentHint') }}</p>
    </div>
  </section>
</template>

<style scoped>
.hero {
  height: var(--hero-h);
  border-radius: var(--radius-lg);
  overflow: hidden;
  position: relative;
  box-shadow: var(--shadow-hero);
  cursor: pointer;
  flex-shrink: 0;
  transition: box-shadow 0.3s ease;
}
.hero:hover {
  box-shadow: var(--shadow-hero), 0 0 0 1px var(--border-strong);
}
.hero-art {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.hero-scrim {
  position: absolute;
  inset: 0;
  background:
    linear-gradient(to right, rgba(5, 5, 7, 0.85) 0%, transparent 55%),
    linear-gradient(to bottom, rgba(5, 5, 7, 0.2) 30%, rgba(5, 5, 7, 0.95) 100%);
}
.hero-text {
  position: absolute;
  left: var(--space-10);
  right: var(--space-10);
  bottom: var(--space-10);
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  max-width: 640px;
}
.eyebrow {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 3px;
  color: var(--text-secondary);
  text-transform: uppercase;
}
.title {
  font-size: 48px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: #fff;
  line-height: 1.05;
  text-shadow: 0 2px 24px rgba(0, 0, 0, 0.5);
}
.meta {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  margin-top: var(--space-2);
}
.last-played {
  font-size: 13px;
  color: var(--text-secondary);
}

.hero--empty {
  height: 220px;
  background: var(--bg-raised);
  border: 1px solid var(--border);
  cursor: default;
  display: flex;
  align-items: center;
  justify-content: center;
}
.hero--empty .hero-text {
  position: static;
  max-width: none;
  text-align: center;
  align-items: center;
}
.hero--empty .title {
  font-size: 30px;
  text-shadow: none;
}
.hint {
  font-size: 14px;
  color: var(--muted);
}
</style>
