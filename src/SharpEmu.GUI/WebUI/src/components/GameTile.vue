<script setup lang="ts">
import { computed } from 'vue'
import type { GameEntry } from '../types'
import { send } from '../bridge'

const props = defineProps<{ game: GameEntry; selected: boolean }>()
const emit = defineEmits<{ select: [game: GameEntry] }>()

const initials = computed(() => {
  const words = props.game.name.split(/\s+/).filter((word) => /[a-z0-9]/i.test(word[0] ?? ''))
  return words.slice(0, 2).map((word) => word[0]!.toUpperCase()).join('') || '?'
})

function select() {
  emit('select', props.game)
}
</script>

<template>
  <button
    class="game-tile"
    :class="{ 'is-selected': selected }"
    :title="game.name"
    @click="select"
    @focus="select"
    @dblclick="send({ type: 'launch', ebootPath: game.ebootPath })"
  >
    <div class="cover">
      <img v-if="game.coverDataUri" :src="game.coverDataUri" :alt="game.name" />
      <div v-else class="placeholder">
        <span>{{ initials }}</span>
      </div>
      <span v-if="game.hasPlayed" class="played-mark" title="Played before" />
    </div>
  </button>
</template>

<style scoped>
.game-tile {
  width: var(--tile-w);
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  scroll-snap-align: start;
  text-align: left;
  opacity: 0.68;
  transition: opacity 180ms ease, transform 260ms var(--ease-out);
}

.cover {
  position: relative;
  width: 100%;
  height: var(--tile-h);
  overflow: hidden;
  border-radius: var(--tile-radius);
  background: #151925;
  box-shadow: 0 12px 28px rgba(0, 0, 0, 0.38);
  transition: box-shadow 220ms ease, outline-color 220ms ease;
}

.cover::after {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: inherit;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.08);
  pointer-events: none;
}

.cover img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  transition: transform 420ms var(--ease-out), filter 220ms ease;
}

.placeholder {
  width: 100%;
  height: 100%;
  display: grid;
  place-items: center;
  color: rgba(255, 255, 255, 0.48);
  background:
    radial-gradient(circle at 70% 20%, rgba(75, 112, 181, 0.52), transparent 34%),
    linear-gradient(145deg, #1b2941, #0b0f18);
}

.placeholder span {
  font-size: 38px;
  font-weight: 300;
  letter-spacing: -0.06em;
}

.played-mark {
  position: absolute;
  right: 9px;
  top: 9px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 3px rgba(7, 12, 21, 0.55);
}

.game-tile:hover,
.game-tile:focus-visible,
.game-tile.is-selected {
  opacity: 1;
  outline: none;
  transform: translateY(-6px);
}

.game-tile:hover .cover,
.game-tile:focus-visible .cover,
.game-tile.is-selected .cover {
  box-shadow:
    0 18px 36px rgba(0, 0, 0, 0.5),
    0 0 0 3px #fff;
}

.game-tile:hover .cover img,
.game-tile.is-selected .cover img {
  transform: scale(1.035);
}

</style>
