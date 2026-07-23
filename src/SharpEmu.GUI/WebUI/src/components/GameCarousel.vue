<script setup lang="ts">
import type { GameEntry } from '../types'
import GameTile from './GameTile.vue'

defineProps<{
  games: readonly GameEntry[]
  selectedPath: string | null
  label: string
}>()

const emit = defineEmits<{ select: [game: GameEntry] }>()
</script>

<template>
  <section v-if="games.length > 0" class="row">
    <h2 class="row-label">{{ label }}</h2>
    <div class="track">
      <GameTile
        v-for="game in games"
        :key="game.ebootPath"
        :game="game"
        :selected="game.ebootPath === selectedPath"
        @select="emit('select', $event)"
      />
    </div>
  </section>
</template>

<style scoped>
.row {
  margin-bottom: 8px;
}
.track {
  display: flex;
  gap: 16px;
  overflow-x: auto;
  overflow-y: hidden;
  padding: 6px 2px 14px;
  scroll-snap-type: x proximity;
}
.track > * {
  scroll-snap-align: start;
}
.track::-webkit-scrollbar {
  height: 6px;
}
</style>
