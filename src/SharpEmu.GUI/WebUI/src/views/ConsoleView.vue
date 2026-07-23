<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useStore } from '../store'
import { send } from '../bridge'

const { state, t } = useStore()

const search = ref('')
const autoscroll = ref(true)
const linesEl = ref<HTMLDivElement | null>(null)

// Filter happens client-side against the buffered lines; the C# ring buffer
// holds the authoritative copy, this is just a view over the pushed batch.
const visibleLines = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q)
  {
    return state.log
  }

  return state.log.filter((l) => l.text.toLowerCase().includes(q))
})

// Auto-scroll to the bottom whenever new lines arrive (and autoscroll is on).
watch(
  () => state.log.length,
  async () => {
    if (!autoscroll.value)
    {
      return
    }

    await nextTick()
    const el = linesEl.value
    if (el)
    {
      el.scrollTop = el.scrollHeight
    }
  },
)
</script>

<template>
  <div class="console">
    <div class="console-head">
      <span class="section-title">{{ t('Console.Title') }}</span>
      <input
        class="search-field console-search"
        type="text"
        :placeholder="t('Console.SearchWatermark')"
        v-model="search"
      />
      <label class="autoscroll">
        <input type="checkbox" v-model="autoscroll" /> {{ t('Console.AutoScroll') }}
      </label>
      <div class="actions">
        <button class="btn btn--ghost sm" @click="send({ type: 'detachConsole' })">{{ t('Console.Split') }}</button>
        <button class="btn btn--ghost sm" @click="send({ type: 'copyLog' })">{{ t('Console.Copy') }}</button>
        <button class="btn btn--ghost sm" @click="send({ type: 'clearLog' })">{{ t('Console.Clear') }}</button>
      </div>
    </div>
    <div class="lines" ref="linesEl">
      <div
        v-for="(line, i) in visibleLines"
        :key="i"
        class="line"
        :class="{ err: line.isError }"
      >
        {{ line.text }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.console {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  background: rgba(11, 15, 23, 0.78);
  border: 1px solid var(--border);
  border-radius: 20px;
  overflow: hidden;
}
.console-head {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}
.console-search {
  width: 320px;
  font-size: 12px;
  padding: 7px 12px;
}
.autoscroll {
  font-size: 12px;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.actions {
  margin-left: auto;
  display: flex;
  gap: var(--space-2);
}
.btn.sm {
  padding: 6px 12px;
  font-size: 12px;
}
.lines {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-2) var(--space-3);
  font-family: 'Cascadia Mono', Consolas, monospace;
  font-size: 12px;
  background: rgba(3, 5, 9, 0.84);
  line-height: 1.5;
}
.line {
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-secondary);
}
.line.err {
  color: var(--danger);
}
</style>
