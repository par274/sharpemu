<script setup lang="ts">
// A label + description row with a slot on the right for the control
// (toggle, select, number input). Mirrors the C# SettingRow control.
defineProps<{
  label: string
  description?: string
  mono?: boolean
}>()
</script>

<template>
  <div class="row">
    <div class="text">
      <span class="label" :class="{ mono }">{{ label }}</span>
      <span v-if="description" class="desc">{{ description }}</span>
    </div>
    <div class="slot">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  min-height: 40px;
}
.text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  min-width: 0;
}
.label {
  font-size: 13px;
  color: var(--text);
}
.label.mono {
  font-family: 'Cascadia Mono', Consolas, monospace;
  font-size: 12px;
}
.desc {
  font-size: 11px;
  color: var(--muted);
  white-space: pre-line;
  line-height: 1.4;
}
.slot {
  flex-shrink: 0;
}
</style>
