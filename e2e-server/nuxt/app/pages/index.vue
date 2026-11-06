<script setup lang="ts">
import debounce from 'lodash/debounce';
const q = ref('');
const onInput = debounce((e: Event) => { q.value = (e.target as HTMLInputElement).value; }, 200);
const { data } = await useFetch('/api/status');
</script>
<template>
  <main><div v-html="data?.html" /><input @input="onInput" placeholder="Filter services"><p>{{ q }}</p></main>
</template>
