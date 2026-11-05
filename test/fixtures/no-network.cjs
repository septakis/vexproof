// Preloaded with NODE_OPTIONS=--require in tests: every fetch fails at once, as on a runner without network.
globalThis.fetch = async (url) => { throw new Error(`fetch failed: no network (${url})`); };
