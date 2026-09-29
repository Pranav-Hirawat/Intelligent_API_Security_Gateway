export function normalizeStoredAdaptive(config) {
  if (!config || typeof config !== "object" || !config.risk || typeof config.risk !== "object") {
    return config;
  }
  // `ml_weight` belonged to the retired ML scorer. Older Postgres volumes
  // retain it, and the settings form must not submit it again while the
  // decision engine is completing its durable-row migration.
  const { ml_weight, ...risk } = config.risk;
  if (ml_weight === undefined) return config;
  return { ...config, risk };
}
