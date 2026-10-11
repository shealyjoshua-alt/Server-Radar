// Helpers shared by the two Azure sources.
const isGov = (text, config) => (config.govMarkers || []).some((m) => text.toLowerCase().includes(m.toLowerCase()));
module.exports = { isGov };
