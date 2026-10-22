// Helpers shared by the two Azure sources.
const isGov = (text, config) => (config.govMarkers || []).some((m) => text.toLowerCase().includes(m.toLowerCase()));
const isEntra = (text) => /\b(Microsoft Entra(?: ID)?|Entra ID|Azure Active Directory|Azure AD)\b/i.test(text);
const isGcc = (text) => /\bGCC(?: High)?\b|Government Community Cloud/i.test(text);
module.exports = { isGov, isEntra, isGcc };
