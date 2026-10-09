// Betrieb unter einem Unterpfad (z. B. https://host/netasset/): Vite setzt
// import.meta.env.BASE_URL beim Build aus VITE_BASE. Die API-Aufrufe im Code
// sind absolut (/api, /auth) – statt jede Stelle anzupassen, präfixt ein
// fetch-Wrapper sie zentral. Ohne VITE_BASE (BASE_URL = '/') ändert sich nichts.

export const BASE_PATH = import.meta.env.BASE_URL.replace(/\/$/, '')

export const withBase = (path: string) => BASE_PATH + path

const API_PATH = /^\/(api|auth|health)(\/|\?|$)/

export function installFetchBase() {
  if (!BASE_PATH) return
  const orig = window.fetch.bind(window)
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) =>
    orig(typeof input === 'string' && API_PATH.test(input) ? BASE_PATH + input : input, init)
}
