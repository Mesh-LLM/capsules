/// <reference types="vite/client" />

// A module bundled on its own as one script, as text (vite.config.ts `inlineIife`).
declare module '*?iife' {
  const code: string
  export default code
}
