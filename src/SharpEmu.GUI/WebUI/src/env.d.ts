/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>
  export default component
}

// The host bridge functions injected by Avalonia NativeWebView.
interface Window {
  /** Called from JS to push a command into C# (NativeWebView built-in). */
  invokeCSharpAction?(json: string): void
}
interface GlobalThis {
  invokeCSharpAction?(json: string): void
}
