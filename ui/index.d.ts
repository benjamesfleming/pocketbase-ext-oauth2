import type { ToastStore } from "./lib/toast-store";

export declare global {
    interface Window {
        PocketBase: typeof import('pocketbase').default;
        Alpine: typeof import('alpinejs');
    }
}

declare module 'alpinejs' {
  namespace Alpine {
    interface Stores {
      toast: ToastStore;
    }
  }
}