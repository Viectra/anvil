export interface KeyboardHandlers {
  focusSearch: () => void;
  newItem: () => void;
  copyPassword: () => void;
  copyUsername: () => void;
  copyTotp: () => void;
  lockVault: () => void;
  openGenerator: () => void;
  moveSelection: (delta: -1 | 1) => void;
  activateSelection: () => void;
  escape: () => void;
}

/** Installs global keyboard-first bindings matching the desktop & extension shortcut map. */
export function registerKeyboardShortcuts(
  win: Window,
  handlers: KeyboardHandlers,
): () => void {
  const onKeyDown = (event: KeyboardEvent) => {
    const mod = event.ctrlKey || event.metaKey;
    const key = event.key.toLowerCase();

    if (mod && !event.shiftKey && key === "k") {
      event.preventDefault();
      handlers.focusSearch();
      return;
    }
    if (mod && !event.shiftKey && key === "n") {
      event.preventDefault();
      handlers.newItem();
      return;
    }
    if (mod && !event.shiftKey && key === "l") {
      event.preventDefault();
      handlers.lockVault();
      return;
    }
    if (mod && event.shiftKey && key === "c") {
      event.preventDefault();
      handlers.copyPassword();
      return;
    }
    if (mod && event.shiftKey && key === "u") {
      event.preventDefault();
      handlers.copyUsername();
      return;
    }
    if (mod && event.shiftKey && key === "t") {
      event.preventDefault();
      handlers.copyTotp();
      return;
    }
    if (mod && event.shiftKey && key === "g") {
      event.preventDefault();
      handlers.openGenerator();
      return;
    }
    if (event.key === "Escape") {
      handlers.escape();
      return;
    }

    const target = event.target as HTMLElement | null;
    const isInput =
      target !== null &&
      (target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable);
    const isSearchInput = target?.dataset.anvilSearch === "true";

    if (isInput && !isSearchInput) {
      return;
    }

    if (event.key === "ArrowDown") {
      event.preventDefault();
      handlers.moveSelection(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      handlers.moveSelection(-1);
    } else if (event.key === "Enter" && !isInput) {
      handlers.activateSelection();
    }
  };

  win.addEventListener("keydown", onKeyDown);
  return () => win.removeEventListener("keydown", onKeyDown);
}
