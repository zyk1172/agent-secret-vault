export interface StatusBarState {
  connected: boolean;
  locked: boolean;
}

export function updateStatusBar(element: HTMLElement, state: StatusBarState): void {
  const connection = state.connected ? "connected" : "not connected";
  const lock = state.locked ? "locked" : "unlocked";
  element.textContent = `ASV: ${connection}, ${lock}`;
}
