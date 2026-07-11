# Menu Bar Extra Design

## Goal

Keep Agent Secret Vault running from the macOS menu bar after the main window
is closed. The menu bar presents a compact, fully functional version of the
workbench while the existing main-window UI remains unchanged.

## Decisions

- Use SwiftUI `MenuBarExtra` with `.menuBarExtraStyle(.window)`.
- Use the monochrome SF Symbol `lock.fill` for the menu bar status item.
- Render a compact panel sized at 420 by 600 points.
- Keep the existing six workbench functions available in the compact panel:
  dashboard, paragraph restore, saved references, record maintenance, agent
  automation, and security boundary.
- Close the main window normally. The process stays alive because the menu
  bar extra remains active.
- Only the menu bar's explicit Quit command terminates the app.
- Preserve the main `VaultWorkbenchView` and all existing main-window copy.

## Architecture

`AgentSecretVaultApplication` owns one `AgentSecretVaultRuntime` instance.
Both the existing `WindowGroup` and the new menu bar panel receive state and
actions from that same runtime. The compact panel must not create another IPC
controller, record store, authorization session, or audit stream.

The app scene contains the following peers:

1. The existing main `WindowGroup`, given a stable scene identifier so it can
   be reopened from the menu bar.
2. A `MenuBarExtra` that hosts the compact panel.

The app delegate returns `false` from
`applicationShouldTerminateAfterLastWindowClosed`. The panel's Quit action
clears reveal sessions before calling `NSApp.terminate(nil)`. The normal
termination notification remains responsible for final cleanup.

## Compact Panel

The panel has three fixed regions:

1. **Header:** a small `lock.fill` symbol, current page title, and a concise
   IPC/vault status indicator. It contains no onboarding copy.
2. **Navigation:** six icon tabs with accessibility labels and hover help.
   The selected page title provides the text label; icons avoid repeated long
   navigation text.
3. **Content and footer:** the selected compact feature view fills the
   remaining height. The footer always provides Open Main Window and Quit.

The compact variants remove tutorial paragraphs, installation instructions,
and duplicated security explanations. They retain action labels, error state,
authorization prompts, and status information needed to complete the action.
The main-window components and wording are not changed.

## Feature Behavior

| Section | Compact behavior |
| --- | --- |
| Dashboard | Show the three connection states, direct page shortcuts, and a small recent-audit preview. |
| Paragraph restore | Keep input, restore, clear, result, and copy actions. Remove the tutorial paragraph. Clear restored plaintext when the panel disappears or resigns active state. |
| Saved references | List the saved contextual `secret://` templates and preserve copy/refresh actions without showing plaintext. |
| Record maintenance | Show the current orphan-scan state and the existing protected-delete request path. |
| Agent automation | Show the redacted audit list with its current state. |
| Security boundary | Show the concise allowed/blocked facts without explanatory onboarding text. |

The menu panel follows the existing visual policy: stable layout, no blurred
background, no repeating animation, and only the existing short interactive
animation for page selection.

## Lifecycle And Safety

- Closing the main window does not stop the runtime or local IPC server.
- Reopening from the menu bar creates or activates the same main scene.
- The compact panel never displays secrets unless the existing local
  authorization flow succeeds.
- Restored paragraph output is cleared on panel dismissal and app focus loss.
- Quit clears reveal sessions and then terminates; no alternate quit control
  is added to the compact content.

## Error Handling

- If the runtime has not started, compact actions use the existing unavailable
  states instead of attempting to create a second runtime.
- Paragraph restore keeps the current invalid-reference and no-reference
  error states in concise form.
- Empty saved-reference, audit, and orphan-scan states are explicit and do
  not claim that a scan or connection has succeeded.

## Validation

- Add unit tests for the menu bar presentation constants: 420 by 600 panel,
  `lock.fill` status symbol, and six-section coverage.
- Add source-level lifecycle tests confirming the app exposes a
  `MenuBarExtra`, prevents termination after the last window closes, and has
  an explicit menu-bar Quit action.
- Add compact paragraph restore tests covering state clearing on dismissal and
  focus loss without exposing plaintext.
- Run the full macOS `xcodebuild test` scheme.
- Manually verify: close the main window, invoke the menu bar panel, use each
  section, reopen the main window, and quit from the menu bar.
