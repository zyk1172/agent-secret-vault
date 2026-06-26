# Keychain recovery matrix

Status: automatic coverage is implemented; cross-user iCloud Keychain recovery verification is pending manual execution.

## Automatic coverage

- New vault creation creates both local and recovery-wrapped master key records.
- Normal local unlock uses the local wrapper and does not require the recovery key.
- A Mac with only the recovery wrapper reports recovery-required state.
- Recovery fails closed when the synchronizable recovery key is unavailable.
- Recovery recreates a local non-synchronizable wrapper after the master key is opened with the recovery key.
- Malformed recovery wrapper data fails closed.
- Unsupported required Keychain controls fail before vault creation and before persisting wrapped state.

## Manual matrix

The following matrix must be completed with signed app builds on two separate macOS user profiles signed into the designated test Apple account.

| Scenario | macOS version | User profile | Apple account | Result | Notes |
| --- | --- | --- | --- | --- | --- |
| Create vault and local unlock | Pending | Pending | Pending | Pending | Requires signed app and iCloud Keychain enabled. |
| Recover on second profile | Pending | Pending | Pending | Pending | Verify recovery wrapper arrives through iCloud Keychain. |
| Recovery unavailable with iCloud Keychain disabled | Pending | Pending | Pending | Pending | Verify fail-closed status and no weaker fallback. |
| Recovered profile creates new local wrapper | Pending | Pending | Pending | Pending | Verify subsequent unlock succeeds without recovery path. |

Do not mark these rows as passed until they have been executed on real macOS user profiles. Unit tests are not a substitute for this matrix.
