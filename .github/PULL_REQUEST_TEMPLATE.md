## What

<!-- One-line summary of the change -->

## Why

<!-- The reason for the change. The diff shows what; explain why. -->

## Touch points

<!-- Which areas of the code does this affect? -->

- [ ] Crypto / file format
- [ ] Sync layer
- [ ] IPC contract (extension <-> desktop)
- [ ] Desktop UI
- [ ] CLI
- [ ] Extension
- [ ] Tests / docs only

## Tests

<!-- New tests added? Existing tests cover the change? -->

## Checklist

- [ ] `dotnet test` passes locally
- [ ] `npm run build` (in `extension/`) passes if extension touched
- [ ] No new warnings under `TreatWarningsAsErrors`
- [ ] Doc updated if behaviour changed

## Security impact

<!-- Does this change anything in the threat model? Anything that touches
     keys, IPC, or persisted state needs a sentence here. "None" is fine. -->
