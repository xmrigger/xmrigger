# Red-team test suite

Adversarial test scenarios for the federation transport defined in
[SPEC-FEDERATION-v1.md](../../SPEC-FEDERATION-v1.md).

Every scenario in `scenarios/` corresponds to one or more attack vectors
catalogued in `SPEC-FEDERATION-v1.md` §6 (E1–E25) and tracked in
`RED-TEAM-LOG.md` at the repo root.

## Running

```bash
node test/red-team/run.js                # run all scenarios against built-in mock target
node test/red-team/run.js --target real  # run against a live federation node (when impl lands)
node test/red-team/run.js --id 03        # run only scenario 03
```

## Scenario lifecycle

Each scenario has one of three statuses:

- `pending` — scenario is written against SPEC but the federation
  implementation does not exist yet, so the assertion is recorded as
  TODO. Reported as `pending` (yellow), not `pass` and not `fail`.
- `pass` — implementation exists, the attack was attempted, the defense
  behaved as the SPEC requires.
- `fail` — implementation exists but the defense did not behave as
  required. Either the implementation has a bug, or the SPEC is wrong.
  Either way it goes into `RED-TEAM-LOG.md` for blue-team triage.

## Adding a scenario

```js
// scenarios/16-example.js
'use strict';
module.exports = {
  id:               '16',
  name:             'short title',
  spec:             'SPEC-FEDERATION-v1.md §X.Y',
  attack_vector:    'E?? from the catalogue, or new',
  expected_outcome: 'one-line of what defense should do',

  /**
   * @param {AttackHarness} harness
   * @returns {Promise<{outcome: string, details: object}>}
   */
  async run(harness) {
    // ... attack code ...
    return { outcome: 'dropped', details: { ... } };
  },

  /**
   * @param {object} result  what `run` returned
   * @returns {boolean}      true = defense held; false = SPEC violated
   */
  verify(result) {
    return result.outcome === 'dropped';
  },
};
```

## Mock target vs real target

While the federation implementation is being built, the harness can run
against `mock-target.js` — a minimal in-process WebSocket server that
applies the SPEC's policy decisions in stub form. This lets the harness
itself be developed and reviewed independently of the implementation.

When `src/federation/` exists, scenarios are flipped from `pending` to
runnable simply by setting their `requires_impl: false` flag (default
already false) and re-running with `--target real`.
