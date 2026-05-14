'use strict';
/**
 * run.js — red-team scenario runner.
 *
 * @license LGPL-2.1
 *
 * Usage:
 *   node test/red-team/run.js                    run all scenarios on mock target
 *   node test/red-team/run.js --target real      use a real federation node (TBD)
 *   node test/red-team/run.js --id 03            run only scenario 03
 *   node test/red-team/run.js --json             machine-readable summary on stdout
 */

const fs   = require('fs');
const path = require('path');

const { AttackHarness, OUTCOMES } = require('./attack-harness');
const { MockTarget }              = require('./mock-target');

// ── CLI ─────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { target: 'mock', id: null, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target')  out.target = argv[++i];
    else if (a === '--id') out.id     = argv[++i];
    else if (a === '--json') out.json = true;
  }
  return out;
}

// ── Scenario loading ────────────────────────────────────────────────────────

function loadScenarios(filterId) {
  const dir = path.join(__dirname, 'scenarios');
  if (!fs.existsSync(dir)) return [];
  const files = fs.readdirSync(dir).filter((f) => /^\d+.*\.js$/.test(f)).sort();
  const scenarios = files.map((f) => {
    const s = require(path.join(dir, f));
    s._file = f;
    return s;
  });
  if (filterId) return scenarios.filter((s) => s.id === filterId);
  return scenarios;
}

// ── Target factory ──────────────────────────────────────────────────────────

async function startTarget(mode) {
  if (mode === 'mock') {
    const t = new MockTarget();
    const ctx = await t.start();
    return { ctx, stop: () => t.stop() };
  }
  if (mode === 'real') {
    const { startRealTarget } = require('./real-target');
    return startRealTarget();
  }
  throw new Error(`unknown target mode: ${mode}`);
}

// ── Pretty output ───────────────────────────────────────────────────────────

const COLOR = process.stdout.isTTY ? {
  red:    (s) => `\x1b[31m${s}\x1b[0m`,
  green:  (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  dim:    (s) => `\x1b[2m${s}\x1b[0m`,
} : {
  red: (s) => s, green: (s) => s, yellow: (s) => s, dim: (s) => s,
};

function badge(status) {
  if (status === 'pass')    return COLOR.green('  PASS  ');
  if (status === 'fail')    return COLOR.red(  '  FAIL  ');
  if (status === 'pending') return COLOR.yellow('PENDING');
  if (status === 'error')   return COLOR.red(  ' ERROR ');
  return status;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  const scenarios = loadScenarios(args.id);

  if (scenarios.length === 0) {
    console.error('No scenarios found.');
    process.exit(2);
  }

  const target = await startTarget(args.target);
  const harness = new AttackHarness({ targetMode: args.target }).attachTarget(target.ctx);

  if (!args.json) {
    console.log(`\nred-team suite — target=${args.target}, scenarios=${scenarios.length}\n`);
  }

  const results = [];

  for (const s of scenarios) {
    let status = 'error';
    let detail = null;
    let err    = null;

    try {
      if (s.requires_impl && args.target !== 'real') {
        status = 'pending';
      } else {
        const result = await Promise.race([
          s.run(harness),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('scenario timeout')), 5_000)
          ),
        ]);
        const ok = await s.verify(result);
        status = ok ? 'pass' : 'fail';
        detail = result;
      }
    } catch (e) {
      err = e.message;
    } finally {
      await harness.cleanup();
    }

    results.push({ id: s.id, name: s.name, attack_vector: s.attack_vector, status, detail, error: err });

    if (!args.json) {
      console.log(`  ${badge(status)}  #${s.id}  ${s.name}`);
      if (s.attack_vector) console.log(`           ${COLOR.dim(s.attack_vector + ' — ' + (s.spec || ''))}`);
      if (err)             console.log(`           ${COLOR.red('error: ' + err)}`);
    }
  }

  await target.stop();

  const counts = results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {});

  if (args.json) {
    console.log(JSON.stringify({ target: args.target, total: results.length, counts, results }, null, 2));
  } else {
    console.log(`\n  total: ${results.length}  pass: ${counts.pass||0}  ` +
                `fail: ${counts.fail||0}  pending: ${counts.pending||0}  ` +
                `error: ${counts.error||0}\n`);
  }

  // Exit 1 if any fail or error. Pending and pass are both acceptable.
  process.exit((counts.fail || 0) + (counts.error || 0) > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
