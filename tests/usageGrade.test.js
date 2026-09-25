'use strict';
// tests/usageGrade.test.js
//
// Pins components/analysis/UsageGrade.js — the VIEW half of A3.
// lib/engines/ruleHitCorrelation.js grades the answer; this file is the only
// place that draws the grade, and a view can undo an engine's honesty without
// touching a line of it.
//
// ⛔ THE FAILURE THIS FILE EXISTS TO PREVENT. The engine separates a usage
// figure matched by the vendor's own rule ID from one matched by NAME only,
// because a name is neither unique nor stable: a rule renamed during the log
// window reads as having had no traffic while it is still passing some. That
// separation is worth exactly nothing if the view then draws both with the same
// chip and the same words — an operator reads the number, not the provenance,
// unless the provenance is on screen. So the caveat is asserted here rather
// than left to a code review.
//
// ⛔ AND THE SECOND: `insufficient-history` and `no-coverage` must not read
// alike. The first is SECVAULT'S limit (the rollup does not reach back far
// enough), the second is the DEVICE'S (it stopped sending). Reporting ours as
// theirs is the precise bug A3 fixed in the engine, and a shared sentence would
// reintroduce it where the operator actually reads it.
//
// Loading technique is the one tests/upgradePlanView.test.js already uses:
// `npm test` is `node --test` with no "type":"module", so an ESM component
// cannot be require()d. Everything pinned below is a plain const or a plain
// function whose body touches no imported identifier, so dropping the import
// block and the `export` keyword and evaluating is exact, not an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(REPO, ...parts), 'utf8');

const VIEW_REL = ['components', 'analysis', 'UsageGrade.js'];
const SRC = read(...VIEW_REL);

// ⛔ COMMENTS ARE STRIPPED BEFORE ANY SOURCE SCAN, AND THAT IS NOT A DETAIL.
// This repo has repeatedly had a scan satisfied by the comment EXPLAINING the
// thing it was hunting — a file that says in prose "never use --evidence here"
// would pass a raw grep for `--evidence` as though it used it, or fail one, in
// whichever direction happens to be wrong. Only code is evidence about code.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^[ \t]*\/\/[^\n]*$/gm, '');
}

const CODE = stripComments(SRC);

function loadView() {
  const declarations = SRC
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/\bexport\s+(const|function)\b/g, '$1')
    .replace(/\bexport\s+default\s+function\b/g, 'function');

  // Cut at the first JSX-bearing component; everything pinned here is declared
  // above it, and `new Function` cannot parse JSX.
  const cut = declarations.indexOf('function UsageGradeBadge(');
  assert.notEqual(cut, -1, 'expected UsageGradeBadge to mark the start of the JSX half');
  const pure = declarations.slice(0, cut);

  const names = [
    'USAGE_CLAIM',
    'USAGE_GRADES',
    'USAGE_NOT_MEASURED',
    'LOG_EVIDENCE_REASONS',
    'LOG_EVIDENCE_UNKNOWN',
    'usageGradeDescriptor',
    'logEvidenceSentence',
    'usageTitle',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${names.join(', ')} };`)();
}

const V = loadView();

// The four grades the engine can produce, verbatim from ruleHitCorrelation.js.
const GRADES = ['device', 'log-id', 'log-name', null];

// Phrases that would claim a usage figure is grounds for removing a rule.
// Negated forms ("not enough on its own to remove the rule") are the point and
// must survive; these are the AFFIRMATIVE claims.
const SUFFICIENCY_CLAIMS = [
  /safe to remove/i,
  /can be removed/i,
  /\bsafe to delete\b/i,
  /sufficient evidence/i,
  /\bproves?\b/i,
  /\bproof\b/i,
  /\bguarantee/i,
];

function allText(d) {
  return [d.label, d.short, d.title, d.caveat, d.caveatShort].filter(Boolean).join(' ');
}

// ── the descriptor table ────────────────────────────────────────────────────

describe('usage grade descriptors', () => {
  it('resolves a descriptor for each of the four grades', () => {
    for (const g of GRADES) {
      const d = V.usageGradeDescriptor(g);
      assert.ok(d, `grade ${String(g)} must resolve`);
      assert.equal(d.grade, g, `descriptor for ${String(g)} must name its own grade`);
    }
  });

  it('gives all four grades a DISTINCT descriptor', () => {
    const labels = GRADES.map((g) => V.usageGradeDescriptor(g).label);
    const shorts = GRADES.map((g) => V.usageGradeDescriptor(g).short);
    const titles = GRADES.map((g) => V.usageGradeDescriptor(g).title);
    assert.equal(new Set(labels).size, 4, `labels must be distinct: ${labels.join(' | ')}`);
    assert.equal(new Set(shorts).size, 4, `short labels must be distinct: ${shorts.join(' | ')}`);
    assert.equal(new Set(titles).size, 4, 'explanations must be distinct');
  });

  it('gives the four grades DISTINCT visual treatments', () => {
    const colors = GRADES.map((g) => V.usageGradeDescriptor(g).badgeColor);
    assert.equal(
      new Set(colors).size,
      4,
      `each grade must be visually distinguishable: ${colors.map(String).join(' | ')}`
    );
  });

  it('never dresses a grade in red or violet', () => {
    // Red is danger and nothing else; violet belongs to EvidenceMark alone.
    for (const g of GRADES) {
      const c = V.usageGradeDescriptor(g).badgeColor;
      assert.notEqual(c, 'danger', `${String(g)} must not be red — red is danger only`);
      assert.notEqual(c, 'purple', `${String(g)} must not be violet — that is EvidenceMark's`);
    }
  });

  it('marks ONLY device and log-id as deletion evidence', () => {
    // Mirrors ruleHitCorrelation.js's own `deletionEvidence`. If those two
    // disagree, the screen authorises something the engine refuses.
    assert.equal(V.usageGradeDescriptor('device').deletionEvidence, true);
    assert.equal(V.usageGradeDescriptor('log-id').deletionEvidence, true);
    assert.equal(V.usageGradeDescriptor('log-name').deletionEvidence, false);
    assert.equal(V.usageGradeDescriptor(null).deletionEvidence, false);
  });

  it('falls back to NOT MEASURED for a grade it has not been taught', () => {
    // An unrecognised value must not resolve to the nearest match: a grade this
    // file does not know is not something to make a confident claim about.
    for (const junk of ['log', 'LOG-ID', 'hits', '', undefined, 0, 'device ']) {
      assert.equal(
        V.usageGradeDescriptor(junk).grade,
        null,
        `${JSON.stringify(junk)} must resolve to NOT MEASURED`
      );
    }
  });
});

// ── the null grade is HUELESS ───────────────────────────────────────────────

describe('not measured', () => {
  it('carries NO hue at all', () => {
    const d = V.usageGradeDescriptor(null);
    assert.equal(d.badgeColor, null, 'not-measured must not have a badge colour');
    assert.equal(d.tone, 'unmeasured');
  });

  it('is the only descriptor with the unmeasured tone', () => {
    const measured = ['device', 'log-id', 'log-name'].map((g) => V.usageGradeDescriptor(g).tone);
    for (const t of measured) {
      assert.notEqual(t, 'unmeasured', 'a measured grade must not borrow the unmeasured tone');
    }
  });

  it('never reads as a zero, a pass, or good news', () => {
    const text = allText(V.usageGradeDescriptor(null)).toLowerCase();
    for (const bad of ['no traffic', 'unused', 'zero hits', 'never used']) {
      assert.ok(!text.includes(bad), `not-measured must not say "${bad}"`);
    }
    assert.match(
      text,
      /absence of evidence|never evidence of absence|cannot say|can say/,
      'not-measured must state that nothing is known, not that nothing happened'
    );
  });

  it('draws the null grade through NotMeasured, never through a muted Badge', () => {
    // A flat grey chip reads as a real but quiet category. The hueless
    // vocabulary is NotMeasured's, and the branch must be on badgeColor.
    assert.match(CODE, /if\s*\(!d\.badgeColor\)/, 'the hueless branch must key on badgeColor');
    assert.match(CODE, /<NotMeasured\b/, 'the hueless branch must render NotMeasured');
    assert.doesNotMatch(
      CODE,
      /color=["']muted["']/,
      'a muted Badge would make "not measured" look like a category'
    );
  });
});

// ── the log-name caveat ─────────────────────────────────────────────────────

describe('log-name', () => {
  const d = V.usageGradeDescriptor('log-name');

  it('carries a caveat at all', () => {
    assert.ok(d.caveat && d.caveat.length > 0, 'log-name must carry a caveat');
  });

  it('states the caveat VISIBLY, not only on hover', () => {
    // caveatShort is what the cell prints beside the figure. A tooltip is not
    // a place to put the difference between "may inform a deletion" and "may
    // not".
    assert.ok(d.caveatShort && d.caveatShort.length > 0, 'log-name must have printable caveat text');
    assert.match(CODE, /caveatShort/, 'the cell must render caveatShort');
  });

  it('names the RENAME hazard specifically', () => {
    assert.match(
      `${d.caveat} ${d.caveatShort}`,
      /renam/i,
      'the caveat must say that a rename hides traffic — that is the failure mode'
    );
  });

  it('is the ONLY grade carrying a caveat', () => {
    // Inventing a caveat for a strong grade teaches the operator to ignore the
    // one that matters.
    for (const g of ['device', 'log-id', null]) {
      assert.equal(V.usageGradeDescriptor(g).caveat, null, `${String(g)} must not carry a caveat`);
      assert.equal(V.usageGradeDescriptor(g).caveatShort, null);
    }
  });

  it('never claims sufficiency to remove a rule', () => {
    const text = allText(d);
    for (const claim of SUFFICIENCY_CLAIMS) {
      assert.doesNotMatch(text, claim, `log-name must not assert ${claim}`);
    }
    // And it must say the opposite out loud.
    assert.match(text, /not enough on its own to remove the rule/i);
  });

  it('holds for EVERY descriptor, not just log-name', () => {
    for (const g of GRADES) {
      const text = allText(V.usageGradeDescriptor(g));
      for (const claim of SUFFICIENCY_CLAIMS) {
        assert.doesNotMatch(text, claim, `${String(g)} must not assert ${claim}`);
      }
    }
  });
});

// ── whose limitation is it? ─────────────────────────────────────────────────

describe('log evidence sentences', () => {
  it('gives insufficient-history and no-coverage DIFFERENT sentences', () => {
    const ours = V.logEvidenceSentence('insufficient-history', 30);
    const theirs = V.logEvidenceSentence('no-coverage', 30);
    assert.notEqual(ours, theirs, 'our limit and the device\'s must not read alike');
  });

  it('attributes insufficient-history to SECVAULT', () => {
    const ours = V.logEvidenceSentence('insufficient-history', 30);
    assert.match(ours, /SecVault/, 'insufficient history is OUR limit and must say so');
    assert.match(
      ours,
      /not a fact about this firewall|limit of ours/i,
      'it must explicitly refuse to blame the device'
    );
  });

  it('attributes no-coverage to the DEVICE', () => {
    const theirs = V.logEvidenceSentence('no-coverage', 30);
    assert.match(theirs, /this firewall did not send logs/i);
    assert.doesNotMatch(
      theirs,
      /SecVault has not been collecting/i,
      'a device that stopped sending is not SecVault running out of history'
    );
  });

  it('covers every logEvidence value the engine can emit', () => {
    // Read from the engine rather than restated here, so a new state cannot be
    // added there and silently render as "no log evidence available".
    const engine = read('lib', 'engines', 'ruleHitCorrelation.js');
    const emitted = new Set();
    const re = /logEvidence\s*=\s*'([a-z-]+)'/g;
    let m = re.exec(engine);
    while (m) {
      emitted.add(m[1]);
      m = re.exec(engine);
    }
    // The ternary form the engine uses for the coverage branch.
    for (const extra of ['insufficient-history', 'window-too-short', 'no-coverage']) emitted.add(extra);
    assert.ok(emitted.size >= 6, `expected the engine to emit several states, saw ${emitted.size}`);
    for (const code of emitted) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(V.LOG_EVIDENCE_REASONS, code),
        `logEvidence '${code}' has no sentence — it would render as "no evidence available"`
      );
    }
  });

  it('gives every code a distinct sentence', () => {
    const codes = Object.keys(V.LOG_EVIDENCE_REASONS);
    const texts = codes.map((c) => V.logEvidenceSentence(c, 30));
    assert.equal(new Set(texts).size, codes.length, 'two states sharing a sentence are one state');
  });

  it('substitutes the real window, and falls back rather than printing a blank', () => {
    assert.match(V.logEvidenceSentence('no-coverage', 7), /7-day/);
    assert.match(V.logEvidenceSentence('no-coverage', 90), /90-day/);
    for (const junk of [undefined, null, 0, -5, 'abc', NaN]) {
      const s = V.logEvidenceSentence('no-coverage', junk);
      assert.doesNotMatch(s, /\{days\}/, 'an unsubstituted token must never reach the screen');
      assert.match(s, /30-day/, 'a junk window falls back to the engine default, not to blank');
    }
  });

  it('never reports an unknown code as a measurement', () => {
    for (const junk of ['nonsense', '', undefined, null]) {
      const s = V.logEvidenceSentence(junk, 30);
      assert.match(s, /^Not measured/, `'${String(junk)}' must read as not measured`);
    }
  });

  it('marks only hits and measured-zero as actual measurements', () => {
    assert.equal(V.LOG_EVIDENCE_REASONS.hits.state, 'hits');
    assert.equal(V.LOG_EVIDENCE_REASONS['measured-zero'].state, 'measured-zero');
    for (const code of ['no-coverage', 'insufficient-history', 'window-too-short',
      'rule-logging-disabled', 'no-rule-identity']) {
      assert.equal(
        V.LOG_EVIDENCE_REASONS[code].state,
        'not-measured',
        `${code} is not a measurement`
      );
    }
    assert.equal(V.LOG_EVIDENCE_UNKNOWN.state, 'not-measured');
  });
});

// ── the claim the column makes ──────────────────────────────────────────────

describe('USAGE_CLAIM', () => {
  it('says what a figure rests on and what it is not enough for', () => {
    assert.match(V.USAGE_CLAIM, /counter/i);
    assert.match(V.USAGE_CLAIM, /rule ID/i);
    for (const claim of SUFFICIENCY_CLAIMS) {
      assert.doesNotMatch(V.USAGE_CLAIM, claim);
    }
  });
});

// ── design system ───────────────────────────────────────────────────────────

describe('design system', () => {
  it('hardcodes no hex colour', () => {
    assert.doesNotMatch(
      CODE,
      /#[0-9a-fA-F]{3,8}\b/,
      'every colour comes from a token, never a literal'
    );
  });

  it('never uses --evidence, which belongs to EvidenceMark alone', () => {
    // Scanned on the COMMENT-STRIPPED source: the header explains why violet is
    // off limits, and a raw grep would be satisfied by that explanation.
    assert.doesNotMatch(CODE, /--evidence/, 'violet is reserved for EvidenceMark');
  });

  it('uses the hueless tokens for the not-measured case', () => {
    // Indirectly: through NotMeasured, which owns --unmeasured/--hatch. A
    // component reaching for its own grey would opt itself out of that
    // vocabulary silently.
    assert.match(CODE, /import NotMeasured from/);
    assert.doesNotMatch(CODE, /var\(--text-muted\)[^)]*not measured/i);
  });

  it('takes spacing and type from the token scales', () => {
    const inlineNumbers = CODE.match(/(gap|padding|margin|fontSize):\s*['"]?\d+px/g) || [];
    assert.deepEqual(inlineNumbers, [], `invented spacing opts out of the scale: ${inlineNumbers}`);
  });

  it('adds no icon library and no CSS framework', () => {
    assert.doesNotMatch(CODE, /from\s+['"](?!\.)/, 'no third-party import belongs in this file');
    assert.doesNotMatch(CODE, /className=["'][^"']*\b(?:flex|text-sm|bg-|p-\d)\b/, 'no Tailwind');
  });

  it('defines no React component inside another', () => {
    // Every component in this file is a top-level declaration.
    const nested = CODE.match(/^\s+function\s+[A-Z]/gm) || [];
    assert.deepEqual(nested, [], `nested component declarations: ${nested}`);
  });
});

// ── the call sites ──────────────────────────────────────────────────────────

describe('call sites', () => {
  it('the rule list renders the grade beside the figure', () => {
    const page = stripComments(read('app', '(dashboard)', 'devices', '[id]', 'rules', 'page.js'));
    assert.match(page, /RuleUsageCell/, 'the rules table must render the shared cell');
    assert.match(
      page,
      /correlateDeviceRules/,
      'without correlation the column can only ever show the device counter'
    );
    assert.doesNotMatch(
      page,
      /r\.hit_count === null \|\| r\.hit_count === undefined \? '—' : r\.hit_count/,
      'the bare em-dash cell must be gone — it could not say why the value was missing'
    );
  });

  it('the rule list survives a failed correlation without losing the counter', () => {
    // ⛔ A read failure of OURS must not render as a gap in the FIREWALL. The
    // fallback has to produce device-grade fields by hand.
    const page = stripComments(read('app', '(dashboard)', 'devices', '[id]', 'rules', 'page.js'));
    assert.match(page, /catch/, 'the correlation must be guarded');
    assert.match(page, /usageGrade:[^,]*'device'/, 'the fallback must still grade the counter');
  });

  it('the cleanup candidate table states what its hit figure rests on', () => {
    const tab = stripComments(read('components', 'analysis', 'CleanupTab.js'));
    assert.match(tab, /UsageGradeBadge/, 'the removal candidate column must name its grade');
    assert.match(tab, /grade="device"/, 'getCleanupCandidates accepts only the device counter');
  });
});
