'use strict';
// Pins the HTTP surface over the application-centric view:
// app/api/applications/**.
//
// ⛔ WHY A SOURCE-SCANNING TEST AND NOT A ROUTE TEST. There is no HTTP harness
// in this repo and none is being added for this (package.json has no
// devDependencies and keeps none). What actually needs pinning here is not a
// response body — it is that the ACCESS BOUNDARY and the ERROR HONESTY of
// these routes cannot drift, and both are visible in the source. The same
// approach tests/reportRoute.test.js already uses.
//
// ⛔ THE DIRECTORY IS WALKED, NOT LISTED. Every rule below is applied to every
// route.js found under app/api/applications, so a route added tomorrow is
// covered by default. A hardcoded file list would pass while an ungated new
// endpoint sat beside it — the failure this suite exists to make impossible.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const API_DIR = path.join(ROOT, 'app', 'api', 'applications');

const MUTATING = ['POST', 'PUT', 'DELETE', 'PATCH'];
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

// Anything that reaches the database or the engine. The guards below are
// checked to run BEFORE any of these — a check that happens after the query
// has already run is not a check.
const DATA_CALL =
  /(pool\s*\.\s*query|evaluateAllApplications\(|evaluateApplication\(|createApplication\(|updateApplication\(|deleteApplication\(|addFlow\(|updateFlow\(|deleteFlow\(|applicationExists\(|findOwnedFlow\()/;

// ── the files ───────────────────────────────────────────────────────────────

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.name === 'route.js') out.push(full);
  }
  return out;
}

// Comments quote the rules they enforce, so a naive scan matches the
// explanation rather than the code. Strip them first — a source-scanning test
// has to read what RUNS.
const code = (src) => src
  .split('\n')
  .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
  .join('\n');

/** The body of one function declaration, or null if the file has no such one. */
function bodyOf(src, name, exported) {
  const sig = exported
    ? new RegExp(`export\\s+async\\s+function\\s+${name}\\s*\\(`)
    : new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`);
  const m = sig.exec(src);
  if (!m) return null;

  // ⛔ Skip past the PARAMETER LIST first. `GET(request, { params })` opens a
  // brace inside its own signature, and taking the first `{` after the name
  // returned "{ params }" as the whole handler — every rule below then
  // "passed" against two words of destructuring. A test that reads the wrong
  // text is worse than no test: it reports a boundary as enforced.
  let i = m.index + m[0].length - 1; // the '(' of the signature
  let parens = 0;
  for (; i < src.length; i += 1) {
    if (src[i] === '(') parens += 1;
    else if (src[i] === ')') {
      parens -= 1;
      if (parens === 0) { i += 1; break; }
    }
  }
  const open = src.indexOf('{', i);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') {
      depth -= 1;
      if (depth === 0) return src.slice(open, i + 1);
    }
  }
  return null;
}

const handlerBody = (src, method) => bodyOf(src, method, true);

/**
 * Names of file-local functions that perform the UUID check, so the guard can
 * be shared by two handlers without this test hardcoding its name. Derived
 * rather than listed, for the same reason the file list is: a rename must not
 * silently stop enforcing the rule.
 */
function uuidGuardNames(src) {
  const names = ['isValidUuid'];
  const re = /function\s+(\w+)\s*\(/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (HTTP_METHODS.includes(m[1])) continue;
    const body = bodyOf(src, m[1], false);
    if (body && /isValidUuid\(/.test(body)) names.push(m[1]);
  }
  return names;
}

const FILES = walk(API_DIR).map((file) => {
  const raw = fs.readFileSync(file, 'utf8');
  return {
    file,
    rel: path.relative(ROOT, file).replace(/\\/g, '/'),
    src: code(raw),
    raw,
    dynamicSegments: (path.relative(API_DIR, file).match(/\[[^\]]+\]/g) || []),
  };
});

describe('the application routes exist at all', () => {
  it('found the five declared route files and nothing unexpected', () => {
    assert.deepEqual(FILES.map((f) => f.rel).sort(), [
      'app/api/applications/[id]/flows/[flowId]/route.js',
      'app/api/applications/[id]/flows/route.js',
      'app/api/applications/[id]/route.js',
      // Declares a published cloud service in one action (v2.126.0). Its
      // derivation lives beside it in from-cloud/derive.js, which is NOT a
      // route module and so is not walked here — a Next route file may export
      // only handlers, which is why the logic it shares with the UI sits in a
      // sibling.
      'app/api/applications/from-cloud/route.js',
      'app/api/applications/route.js',
    ]);
  });

  it('⛔ the scanner reads real handler bodies, not a fragment of a signature', () => {
    // THE BUG THIS EXISTS FOR. `GET(request, { params })` opens a brace in its
    // own parameter list, so the first version of bodyOf() returned
    // "{ params }" as the handler and every rule in this file passed against
    // it — a suite reporting an access boundary as enforced while reading two
    // words of destructuring. A source-scanning test has to prove it found the
    // source.
    let handlers = 0;
    for (const f of FILES) {
      for (const method of HTTP_METHODS) {
        const body = handlerBody(f.src, method);
        if (!body) continue;
        handlers += 1;
        assert.ok(body.length > 150, `${f.rel} ${method} body is suspiciously short: ${body}`);
        assert.match(body, /NextResponse\.json\(/,
          `${f.rel} ${method} body contains no response — the wrong text was captured`);
      }
    }
    assert.equal(handlers, 9, 'expected GET+POST, GET+PUT+DELETE, POST, PUT+DELETE, POST');
  });

  it('every engine function the routes call really is exported', () => {
    // Catches an engine rename that would otherwise only surface as a 500 the
    // first time an operator saved a flow.
    const engine = require('../lib/engines/applicationViewData');
    for (const fn of ['evaluateAllApplications', 'evaluateApplication', 'createApplication',
      'updateApplication', 'deleteApplication', 'addFlow', 'updateFlow', 'deleteFlow']) {
      assert.equal(typeof engine[fn], 'function', `${fn} is not exported`);
    }
  });
});

describe('⛔ every mutating handler is gated, in every file, by default', () => {
  // Written per FILE and per HANDLER rather than as one assertion over a
  // hardcoded list: a new file, or a new verb on an existing file, is covered
  // the moment it is added. An ungated mutation here is not a small bug — a
  // read-only account could rewrite the declared map the whole page judges
  // against.
  for (const f of FILES) {
    for (const method of MUTATING) {
      const body = handlerBody(f.src, method);
      if (!body) continue;

      it(`${f.rel} ${method} checks can(session, OPERATE)`, () => {
        assert.match(body, /can\(session,\s*OPERATE\)/);
      });

      it(`${f.rel} ${method} refuses through forbiddenResponse(OPERATE)`, () => {
        // The 403 body names the capability; "admin role required" became
        // actively misleading once three roles existed.
        assert.match(body, /forbiddenResponse\(OPERATE\)/);
      });

      it(`${f.rel} ${method} gates BEFORE it touches any data`, () => {
        const gate = body.search(/can\(session,\s*OPERATE\)/);
        const data = body.search(DATA_CALL);
        assert.ok(gate > -1, 'no capability check at all');
        if (data > -1) {
          assert.ok(gate < data,
            'the capability check runs after the query — by then the work is done');
        }
      });

      it(`${f.rel} ${method} resolves its own session`, () => {
        assert.match(body, /getServerSession\(authOptions\)/);
      });
    }
  }

  it('⛔ no mutating route uses isAdmin — declaring an application is not administration', () => {
    // MANAGE_DEVICES would exclude every operator. Declaring what an
    // application needs changes no device, no rule and no score; it is exactly
    // the work the operator role exists for, and /api/segmentation's mutations
    // are gated the same way for the same reason.
    for (const f of FILES) {
      assert.equal(/isAdmin/.test(f.raw), false, `${f.rel} uses isAdmin`);
    }
  });

  it('⛔ GET is NOT gated — this is fleet posture, not personal data', () => {
    // The two documented GET exceptions in this product are log search and the
    // VPN identity tabs, both because they name individual people. Nothing
    // here does. A UI gate stricter than its route reads to the operator as a
    // broken product rather than as a permission they lack.
    for (const f of FILES) {
      const body = handlerBody(f.src, 'GET');
      if (!body) continue;
      assert.equal(/forbiddenResponse/.test(body), false, `${f.rel} GET is gated`);
      assert.equal(/can\(session/.test(body), false, `${f.rel} GET checks a capability`);
    }
  });
});

describe('⛔ every id is UUID-validated before it reaches a query', () => {
  // A malformed segment must be a 400. Left unchecked, Postgres answers
  // "invalid input syntax for type uuid" — a 500 that reads as a broken
  // server — and any attempt to be lenient about it instead produces an empty
  // result, which reads as "no such application". Both are wrong answers to a
  // malformed request.
  for (const f of FILES) {
    if (f.dynamicSegments.length === 0) continue;

    it(`${f.rel} imports the shared validator rather than rolling its own regex`, () => {
      assert.match(f.src, /isValidUuid[\s\S]*apiUtils/);
    });

    for (const seg of f.dynamicSegments) {
      const name = seg.slice(1, -1);
      it(`${f.rel} validates params.${name}`, () => {
        assert.match(f.src, new RegExp(`isValidUuid\\(params\\.${name}\\)`));
      });
    }

    for (const method of HTTP_METHODS) {
      const body = handlerBody(f.src, method);
      if (!body) continue;
      it(`${f.rel} ${method} validates before querying`, () => {
        const guards = uuidGuardNames(f.src)
          .map((n) => body.search(new RegExp(`${n}\\(`)))
          .filter((i) => i > -1);
        const data = body.search(DATA_CALL);
        assert.ok(guards.length > 0, 'no uuid guard in this handler');
        if (data > -1) {
          assert.ok(Math.min(...guards) < data,
            'the id reaches a query before it is validated');
        }
      });
    }
  }

  it('an invalid id is a 400, and it says which id', () => {
    for (const f of FILES) {
      if (f.dynamicSegments.length === 0) continue;
      assert.match(f.src, /Invalid application id/);
      assert.match(f.src, /status: 400/);
    }
  });
});

describe('⛔ the flow 400 carries the ENGINE reason, not a generic string', () => {
  // addFlow/updateFlow validate with normaliseFlow — the same parser that will
  // later evaluate the flow — so the reason names the field that is wrong
  // ("Source ... is not a valid address or CIDR."). Replacing it with
  // "invalid input" throws away the only thing that makes the error fixable,
  // and leaves the operator guessing at a row that can never produce a verdict.
  const flowFiles = FILES.filter((f) => /flows/.test(f.rel));

  it('there are flow routes to check', () => {
    assert.equal(flowFiles.length, 2);
  });

  for (const f of flowFiles) {
    it(`${f.rel} returns result.reason verbatim with a 400`, () => {
      assert.match(f.src, /error:\s*result\.reason/);
      assert.match(f.src, /status:?\s*:?\s*400|status: 400/);
    });

    it(`${f.rel} invents no generic replacement`, () => {
      assert.equal(/invalid input/i.test(f.src), false);
      assert.equal(/bad request/i.test(f.src), false);
    });
  }

  it('the reason really does name the field — pinned against the engine itself', () => {
    // If normaliseFlow ever stopped naming the field, returning it verbatim
    // would become pointless without anything failing. So the claim is checked
    // at its source, not just at the route.
    const { normaliseFlow } = require('../lib/engines/applicationView');
    const bad = normaliseFlow({ src: '10.0.0.300', dst: '10.0.0.0/24', protocol: 'tcp' });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /10\.0\.0\.300/);
  });
});

describe('⛔ a flow can never be created or edited against the wrong parent', () => {
  it('POST /flows proves the application exists before inserting', () => {
    const f = FILES.find((x) => x.rel.endsWith('flows/route.js'));
    const body = handlerBody(f.src, 'POST');
    assert.match(body, /applicationExists\(/);
    assert.match(body, /status: 404/);
    const check = body.search(/applicationExists\(/);
    const insert = body.search(/addFlow\(/);
    assert.ok(check > -1 && insert > -1 && check < insert,
      'the FK would report this as a 500 instead of telling the caller what is wrong');
  });

  for (const method of ['PUT', 'DELETE']) {
    it(`${method} /flows/[flowId] proves the flow belongs to THIS application`, () => {
      // updateFlow/deleteFlow key on the flow id ALONE. Trusting the flowId
      // would let a request addressed to application A edit or delete a flow
      // belonging to application B, silently, with a 200.
      const f = FILES.find((x) => x.rel.endsWith('[flowId]/route.js'));
      const body = handlerBody(f.src, method);
      assert.match(body, /findOwnedFlow\(params\.id,\s*params\.flowId\)/);
      assert.match(body, /status: 404/);
      const owned = body.search(/findOwnedFlow\(/);
      const mutate = body.search(/updateFlow\(|deleteFlow\(/);
      assert.ok(owned > -1 && mutate > -1 && owned < mutate);
    });
  }

  it('the ownership query constrains BOTH ids in the SQL, not in JS', () => {
    const f = FILES.find((x) => x.rel.endsWith('[flowId]/route.js'));
    assert.match(f.src, /WHERE id = \$1::uuid AND application_id = \$2::uuid/);
  });
});

describe('⛔ errors are returned, never swallowed into an empty 200', () => {
  // An operator handed an empty list learns nothing and concludes the fleet is
  // clean; one handed the error knows what to fix. Same rule the work queue
  // enforces with its per-source banners.
  for (const f of FILES) {
    for (const method of HTTP_METHODS) {
      const body = handlerBody(f.src, method);
      if (!body) continue;
      it(`${f.rel} ${method} surfaces a thrown failure`, () => {
        assert.match(body, /catch\s*\(\s*err\s*\)/);
        assert.match(body, /status: 500/);
        assert.match(body, /error:\s*err\.message/);
      });
    }
  }

  it('no handler returns an empty array as a fallback for a failure', () => {
    for (const f of FILES) {
      assert.equal(/catch[\s\S]{0,120}NextResponse\.json\(\s*\[\s*\]/.test(f.src), false,
        `${f.rel} answers a failure with an empty list`);
    }
  });
});

describe('the query-string window', () => {
  // ⛔ A JUNK `days` IS IGNORED, NOT REFUSED. The engine owns the default and
  // always reports the window it actually used back in `windowDays`, so the
  // response can never state a span the evidence does not cover — which is the
  // failure the guard exists to prevent, not the presence of a bad parameter.
  const withGet = FILES.filter((f) => handlerBody(f.src, 'GET'));

  it('both read routes accept ?days=', () => {
    assert.equal(withGet.length, 2);
    for (const f of withGet) assert.match(f.src, /searchParams\.get\('days'\)/);
  });

  it('⛔ the parser returns undefined for junk — it never produces an error response', () => {
    for (const f of withGet) {
      const parser = bodyOf(f.src, 'windowDaysFrom', false);
      assert.ok(parser, `${f.rel} has no windowDaysFrom`);
      assert.match(parser, /return undefined/);
      assert.equal(/NextResponse|status:/.test(parser), false,
        `${f.rel} refuses a bad days value instead of ignoring it`);
    }
  });

  it('⛔ it refuses 0, negatives and non-integers, rather than forwarding them', () => {
    // Forwarding "-5" is how a page ends up printing "evaluated over -5 days"
    // beside a measurement taken over a different span.
    for (const f of withGet) {
      const parser = bodyOf(f.src, 'windowDaysFrom', false);
      assert.match(parser, /\\d\+\$/, 'digits-only test missing');
      assert.match(parser, /n\s*>\s*0/, 'positivity test missing');
    }
  });

  it('the window is passed to the engine, not applied in the route', () => {
    for (const f of withGet) {
      assert.match(f.src, /\{\s*windowDays\s*\}/);
    }
  });
});

describe('⛔ no recompute/refresh endpoint exists — there is no stored verdict', () => {
  // Every GET evaluates the current rulebase over the current traffic window.
  // A "refresh" would imply a cached verdict, which is precisely the staleness
  // this feature is built to beat.
  it('no route file or directory offers one', () => {
    const names = walk(API_DIR).map((p) => path.relative(API_DIR, p).replace(/\\/g, '/'));
    for (const n of names) {
      assert.equal(/recompute|refresh|reevaluate|re-evaluate/i.test(n), false,
        `${n} looks like a recompute endpoint`);
    }
    for (const f of FILES) {
      assert.equal(/recompute|reevaluate/i.test(f.src), false, `${f.rel} mentions a recompute`);
    }
  });
});

describe('Next.js route-module hygiene', () => {
  it('every route exports dynamic = force-dynamic', () => {
    // Without it, `npm run build` prerenders the route and hits the database at
    // build time.
    for (const f of FILES) {
      assert.match(f.src, /export const dynamic = 'force-dynamic'/, f.rel);
    }
  });

  it('⛔ nothing but handlers and config is exported', () => {
    // A Next route module may only export HTTP handlers and a small set of
    // config values; anything else fails the build. This is also why the
    // helpers in these files are file-local and pinned by source scan rather
    // than imported into this test.
    const allowed = new Set([...HTTP_METHODS, 'dynamic', 'revalidate', 'runtime',
      'fetchCache', 'preferredRegion', 'maxDuration']);
    for (const f of FILES) {
      const exported = [
        ...f.src.matchAll(/export\s+(?:async\s+)?(?:function|const|let|var)\s+(\w+)/g),
      ].map((m) => m[1]);
      for (const name of exported) {
        assert.ok(allowed.has(name), `${f.rel} exports ${name}, which Next will reject`);
      }
      assert.equal(/export\s+default/.test(f.src), false, `${f.rel} has a default export`);
    }
  });

  it('the operator-visible actions are recorded in the activity log', () => {
    for (const f of FILES) {
      for (const method of MUTATING) {
        if (!handlerBody(f.src, method)) continue;
        assert.match(f.src, /logActivity\(/, `${f.rel} mutates without an audit line`);
      }
    }
  });

  it('⛔ a failed audit line never fails the write it describes', () => {
    for (const f of FILES) {
      if (!/logActivity\(/.test(f.src)) continue;
      assert.match(f.src, /try\s*\{[\s\S]{0,500}logActivity\([\s\S]{0,500}\}\s*catch/,
        `${f.rel} lets the audit trail break the primary action`);
    }
  });
});
