// Browser-level test of the dashboard (index.html + static/app.js).
//
// Loads the real page in jsdom, talks to the real Flask app, and scans the
// deliberately vulnerable local target. Run it with:  make test-ui
// (scripts/run_dashboard_tests.py starts the servers and sets the variables below.)
//
//   APP_URL     where the dashboard is served, e.g. http://127.0.0.1:5099/
//   TARGET_URL  the vulnerable test target to scan, e.g. http://127.0.0.1:34021/?id=1
import jsdomPkg from 'jsdom';
const { JSDOM, requestInterceptor } = jsdomPkg;
import { EventSource as NodeEventSource } from 'eventsource';

const APP = process.env.APP_URL;
const TARGET = process.env.TARGET_URL;
if (!APP || !TARGET) {
    console.error('Set APP_URL and TARGET_URL, or run: make test-ui');
    process.exit(2);
}
let passed = 0,
    failed = 0;
const check = (name, ok, extra = '') => {
    ok ? passed++ : failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '   <-- ' + extra}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 60000, step = 100) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
        if (await fn()) return true;
        await sleep(step);
    }
    return false;
}

const requested = [];
const resources = {
    interceptors: [
        requestInterceptor((request) => {
            requested.push(request.url);
        }),
    ],
};

async function openPage(url = APP, { sse = true } = {}) {
    const state = { sseCount: 0, confirms: 0 };
    const dom = await JSDOM.fromURL(url, {
        runScripts: 'dangerously',
        resources,
        pretendToBeVisual: true,
        beforeParse(window) {
            window.fetch = (input, init) => fetch(new URL(input, window.location.href), init);
            if (sse) {
                window.EventSource = class extends NodeEventSource {
                    constructor(u, o) {
                        super(new URL(u, window.location.href).href, o);
                        state.sseCount++;
                    }
                };
            }
            window.confirm = () => {
                state.confirms++;
                return true;
            };
            window.HTMLElement.prototype.scrollIntoView = undefined; // jsdom lacks it; the page must cope
        },
    });
    await until(() => dom.window.document.readyState === 'complete');
    await sleep(300);
    return { dom, win: dom.window, doc: dom.window.document, state };
}
const text = (doc, id) => doc.getElementById(id).textContent.trim();
const submit = (doc) =>
    doc
        .getElementById('scan-form')
        .dispatchEvent(new doc.defaultView.Event('submit', { cancelable: true, bubbles: true }));

// ---------------------------------------------------------------- 1. load
let { win, doc, state } = await openPage();
check('page title', doc.title === 'Kavalu Security Engine');
check(
    'served from a NON-5000 port (old dashboard failed here)',
    !new URL(APP).port || new URL(APP).port !== '5000',
    new URL(APP).port,
);
check(
    'engine status shows online',
    await until(() => text(doc, 'engine-status') === 'Engine online', 5000),
    text(doc, 'engine-status'),
);
check('API base is same-origin', win.resolveApiBase() === '');
check(
    '6 module checkboxes; 5 checked by default; Burp unchecked',
    doc.querySelectorAll('input[name=module]').length === 6 &&
        doc.querySelectorAll('input[name=module]:checked').length === 5 &&
        !doc.querySelector('input[value=burp]').checked,
);
check(
    'only same-origin resources were requested (no CDN, no fonts)',
    requested.every((u) => new URL(u).origin === new URL(APP).origin),
    requested.join(', '),
);
check(
    'stylesheet and script were requested from /static',
    ['style.css', 'app.js'].every((f) => requested.some((u) => u.endsWith('/static/' + f))),
    requested.join(', '),
);
check(
    'history empty message shown, clear button hidden',
    text(doc, 'history').startsWith('No scans yet') && doc.getElementById('clear-history').hidden,
);

// ---------------------------------------------------------------- 2. validation
submit(doc);
await sleep(100);
check(
    'empty URL -> inline error, no alert dialog',
    !doc.getElementById('form-error').hidden && text(doc, 'form-error').includes('Enter the address'),
);
doc.getElementById('target-url').value = TARGET;
doc.getElementById('select-none').click();
check('"Clear all" unchecks every module', doc.querySelectorAll('input[name=module]:checked').length === 0);
submit(doc);
await sleep(100);
check('no module selected -> error', text(doc, 'form-error').includes('at least one'));
doc.getElementById('select-all').click();
check('"Select all" checks all six', doc.querySelectorAll('input[name=module]:checked').length === 6);
doc.querySelector('input[value=burp]').checked = false;

// ---------------------------------------------------------------- 3. real scan via SSE
doc.getElementById('target-url').value = TARGET;
submit(doc);
await sleep(50);
check('button disabled + "Scanning…" while running', doc.getElementById('scan-button').disabled);
const done = await until(() => !doc.getElementById('results-section').hidden, 90000);
check('scan finished and results are visible', done);
check('live progress used Server-Sent Events', state.sseCount >= 1, String(state.sseCount));
check(
    'progress panel hidden and button re-enabled after the scan',
    doc.getElementById('progress-section').hidden && !doc.getElementById('scan-button').disabled,
);

// ---------------------------------------------------------------- 4. results are correct
const counts = [...doc.querySelectorAll('#severity-counts li')].map(
    (li) => li.querySelector('strong').textContent,
);
check(
    'risk score and grade',
    text(doc, 'risk-score') === '100' && text(doc, 'risk-grade') === 'Grade F · Critical Risk',
    `${text(doc, 'risk-score')} / ${text(doc, 'risk-grade')}`,
);
check(
    'severity counts: 1 critical, 2 high, 7 medium, 3 low',
    counts.slice(0, 4).join(',') === '1,2,7,3',
    counts.join(','),
);
const rows = [...doc.querySelectorAll('#owasp-body tr')].map((tr) =>
    [...tr.children].map((td) => td.textContent),
);
check('OWASP table lists all 10 categories', rows.length === 10, String(rows.length));
check(
    'A03 shows "Critical issues"; A04 shows "No findings"',
    rows.find((r) => r[0] === 'A03:2021')?.[2] === 'Critical issues' &&
        rows.find((r) => r[0] === 'A04:2021')?.[2] === 'No findings',
    JSON.stringify(rows.slice(0, 4)),
);
check('injection notice is hidden (module was selected)', doc.getElementById('owasp-notice').hidden);
const cards = [...doc.querySelectorAll('#findings article.finding')];
check(
    'findings rendered, most severe first inside the first group',
    cards.length >= 10 && cards[0].classList.contains('critical'),
    String(cards.length),
);
check(
    'SQL injection finding has title, severity label and fix text',
    cards.some(
        (c) =>
            c.querySelector('h4').textContent === 'SQL Injection Vulnerability' &&
            c.querySelector('.sev').textContent === 'critical' &&
            c.querySelector('.fix'),
    ),
);
check(
    'roadmap and engine-module list rendered',
    doc.querySelectorAll('#roadmap li').length > 0 && doc.querySelectorAll('#engine-modules li').length >= 5,
);
check(
    'attribution facts rendered (no invented filler text)',
    doc.querySelectorAll('#attribution dt').length === 9 &&
        !doc.getElementById('attribution').textContent.includes('Independent Target'),
);
const scanId = win.currentScanId ?? null;
const pdfHref =
    doc.getElementById('download-pdf').getAttribute('href') || doc.getElementById('download-pdf').href;
check(
    'download links point at /api/report/<id>?format=…',
    ['pdf', 'html', 'json'].every(
        (f) =>
            doc.getElementById('download-' + f).href.includes('/api/report/') &&
            doc.getElementById('download-' + f).href.endsWith('format=' + f),
    ),
    pdfHref,
);
for (const [f, type] of [
    ['pdf', 'application/pdf'],
    ['html', 'text/html'],
    ['json', 'application/json'],
]) {
    const r = await fetch(doc.getElementById('download-' + f).href);
    check(
        `${f.toUpperCase()} download works (${type})`,
        r.status === 200 && (r.headers.get('content-type') || '').startsWith(type),
        `${r.status} ${r.headers.get('content-type')}`,
    );
}
const stored = JSON.parse(win.localStorage.getItem('kavalu_scan_history') || '[]');
check(
    'scan saved to browser history (same storage keys as before)',
    stored.length === 1 && win.localStorage.getItem('kavalu_scan_' + stored[0].scan_id) !== null,
);
check(
    'history list shows it, clear button visible',
    doc.querySelectorAll('.history-item').length === 1 && !doc.getElementById('clear-history').hidden,
);

// ---------------------------------------------------------------- 5. history click + clear
doc.getElementById('results-section').hidden = true;
doc.querySelector('.history-item').click();
await sleep(100);
check(
    'clicking history re-opens the saved results',
    !doc.getElementById('results-section').hidden && text(doc, 'result-target').includes('127.0.0.1'),
);
doc.getElementById('clear-history').click();
await sleep(50);
check(
    'clear history asks for confirmation and empties the list',
    state.confirms === 1 &&
        text(doc, 'history').startsWith('No scans yet') &&
        win.localStorage.getItem('kavalu_scan_history') === null,
);

// ---------------------------------------------------------------- 6. hostile scan data must stay inert
win.__pwned = undefined;
win.renderResults({
    scan_id: 'a'.repeat(32),
    target_url: '<img src=x onerror="window.__pwned=1">',
    risk: { score: 50, grade: 'C', label: 'Elevated Risk' },
    stats: { critical: 0 },
    findings: [
        {
            severity: 'high',
            title: '<script>window.__pwned=1</script>',
            description: '<img src=x onerror="window.__pwned=1">',
            type: 't<b>x</b>',
            owasp: 'A03',
            owasp_code: 'A03:2021',
            cwe: ['<i>c</i>'],
            details: { '<k>': '<svg onload=window.__pwned=1>' },
            remediation: '<a href="javascript:window.__pwned=1">fix</a>',
        },
    ],
    owasp_coverage: [
        { key: 'A03', code: 'A03:2021', name: '<b>Injection</b>', counts: { high: 1 }, status: 'high' },
    ],
    deployment_info: { platform: '<u>p</u>' },
    developer_info: {
        social_footprint: [
            'javascript:window.__pwned=1',
            { platform: '<b>x</b>', handle: 'h', url: 'data:text/html,<script>1</script>' },
            'https://good.example/a',
        ],
    },
    engine_modules: [{ name: '<b>m</b>', description: '<i>d</i>', ran: true }],
});
await sleep(100);
const live = doc.getElementById('results-section');
check('hostile data: no script ran', win.__pwned === undefined);
check(
    'hostile data: no injected elements',
    live.querySelectorAll('img, script, svg, b, i, u').length === 0,
    live.querySelectorAll('img, script, svg, b, i, u').length + ' found',
);
const hrefs = [...live.querySelectorAll('a[href]')]
    .map((a) => a.getAttribute('href'))
    .filter((h) => !h.includes('/api/report/'));
check(
    'hostile data: only the http(s) profile link survives',
    hrefs.length === 1 && hrefs[0] === 'https://good.example/a',
    JSON.stringify(hrefs),
);
check(
    'hostile data: shown literally as text',
    text(doc, 'result-target') === '<img src=x onerror="window.__pwned=1">',
);
win.close();

// ---------------------------------------------------------------- 7. polling fallback (no EventSource)
({ win, doc, state } = await openPage(APP, { sse: false }));
doc.querySelectorAll('input[name=module]').forEach((i) => {
    i.checked = i.value === 'tls';
});
doc.getElementById('target-url').value = TARGET;
submit(doc);
check(
    'polling fallback: scan completes without EventSource',
    (await until(() => !doc.getElementById('results-section').hidden, 60000)) && state.sseCount === 0,
);
check(
    'polling fallback: only the TLS module ran (injection notice shown)',
    !doc.getElementById('owasp-notice').hidden,
);

// ---------------------------------------------------------------- 8. error paths
doc.getElementById('results-section').hidden = true;
doc.getElementById('target-url').value = 'does-not-exist.invalid'; // no scheme: the page must add https://
submit(doc);
check(
    'unreachable target -> clear inline error, button usable again',
    (await until(
        () => !doc.getElementById('form-error').hidden && !doc.getElementById('scan-button').disabled,
        20000,
    )) && doc.getElementById('progress-section').hidden,
    text(doc, 'form-error'),
);
check(
    'address without a scheme gets https:// added',
    doc.getElementById('target-url').value === 'https://does-not-exist.invalid',
    doc.getElementById('target-url').value,
);
const realFetch = win.fetch;
win.fetch = () => Promise.reject(new TypeError('Failed to fetch'));
await win.checkEngine();
check(
    'engine offline status is shown',
    text(doc, 'engine-status').startsWith('Engine not reachable') &&
        doc.getElementById('engine-status').classList.contains('offline'),
);
doc.getElementById('target-url').value = TARGET;
submit(doc);
check(
    'starting a scan while offline -> friendly message',
    await until(() => text(doc, 'form-error').includes('Cannot reach the Security Engine'), 5000),
    text(doc, 'form-error'),
);
win.fetch = realFetch;
win.close();

// ---------------------------------------------------------------- 9. ?api= override is loopback-only
for (const [search, expected] of [
    ['?api=http://localhost:5000', 'http://localhost:5000'],
    ['?api=http://127.0.0.1:5000/x?y=1', 'http://127.0.0.1:5000'],
    ['?api=https://evil.example', ''],
    ['?api=javascript:alert(1)', ''],
    ['?api=not a url', ''],
    ['', ''],
]) {
    const p = await openPage(APP + search);
    check(
        `api override "${search}" -> "${expected}"`,
        p.win.resolveApiBase() === expected,
        p.win.resolveApiBase(),
    );
    p.win.close();
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
