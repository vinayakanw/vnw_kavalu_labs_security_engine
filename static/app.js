/*
 * Kavalu Security Engine: dashboard script.
 *
 * Plain JavaScript with no libraries. Scan results describe a website the
 * user does not control, so they are NEVER inserted as HTML: every value goes
 * through h() below, which uses text nodes. Do not use innerHTML here.
 */
'use strict';

/* ------------------------------------------------------------------ settings */

const POLL_INTERVAL_MS = 1500;
const HEALTH_INTERVAL_MS = 30000;
const HISTORY_KEY = 'kavalu_scan_history';
const SCAN_KEY_PREFIX = 'kavalu_scan_';
const HISTORY_LIMIT = 30; // scans kept in this browser
const HISTORY_SHOWN = 10; // scans listed on the page

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const RESULT_LABELS = {
    critical: 'Critical issues',
    high: 'High-risk issues',
    attention: 'Needs attention',
    clear: 'Informational only',
    not_tested: 'No findings',
};

let currentScanId = null;
let eventStream = null;
let pollTimer = null;

/* ------------------------------------------------------------------- helpers */

const $ = (id) => document.getElementById(id);

/** Create an element. String children become text nodes, so they are always safe. */
function h(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(props || {})) {
        if (value === undefined || value === null || value === false) continue;
        if (name === 'class') node.className = value;
        else if (name === 'text') node.textContent = value;
        else node.setAttribute(name, value === true ? '' : value);
    }
    for (const child of children.flat()) {
        if (child !== undefined && child !== null && child !== false) node.append(child);
    }
    return node;
}

function replaceContent(node, ...children) {
    node.replaceChildren(...children.flat().filter(Boolean));
}

/** Return the URL only if it is http(s); anything else (javascript:, data:, ...) is dropped. */
function safeHref(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
    } catch {
        return null;
    }
}

function sortBySeverity(items) {
    return [...items].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5));
}

/* ---------------------------------------------------------------------- API */

/**
 * Where the API lives. Normally the same server that served this page.
 * Two development exceptions: opening the file directly, or adding
 * ?api=http://127.0.0.1:5000 when the page is served by something else.
 * The override is accepted for loopback addresses only, so a crafted link
 * cannot make the dashboard send scan targets to another host.
 */
function resolveApiBase() {
    const override = new URLSearchParams(window.location.search).get('api');
    if (override) {
        try {
            const url = new URL(override);
            const isLoopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
            if (isLoopback && (url.protocol === 'http:' || url.protocol === 'https:')) {
                return url.origin;
            }
        } catch {
            /* ignore a malformed override */
        }
    }
    return window.location.protocol === 'file:' ? 'http://127.0.0.1:5000' : '';
}

const API_BASE = resolveApiBase();
const apiUrl = (path) => API_BASE + path;

class EngineUnreachableError extends Error {
    constructor() {
        super(
            'Cannot reach the Security Engine. Make sure it is running (flask --app app run), then try again.',
        );
    }
}

/** Fetch an API path and parse the JSON body. Any non-JSON answer means the engine is not there. */
async function fetchJson(path, options) {
    let response;
    try {
        response = await fetch(apiUrl(path), options);
    } catch {
        throw new EngineUnreachableError();
    }
    if (!(response.headers.get('content-type') || '').includes('application/json')) {
        throw new EngineUnreachableError();
    }
    return { ok: response.ok, data: await response.json() };
}

/* --------------------------------------------------------------- scan form */

function selectedModules() {
    return [...document.querySelectorAll('input[name="module"]:checked:not(:disabled)')].map((input) => input.value);
}

function setAllModules(checked) {
    document.querySelectorAll('input[name="module"]').forEach((input) => {
        input.checked = checked;
    });
}

function normalizeUrl(raw) {
    const value = raw.trim();
    if (!value) return '';
    return /^https?:\/\//i.test(value) ? value : `https://${value}`;
}

function showFormError(message) {
    const box = $('form-error');
    box.textContent = message;
    box.hidden = !message;
}

function setBusy(busy) {
    const button = $('scan-button');
    button.disabled = busy;
    button.textContent = busy ? 'Scanning…' : 'Start scan';
}

function showProgress(percent, message) {
    const value = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : 0;
    $('progress-section').hidden = false;
    $('progress-bar').value = value;
    $('progress-text').textContent = `${Math.round(value)}%  ${message || 'Running security checks…'}`;
}

function hideProgress() {
    $('progress-section').hidden = true;
}

async function onSubmit(event) {
    event.preventDefault();
    showFormError('');

    const url = normalizeUrl($('target-url').value);
    if (!url) {
        showFormError('Enter the address of the website to scan, for example https://example.com');
        return;
    }
    const modules = selectedModules();
    if (modules.length === 0) {
        showFormError('Select at least one check to run.');
        return;
    }
    $('target-url').value = url;

    setBusy(true);
    $('results-section').hidden = true;
    showProgress(5, 'Checking that the website can be reached…');

    try {
        const { ok, data } = await fetchJson('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url,
                scan_types: modules,
                use_burp: modules.includes('burp'),
                use_selenium: modules.includes('browser'),
            }),
        });
        if (!ok || data.error) throw new Error(data.error || 'The scan could not be started.');

        currentScanId = data.scan_id;
        showProgress(10, 'Scan started…');
        trackScan(data.scan_id);
    } catch (error) {
        failScan(error.message);
    }
}

/* ------------------------------------------------------------ live progress */

function stopTracking() {
    if (eventStream) {
        eventStream.close();
        eventStream = null;
    }
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

function failScan(message) {
    stopTracking();
    setBusy(false);
    hideProgress();
    showFormError(message);
}

/**
 * Follow a scan with Server-Sent Events, falling back to polling when events
 * are unavailable, fail, or reach the server's 60-second window. The scan
 * keeps running on the server in every case.
 */
function trackScan(scanId) {
    stopTracking();
    let finished = false;

    const finish = () => {
        if (finished) return;
        finished = true;
        stopTracking();
        finishScan(scanId);
    };

    const startPolling = () => {
        if (pollTimer || finished) return;
        pollTimer = setInterval(() => poll(scanId, finish), POLL_INTERVAL_MS);
    };

    if (typeof EventSource === 'undefined') {
        startPolling();
        return;
    }

    const fallBackToPolling = () => {
        if (eventStream) {
            eventStream.close();
            eventStream = null;
        }
        startPolling();
    };

    eventStream = new EventSource(apiUrl(`/api/scan/stream/${encodeURIComponent(scanId)}`));
    eventStream.onmessage = (event) => {
        let update;
        try {
            update = JSON.parse(event.data);
        } catch {
            return;
        }
        showProgress(update.progress, update.current_message);
        if (update.status === 'completed' || update.status === 'error') finish();
    };
    eventStream.addEventListener('done', finish);
    eventStream.addEventListener('timeout', fallBackToPolling);
    eventStream.onerror = () => {
        if (!finished) fallBackToPolling();
    };
}

async function poll(scanId, finish) {
    try {
        const { data } = await fetchJson(`/api/scan/status/${encodeURIComponent(scanId)}`);
        if (data.error) {
            failScan(data.error);
            return;
        }
        showProgress(data.progress, data.current_message);
        if (data.status === 'completed' || data.status === 'error') finish();
    } catch {
        /* A brief network problem should not end the scan view; the next poll retries. */
    }
}

async function finishScan(scanId) {
    try {
        const { data } = await fetchJson(`/api/scan/status/${encodeURIComponent(scanId)}`);
        if (data.error) throw new Error(data.error);

        setBusy(false);
        hideProgress();
        if (data.status === 'completed') {
            saveToHistory(data);
            renderResults(data);
        } else {
            showFormError(data.current_message || 'The scan stopped because of an error.');
        }
        renderHistory();
    } catch (error) {
        failScan(error.message);
    }
}

/* ------------------------------------------------------------------ results */

function renderResults(data) {
    currentScanId = data.scan_id || currentScanId;
    const findings = Array.isArray(data.findings) ? data.findings : [];
    const coverage = Array.isArray(data.owasp_coverage) ? data.owasp_coverage : [];

    $('result-target').textContent = data.target_url || 'Unknown';
    $('result-id').textContent = (data.scan_id || '').slice(0, 8);

    renderRisk(data.risk);
    renderCounts(data.stats);
    renderDownloads(data.scan_id);
    renderAttribution(data.deployment_info, data.developer_info);
    renderOwasp(coverage, owaspWasSelected(data));
    renderFindings(findings, coverage);
    renderRoadmap(findings);
    renderEngineModules(data.engine_modules);

    const section = $('results-section');
    section.hidden = false;
    section.focus({ preventScroll: true });
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    section.scrollIntoView?.({ behavior: reduceMotion ? 'auto' : 'smooth' });
}

function renderRisk(risk) {
    const hasScore = Boolean(risk) && typeof risk.score === 'number';
    $('risk-score').textContent = hasScore ? String(risk.score) : '–';
    $('risk-grade').textContent = hasScore ? `Grade ${risk.grade} · ${risk.label}` : 'Not available';
    const bar = $('risk-bar');
    bar.value = hasScore ? Math.min(100, risk.score) : 0;
    bar.className = hasScore ? `grade-${String(risk.grade).toLowerCase()}` : '';
}

function renderCounts(stats) {
    const counts = stats || {};
    replaceContent(
        $('severity-counts'),
        SEVERITIES.map((severity) =>
            h(
                'li',
                { class: severity },
                h('strong', { text: String(counts[severity] || 0) }),
                SEVERITY_LABELS[severity],
            ),
        ),
    );
}

function renderDownloads(scanId) {
    for (const format of ['pdf', 'html', 'json']) {
        $(`download-${format}`).href = apiUrl(`/api/report/${encodeURIComponent(scanId)}?format=${format}`);
    }
}

function fact(label, value) {
    return h('div', {}, h('dt', { text: label }), h('dd', {}, value));
}

function socialLink(profile) {
    const url = safeHref(typeof profile === 'string' ? profile : profile && profile.url);
    if (!url) return null;
    const label =
        typeof profile === 'object' && profile.handle
            ? `${profile.platform || 'Profile'}: ${profile.handle}`
            : url.replace(/^https?:\/\//, '');
    return h('a', { href: url, rel: 'noopener noreferrer', target: '_blank', text: label });
}

function renderAttribution(deployment, developer) {
    const site = deployment || {};
    const dev = developer || {};
    const address = [site.ip_address, site.asn && site.asn !== 'N/A' ? `(${site.asn})` : null]
        .filter(Boolean)
        .join(' ');
    const profiles = (Array.isArray(dev.social_footprint) ? dev.social_footprint : [])
        .slice(0, 3)
        .map(socialLink)
        .filter(Boolean);

    replaceContent(
        $('attribution'),
        fact('Platform', site.platform || 'Unknown'),
        fact('Server header', site.server_header || 'Not shown'),
        fact('Location', site.location || 'Unknown'),
        fact('IP address', address || 'Unknown'),
        fact('Hosting provider', site.hosting_org || 'Unknown'),
        fact('Developer', dev.developer_name || 'Not disclosed'),
        fact('Organisation', dev.organization || 'Not disclosed'),
        fact('Source', `${dev.discovery_source || 'None'} (${dev.confidence || 'Low'} confidence)`),
        fact(
            'Profiles',
            profiles.length ? profiles.flatMap((link, i) => (i ? [', ', link] : [link])) : 'None found',
        ),
    );
}

function owaspWasSelected(data) {
    if (data.owasp_ran !== undefined) return Boolean(data.owasp_ran);
    const types = data.scan_types || [];
    return ['owasp', 'vulnerabilities', 'all'].some((type) => types.includes(type));
}

function renderOwasp(coverage, injectionTestsSelected) {
    $('owasp-notice').hidden = injectionTestsSelected;
    replaceContent(
        $('owasp-body'),
        coverage.map((category) => {
            const counts = category.counts || {};
            const untested =
                !injectionTestsSelected && (category.status === 'not_tested' || category.status === 'clear');
            return h(
                'tr',
                {},
                h('td', { text: category.code }),
                h('td', { text: category.name }),
                h('td', {
                    class: `result ${untested ? 'not_tested' : category.status}`,
                    text: untested ? 'Not selected' : RESULT_LABELS[category.status] || category.status,
                }),
                h('td', {
                    class: 'num',
                    text: [counts.critical, counts.high, counts.medium, counts.low]
                        .map((n) => n || 0)
                        .join(' / '),
                }),
            );
        }),
    );
}

function detailsList(details) {
    const entries = Object.entries(details || {}).slice(0, 4);
    if (entries.length === 0) return null;
    return h(
        'dl',
        { class: 'details' },
        entries.map(([key, value]) => {
            const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
            return h(
                'div',
                {},
                h('dt', { text: key }),
                h('dd', { text: text.length > 120 ? `${text.slice(0, 120)}…` : text }),
            );
        }),
    );
}

function findingCard(finding) {
    const severity = SEVERITIES.includes(finding.severity) ? finding.severity : 'info';
    const tags = [
        finding.owasp_code,
        ...(Array.isArray(finding.cwe) ? finding.cwe : []),
        finding.type,
    ].filter(Boolean);
    return h(
        'article',
        { class: `finding ${severity}` },
        h(
            'p',
            { class: 'meta' },
            h('span', { class: `sev ${severity}`, text: severity }),
            tags.length ? ` · ${tags.join(' · ')}` : '',
        ),
        h('h4', { text: finding.title || 'Finding' }),
        finding.description ? h('p', { text: finding.description }) : null,
        detailsList(finding.details),
        finding.remediation
            ? h('p', { class: 'fix' }, h('strong', { text: 'How to fix: ' }), finding.remediation)
            : null,
    );
}

function findingGroup(title, items) {
    return h(
        'div',
        { class: 'group' },
        h('h4', { text: `${title} (${items.length})` }),
        sortBySeverity(items).map(findingCard),
    );
}

function renderFindings(findings, coverage) {
    const container = $('findings');
    if (findings.length === 0) {
        replaceContent(
            container,
            h('p', { text: 'No findings. This only means the selected checks reported nothing.' }),
        );
        return;
    }
    if (coverage.length === 0) {
        replaceContent(container, findingGroup('All findings', findings));
        return;
    }
    const known = new Set(coverage.map((category) => category.key));
    const worstRank = (items) => Math.min(...items.map((f) => SEVERITY_RANK[f.severity] ?? 5));
    // Most serious category first; categories with equal severity keep OWASP order.
    const groups = coverage
        .map((category) => [
            `${category.code} ${category.name}`,
            findings.filter((f) => f.owasp === category.key),
        ])
        .concat([['Informational and other findings', findings.filter((f) => !known.has(f.owasp))]])
        .filter(([, items]) => items.length > 0)
        .sort(([, a], [, b]) => worstRank(a) - worstRank(b));
    replaceContent(
        container,
        groups.map(([title, items]) => findingGroup(title, items)),
    );
}

function renderRoadmap(findings) {
    const columns = [
        { title: 'Fix now (critical and high)', severities: ['critical', 'high'], items: [] },
        { title: 'Plan next (medium)', severities: ['medium'], items: [] },
        { title: 'Improve when you can (low and informational)', severities: ['low', 'info'], items: [] },
    ];
    const seen = new Set();
    for (const finding of sortBySeverity(findings)) {
        const key = `${finding.title}|${finding.remediation}`;
        if (!finding.remediation || seen.has(key)) continue;
        seen.add(key);
        columns.find((column) => column.severities.includes(finding.severity))?.items.push(finding);
    }

    replaceContent(
        $('roadmap'),
        h(
            'div',
            { class: 'roadmap' },
            columns.map((column) =>
                h(
                    'div',
                    {},
                    h('h4', { text: column.title }),
                    column.items.length === 0
                        ? h('p', { class: 'hint', text: 'Nothing identified.' })
                        : h(
                              'ul',
                              {},
                              column.items.slice(0, 12).map((item) =>
                                  h(
                                      'li',
                                      {},
                                      h('strong', {
                                          text: `${item.owasp_code ? `[${item.owasp_code}] ` : ''}${item.title}: `,
                                      }),
                                      item.remediation,
                                  ),
                              ),
                          ),
                ),
            ),
        ),
    );
}

function renderEngineModules(modules) {
    replaceContent(
        $('engine-modules'),
        (Array.isArray(modules) ? modules : []).map((module) =>
            h(
                'li',
                {},
                h('strong', { text: module.ran ? 'Ran' : 'Skipped' }),
                ` · ${module.name}: ${module.description}`,
            ),
        ),
    );
}

/* ------------------------------------------------------------------ history */

function readHistory() {
    try {
        const list = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        return Array.isArray(list) ? list.filter((scan) => scan && scan.scan_id) : [];
    } catch {
        return [];
    }
}

function saveToHistory(data) {
    if (!data || !data.scan_id) return;
    try {
        localStorage.setItem(SCAN_KEY_PREFIX + data.scan_id, JSON.stringify(data));
        const history = readHistory().filter((scan) => scan.scan_id !== data.scan_id);
        history.unshift({
            scan_id: data.scan_id,
            target_url: data.target_url || 'Unknown target',
            start_time: data.start_time || new Date().toISOString(),
            status: data.status || 'completed',
            stats: data.stats || {},
            risk: data.risk || {},
        });
        for (const dropped of history.splice(HISTORY_LIMIT)) {
            localStorage.removeItem(SCAN_KEY_PREFIX + dropped.scan_id);
        }
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
        /* Storage can be full or blocked; history is a convenience, not required. */
    }
}

function formatTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}

function renderHistory() {
    const history = readHistory().slice(0, HISTORY_SHOWN);
    $('clear-history').hidden = history.length === 0;
    if (history.length === 0) {
        replaceContent(
            $('history'),
            h('p', { text: 'No scans yet. Results appear here after you run one.' }),
        );
        return;
    }
    replaceContent(
        $('history'),
        history.map((scan) => {
            const stats = scan.stats || {};
            const grade = scan.risk && scan.risk.grade ? `Grade ${scan.risk.grade} · ` : '';
            const button = h(
                'button',
                { type: 'button', class: 'history-item' },
                h(
                    'span',
                    {},
                    h('span', { class: 'where', text: scan.target_url }),
                    h('span', {
                        class: 'when',
                        text: `${formatTime(scan.start_time)} · ID ${String(scan.scan_id).slice(0, 8)}`,
                    }),
                ),
                h('span', {
                    class: 'tally',
                    text: `${grade}${stats.critical || 0} critical · ${stats.high || 0} high`,
                }),
            );
            button.addEventListener('click', () => openHistoryScan(scan.scan_id));
            return button;
        }),
    );
}

async function openHistoryScan(scanId) {
    try {
        const saved = localStorage.getItem(SCAN_KEY_PREFIX + scanId);
        if (saved) {
            renderResults(JSON.parse(saved));
            return;
        }
    } catch {
        /* fall through to the server */
    }
    try {
        const { data } = await fetchJson(`/api/scan/status/${encodeURIComponent(scanId)}`);
        if (data && !data.error) {
            renderResults(data);
            return;
        }
    } catch {
        /* handled below */
    }
    showFormError('That scan is no longer available.');
}

function clearHistory() {
    if (!window.confirm('Remove the scan history saved in this browser?')) return;
    try {
        for (const scan of readHistory()) localStorage.removeItem(SCAN_KEY_PREFIX + scan.scan_id);
        localStorage.removeItem(HISTORY_KEY);
    } catch {
        /* nothing to clean up */
    }
    renderHistory();
}

/* ---------------------------------------------------------- engine status */

async function checkEngine() {
    const status = $('engine-status');
    try {
        const response = await fetch(apiUrl('/api/history'), { cache: 'no-store' });
        if (!response.ok) throw new Error('not ok');
        status.className = 'status online';
        status.textContent = 'Engine online';
    } catch {
        status.className = 'status offline';
        status.textContent = 'Engine not reachable. Start it with: flask --app app run';
    }
}

/* --------------------------------------------------------------------- start */

function init() {
    $('scan-form').addEventListener('submit', onSubmit);
    $('select-all').addEventListener('click', () => setAllModules(true));
    $('select-none').addEventListener('click', () => setAllModules(false));
    $('clear-history').addEventListener('click', clearHistory);
    renderHistory();
    checkEngine();
    setInterval(checkEngine, HEALTH_INTERVAL_MS);
}

init();
