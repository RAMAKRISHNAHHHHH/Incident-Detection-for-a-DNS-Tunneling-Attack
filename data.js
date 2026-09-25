/**
 * data.js
 * -------
 * Generates a synthetic DNS query log: realistic "normal" resolver traffic
 * plus one or two injected DNS-tunneling incidents, so the detector has
 * something real to find. Also exposes a loader for user-supplied JSON logs
 * (see /data/sample-log-schema.json for the expected shape).
 */

const DataSource = (() => {

  const NORMAL_DOMAINS = [
    'google.com', 'github.com', 'cloudflare.com', 'apple.com', 'slack.com',
    'zoom.us', 'wikipedia.org', 'stackoverflow.com', 'npmjs.com', 'notion.so',
  ];
  const NORMAL_SUBS = ['www', 'api', 'cdn', 'static', 'mail', 'assets', 'edge', 'app', 'accounts', ''];
  const NORMAL_QTYPES = ['A', 'AAAA', 'CNAME'];
  const INTERNAL_IPS = ['10.20.4.12', '10.20.4.31', '10.20.4.47', '10.20.5.8', '10.20.5.19', '10.20.6.2'];

  const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
  function pick(arr) { return arr[randInt(0, arr.length - 1)]; }

  function randomB32Label(len) {
    let s = '';
    for (let i = 0; i < len; i++) s += B32_ALPHABET[randInt(0, B32_ALPHABET.length - 1)];
    return s;
  }

  function isoOffset(baseMs, offsetSec) {
    return new Date(baseMs + offsetSec * 1000).toISOString();
  }

  function generateNormalTraffic(baseMs, count) {
    const out = [];
    for (let i = 0; i < count; i++) {
      const apex = pick(NORMAL_DOMAINS);
      const sub = pick(NORMAL_SUBS);
      const name = sub ? `${sub}.${apex}` : apex;
      out.push({
        timestamp: isoOffset(baseMs, randInt(0, 1200)),
        srcIp: pick(INTERNAL_IPS),
        queryName: name,
        queryType: pick(NORMAL_QTYPES),
      });
    }
    return out;
  }

  // Simulates a tool like iodine/dnscat2: many unique, high-entropy,
  // near-max-length labels under one attacker-controlled apex domain,
  // skewed toward TXT/NULL records, from one or two compromised hosts,
  // at an elevated, fairly steady rate.
  function generateTunnelingIncident(baseMs, apexDomain, opts = {}) {
    const {
      count = 220,
      sourceIps = ['10.20.5.19'],
      labelLenRange = [38, 58],
      qtypeWeights = { TXT: 0.55, NULL: 0.25, CNAME: 0.2 },
      windowSec = 900,
    } = opts;

    const out = [];
    const types = Object.keys(qtypeWeights);
    const weights = Object.values(qtypeWeights);

    for (let i = 0; i < count; i++) {
      const len = randInt(labelLenRange[0], labelLenRange[1]);
      // Occasionally split into two labels to mimic staying under the
      // 63-byte single-label limit while still smuggling a long payload.
      const label = len > 45
        ? `${randomB32Label(Math.ceil(len / 2))}.${randomB32Label(Math.floor(len / 2))}`
        : randomB32Label(len);

      let r = Math.random(), acc = 0, qtype = types[0];
      for (let t = 0; t < types.length; t++) {
        acc += weights[t];
        if (r <= acc) { qtype = types[t]; break; }
      }

      out.push({
        timestamp: isoOffset(baseMs, randInt(0, windowSec)),
        srcIp: pick(sourceIps),
        queryName: `${label}.${apexDomain}`,
        queryType: qtype,
      });
    }
    return out;
  }

  function buildDataset() {
    const baseMs = Date.now() - 20 * 60 * 1000; // 20-minute capture window
    let events = [];
    events = events.concat(generateNormalTraffic(baseMs, 380));
    events = events.concat(generateTunnelingIncident(baseMs, 'sync-cdn-update.net', {
      count: 240,
      sourceIps: ['10.20.5.19'],
    }));
    // A second, quieter/lower-volume incident so the tool visibly ranks by
    // severity rather than just volume.
    events = events.concat(generateTunnelingIncident(baseMs, 'telemetry-relay.io', {
      count: 60,
      sourceIps: ['10.20.4.47'],
      labelLenRange: [24, 34],
      qtypeWeights: { TXT: 0.7, A: 0.3 },
    }));
    events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    return events;
  }

  function parseUploadedLog(jsonText) {
    const parsed = JSON.parse(jsonText);
    const arr = Array.isArray(parsed) ? parsed : parsed.queries;
    if (!Array.isArray(arr)) throw new Error('Expected a JSON array of query records, or { "queries": [...] }.');
    return arr.map(r => ({
      timestamp: r.timestamp || new Date().toISOString(),
      srcIp: r.srcIp || r.source_ip || 'unknown',
      queryName: r.queryName || r.query_name || r.name,
      queryType: (r.queryType || r.query_type || r.type || 'A').toUpperCase(),
    })).filter(r => !!r.queryName);
  }

  return { buildDataset, parseUploadedLog };
})();
