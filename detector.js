/**
 * detector.js
 * -----------
 * A heuristic DNS-tunneling detection engine.
 *
 * DNS tunneling abuses the DNS protocol to smuggle data (C2 traffic, file
 * exfiltration, etc.) inside queries that are technically valid but
 * behaviorally abnormal. No single query "looks evil" — the tell is in
 * the *pattern* across many queries to the same domain. This module scores
 * domains, not individual packets, by combining several independent signals:
 *
 *   1. Label entropy      — encoded payloads (base32/base64/hex) look random.
 *   2. Label length        — attackers pack data close to the 63-byte label
 *                            ceiling and the 253-byte name ceiling.
 *   3. Charset shape       — payload-bearing labels cluster tightly around
 *                            base32/base64 alphabets instead of natural words.
 *   4. Query-type mix      — TXT and NULL records carry more data per query
 *                            and are disproportionately used by tunneling
 *                            tools (iodine, dnscat2, dns2tcp, DNSCat...).
 *   5. Subdomain cardinality/uniqueness — normal traffic re-requests a small
 *                            set of names; tunneling mints a new, never-
 *                            repeated subdomain per chunk of data.
 *   6. Query rate           — sustained high-frequency queries to one apex
 *                            domain from a single host is unusual for
 *                            legitimate resolution traffic.
 *
 * This is an educational/demo heuristic engine, not a production IDS.
 * Real deployments should tune thresholds against their own baseline
 * traffic and combine this with allow-lists, threat intel, and NXDOMAIN
 * ratio analysis.
 */

const Detector = (() => {

  // ---- Signal primitives -----------------------------------------------

  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return Object.values(freq).reduce((h, count) => {
      const p = count / len;
      return h - p * Math.log2(p);
    }, 0);
  }

  // Leftmost label chain (everything before the registrable apex domain).
  // Simplified: treats the last two labels as the apex (fine for the
  // .com/.net/.org-style names used in this demo dataset).
  function splitName(fqdn) {
    const labels = fqdn.split('.').filter(Boolean);
    if (labels.length <= 2) {
      return { apex: fqdn, subLabels: [] };
    }
    const apex = labels.slice(-2).join('.');
    const subLabels = labels.slice(0, -2);
    return { apex, subLabels };
  }

  // How closely a string's charset matches a base32/base64-style payload
  // alphabet, as a 0..1 fraction of characters that are "codey" rather
  // than dictionary-word-like.
  function payloadCharsetRatio(str) {
    if (!str) return 0;
    const codey = str.match(/[A-Za-z0-9+/=_-]/g) || [];
    const vowels = str.match(/[aeiouAEIOU]/g) || [];
    // Real words have vowels roughly ~35-45% of letters; encoded payloads
    // are vowel-starved because they're statistically uniform over the
    // alphabet. Low vowel ratio + long length is a strong tell.
    const vowelRatio = str.length ? vowels.length / str.length : 0;
    const codeyRatio = str.length ? codey.length / str.length : 0;
    return Math.max(0, codeyRatio - vowelRatio);
  }

  const TUNNELING_QTYPES = new Set(['TXT', 'NULL', 'CNAME']);

  // ---- Per-domain aggregation --------------------------------------------

  function analyze(queries) {
    const byApex = new Map();

    for (const q of queries) {
      const { apex, subLabels } = splitName(q.queryName);
      if (!byApex.has(apex)) {
        byApex.set(apex, {
          apex,
          queries: [],
          subLabelSet: new Set(),
          sourceIPs: new Set(),
          qtypeCounts: {},
        });
      }
      const bucket = byApex.get(apex);
      bucket.queries.push(q);
      bucket.sourceIPs.add(q.srcIp);
      bucket.qtypeCounts[q.queryType] = (bucket.qtypeCounts[q.queryType] || 0) + 1;
      if (subLabels.length) bucket.subLabelSet.add(subLabels.join('.'));
    }

    const results = [];
    for (const bucket of byApex.values()) {
      results.push(scoreDomain(bucket));
    }
    results.sort((a, b) => b.score - a.score);
    return results;
  }

  function scoreDomain(bucket) {
    const total = bucket.queries.length;
    const uniqueSub = bucket.subLabelSet.size;
    const uniqueRatio = total ? uniqueSub / total : 0;

    let entropySum = 0;
    let labelLenSum = 0;
    let maxLabelLen = 0;
    let charsetSum = 0;
    let scored = 0;

    for (const label of bucket.subLabelSet) {
      const leaf = label.split('.')[0]; // innermost/leftmost label
      entropySum += shannonEntropy(leaf);
      labelLenSum += leaf.length;
      maxLabelLen = Math.max(maxLabelLen, leaf.length);
      charsetSum += payloadCharsetRatio(leaf);
      scored++;
    }

    const avgEntropy = scored ? entropySum / scored : 0;
    const avgLabelLen = scored ? labelLenSum / scored : 0;
    const avgCharsetRatio = scored ? charsetSum / scored : 0;

    const tunnelingTypeHits = Object.entries(bucket.qtypeCounts)
      .filter(([t]) => TUNNELING_QTYPES.has(t))
      .reduce((sum, [, c]) => sum + c, 0);
    const tunnelingTypeRatio = total ? tunnelingTypeHits / total : 0;

    const timestamps = bucket.queries.map(q => new Date(q.timestamp).getTime()).sort((a, b) => a - b);
    const spanMinutes = timestamps.length > 1
      ? Math.max((timestamps[timestamps.length - 1] - timestamps[0]) / 60000, 0.1)
      : 0.1;
    const queriesPerMinute = total / spanMinutes;

    // ---- Weighted composite score (0-100) --------------------------------
    // Each term is normalized to roughly 0..1 before weighting so no single
    // signal can dominate the score on its own; a real incident should trip
    // several signals at once.
    const entropyTerm = clamp01(avgEntropy / 4.5);       // ~4.5 bits/char ≈ near-random
    const lengthTerm = clamp01(avgLabelLen / 45);         // long labels are suspicious
    const charsetTerm = clamp01(avgCharsetRatio / 0.6);
    const uniqueTerm = clamp01(uniqueRatio);              // near 1 = every query is new data
    const typeTerm = clamp01(tunnelingTypeRatio);
    const rateTerm = clamp01(queriesPerMinute / 30);      // 30+ qpm to one apex is a lot
    const volumeTerm = clamp01(total / 150);              // sheer volume to one apex domain

    const score = Math.round(100 * (
      entropyTerm * 0.26 +
      lengthTerm * 0.16 +
      charsetTerm * 0.14 +
      uniqueTerm * 0.20 +
      typeTerm * 0.10 +
      rateTerm * 0.08 +
      volumeTerm * 0.06
    ));

    let severity = 'clean';
    if (score >= 70) severity = 'critical';
    else if (score >= 40) severity = 'suspicious';

    const dominantType = Object.entries(bucket.qtypeCounts)
      .sort((a, b) => b[1] - a[1])[0]?.[0] || '—';

    const samples = [...bucket.queries]
      .sort((a, b) => shannonEntropy(splitName(b.queryName).subLabels.join('')) - shannonEntropy(splitName(a.queryName).subLabels.join('')))
      .slice(0, 6);

    return {
      apex: bucket.apex,
      score,
      severity,
      totalQueries: total,
      uniqueSubdomains: uniqueSub,
      uniqueRatio,
      avgEntropy,
      avgLabelLen,
      maxLabelLen,
      dominantType,
      tunnelingTypeRatio,
      queriesPerMinute,
      sourceIPs: [...bucket.sourceIPs],
      samples,
      signals: {
        entropyTerm, lengthTerm, charsetTerm, uniqueTerm, typeTerm, rateTerm, volumeTerm,
      },
    };
  }

  function clamp01(x) {
    return Math.max(0, Math.min(1, x));
  }

  return { analyze, shannonEntropy, splitName, payloadCharsetRatio };
})();
