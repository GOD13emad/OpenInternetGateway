'use strict';

// Read only the current, public, shared VPNBook OpenVPN login from its HTTPS page.
// Never save the password, reuse a stale response or initiate a VPN connection.
const OFFICIAL_URL = 'https://www.vpnbook.com/freevpn/openvpn';
const MAX_BYTES = 512 * 1024;
const MAX_AGE_MS = 21 * 24 * 60 * 60 * 1000;

function parsePublicLogin(html, now = Date.now()) {
  if (typeof html !== 'string' || Buffer.byteLength(html) > MAX_BYTES) {
    throw new Error('VPNBook credential page is missing or too large.');
  }
  // Strip active/irrelevant markup before parsing; page contents are untrusted data.
  const page = html.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]*>/g, ' ').replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/\s+/g, ' ');
  const section = /\bVPN Credentials\b([\s\S]{0,800})/i.exec(page);
  if (!section) throw new Error('Official VPNBook login section was not found.');
  const matches = [...section[1].matchAll(/\bUsername\s+vpnbook\s+Copy\s+Password\s+([A-Za-z0-9]{4,32})\s+Copy\s+Last updated:\s+([A-Za-z]{3}\s+\d{1,2},\s+\d{4})/gi)];
  if (matches.length !== 1) throw new Error('Official VPNBook login is missing or ambiguous.');
  const timestamp = Date.parse(matches[0][2] + ' 00:00:00 GMT');
  if (!Number.isFinite(timestamp) || !Number.isFinite(now) ||
      timestamp - now > 24 * 60 * 60 * 1000 || now - timestamp > MAX_AGE_MS) {
    throw new Error('Official VPNBook login update date is stale or invalid.');
  }
  return {
    username: 'vpnbook', password: matches[0][1],
    lastUpdated: new Date(timestamp).toISOString().slice(0, 10),
    source: OFFICIAL_URL
  };
}

async function fetchPublicLogin({ request = fetch, now = Date.now } = {}) {
  try {
    const response = await request(OFFICIAL_URL, {
      redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000),
      headers: { Accept: 'text/html' }
    });
    if (response?.status !== 200 || response.url !== OFFICIAL_URL ||
        !/^text\/html\b/i.test(response.headers?.get('content-type') || '')) {
      throw new Error('Invalid official VPNBook response.');
    }
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BYTES) {
      throw new Error('VPNBook response exceeds the maximum size.');
    }
    if (!response.body) throw new Error('VPNBook response has no body.');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.byteLength;
      if (size > MAX_BYTES) throw new Error('VPNBook response exceeds the maximum size.');
      chunks.push(Buffer.from(chunk));
    }
    return parsePublicLogin(Buffer.concat(chunks).toString('utf8'), now());
  } catch {
    // Never echo untrusted page contents, URL parameters, or credential material.
    throw new Error('Cannot securely retrieve current free VPNBook credentials. Visit vpnbook.com/freevpn/openvpn.');
  }
}

module.exports = { OFFICIAL_URL, MAX_BYTES, parsePublicLogin, fetchPublicLogin };
