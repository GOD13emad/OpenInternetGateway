'use strict';

const DEFAULT_RELEASE_URL = 'https://github.com/GOD13emad/OpenInternetGateway/releases/latest';
const RELEASE_TAG_PATH = /^\/GOD13emad\/OpenInternetGateway\/releases\/tag\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function trustedReleaseUrl(candidate) {
  if (typeof candidate !== 'string' || !candidate || candidate.length > 512 ||
      candidate !== candidate.trim() || candidate.includes('\\')) {
    return DEFAULT_RELEASE_URL;
  }
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return DEFAULT_RELEASE_URL;
  }
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com' ||
      parsed.username || parsed.password || parsed.port || parsed.search || parsed.hash) {
    return DEFAULT_RELEASE_URL;
  }
  if (parsed.pathname === '/GOD13emad/OpenInternetGateway/releases/latest' ||
      RELEASE_TAG_PATH.test(parsed.pathname)) {
    return parsed.href;
  }
  return DEFAULT_RELEASE_URL;
}

module.exports = { DEFAULT_RELEASE_URL, trustedReleaseUrl };
