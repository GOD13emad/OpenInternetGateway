// The privileged gateway preload is authorized only in the packaged local dashboard.
function protectDashboardNavigation(contents) {
  contents.on('will-navigate', event => event.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
}

function assertDashboardIpcSender(event, window, expectedUrl) {
  const contents = window?.webContents;
  if (!contents || contents.isDestroyed?.() || event?.sender !== contents ||
      !contents.mainFrame || event.senderFrame !== contents.mainFrame ||
      contents.mainFrame.url !== expectedUrl) {
    throw new Error('GATEWAY_IPC_SENDER_DENIED');
  }
}

const TRUSTED_RELEASE_FALLBACK = 'https://github.com/GOD13emad/OpenInternetGateway/releases/latest';

// The release URL may arrive from an on-disk cache or remote metadata.
// Never pass an arbitrary protocol/host/path to OS shell.openExternal.
function trustedReleaseUrl(candidate) {
  try {
    const url = new URL(String(candidate));
    if (url.protocol !== 'https:' || url.hostname !== 'github.com' ||
        url.username || url.password || url.port || url.search || url.hash ||
        !/^\/GOD13emad\/OpenInternetGateway\/releases\/(?:latest|tag\/[A-Za-z0-9._-]+)$/.test(url.pathname)) {
      return TRUSTED_RELEASE_FALLBACK;
    }
    return url.href;
  } catch {
    return TRUSTED_RELEASE_FALLBACK;
  }
}

module.exports = { protectDashboardNavigation, assertDashboardIpcSender, trustedReleaseUrl };
