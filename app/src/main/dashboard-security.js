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

module.exports = { protectDashboardNavigation, assertDashboardIpcSender };
