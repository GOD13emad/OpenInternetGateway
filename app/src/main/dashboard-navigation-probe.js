'use strict';

// Read-only interaction coverage for the installed dashboard on a disposable
// Windows CI runner. This script deliberately never calls gateway.action or
// clicks the power, recovery, update, relay or diagnostics controls.
const navigationScript = String.raw`(() => {
  const find = page => document.querySelector('button.nav-item[data-page="' + page + '"]');
  const activePage = page => {
    const button = find(page);
    const section = document.getElementById('page-' + page);
    return !!button && !!section
      && button.classList.contains('active')
      && section.classList.contains('active')
      && document.querySelectorAll('section.page.active').length === 1;
  };
  if (document.readyState === 'loading') throw new Error('DOM_NOT_READY');
  if (document.querySelectorAll('button.nav-item').length !== 6) throw new Error('NAV_COUNT_INVALID');
  if (!document.getElementById('powerButton')) throw new Error('POWER_CONTROL_MISSING');
  if (!activePage('overview')) throw new Error('INITIAL_PAGE_INVALID');
  const settings = find('settings');
  settings.click();
  if (!activePage('settings') || document.getElementById('pageTitle').textContent !== 'Settings') {
    throw new Error('SETTINGS_NAVIGATION_FAILED');
  }
  find('overview').click();
  if (!activePage('overview') || document.getElementById('pageTitle').textContent !== 'Overview') {
    throw new Error('OVERVIEW_RETURN_FAILED');
  }
  return { pass: true, pagesVisited: ['settings', 'overview'],
    navigationClicked: true, powerControlInvoked: false };
})()`;

async function probeReadOnlyNavigation(webContents) {
  const result = await webContents.executeJavaScript(navigationScript, true);
  if (result?.pass !== true ||
      result.navigationClicked !== true ||
      result.powerControlInvoked !== false ||
      JSON.stringify(result.pagesVisited) !== JSON.stringify(['settings', 'overview'])) {
    throw new Error('DESKTOP_NAVIGATION_PROBE_INVALID');
  }
  return result;
}
module.exports = { navigationScript, probeReadOnlyNavigation };
