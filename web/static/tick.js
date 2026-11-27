// The panel's clock: a worker posts a "tick" every 3 s. Browsers space out
// the timers of background tabs (down to one a minute); not a worker's, so
// the page keeps the tab title up to date.
setInterval(() => postMessage("tick"), 3000);
