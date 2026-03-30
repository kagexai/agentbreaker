(function () {
  if (typeof window === "undefined" || typeof window.EventSource === "undefined") {
    return;
  }
  let lastRefreshAt = 0;
  const refreshCooldownMs = 4000;

  function dispatch(payload) {
    try {
      window.dispatchEvent(new CustomEvent("agentbreaker:update", { detail: payload || {} }));
    } catch (_) {
      // no-op
    }
  }

  function maybeRefresh(payload) {
    if (window.AGENTBREAKER_DISABLE_AUTO_REFRESH) {
      return;
    }
    if (typeof window.AGENTBREAKER_REFRESH === "function") {
      const now = Date.now();
      if (now - lastRefreshAt < refreshCooldownMs) {
        return;
      }
      lastRefreshAt = now;
      window.AGENTBREAKER_REFRESH(payload || {});
    }
  }

  const stream = new EventSource("/api/events");
  stream.addEventListener("ready", function (event) {
    let payload = {};
    try {
      payload = JSON.parse(event.data || "{}");
    } catch (_) {
      payload = {};
    }
    dispatch({ type: "ready", payload: payload });
  });
  stream.addEventListener("update", function (event) {
    let payload = {};
    try {
      payload = JSON.parse(event.data || "{}");
    } catch (_) {
      payload = {};
    }
    dispatch({ type: "update", payload: payload });
    maybeRefresh(payload);
  });
})();
