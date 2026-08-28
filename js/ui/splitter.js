(function(global) {
  'use strict';

  function dragHandle(handle, apply) {
    if (!handle) return;
    handle.addEventListener("pointerdown", e => {
      e.preventDefault();
      handle.setPointerCapture(e.pointerId);
      handle.classList.add("dragging");
      const move = ev => apply(ev);
      const up = () => {
        handle.classList.remove("dragging");
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", up);
        handle.removeEventListener("pointercancel", up);
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", up);
      handle.addEventListener("pointercancel", up);
    });
  }

  function applyCols(ws, ev) {
    if (!ws) return;
    const r = ws.getBoundingClientRect();
    let pct = ((ev.clientX - r.left) / r.width) * 100;
    pct = Math.max(15, Math.min(85, pct));
    ws.style.gridTemplateColumns = pct + "% 5px minmax(0,1fr)";
  }

  function initSplitters() {
    const $ = id => document.getElementById(id);

    dragHandle($("hsplit"), ev => {
      const dp = $("detailsPane");
      if (!dp) return;
      const h = Math.max(70, Math.min(window.innerHeight - 240, dp.getBoundingClientRect().bottom - ev.clientY));
      dp.style.height = h + "px";
    });

    dragHandle($("hsplit2"), ev => {
      const hp = $("hexPane");
      if (!hp) return;
      const h = Math.max(60, Math.min(window.innerHeight - 200, window.innerHeight - ev.clientY));
      hp.style.height = h + "px";
      hp.style.flex = "none";
    });

    dragHandle($("vsplitP"), ev => applyCols($("wsPkcs7"), ev));
    dragHandle($("vsplitX"), ev => applyCols($("wsX509"), ev));
  }

  const splitterModule = {
    dragHandle,
    applyCols,
    initSplitters
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = splitterModule;
  }
  global.PKCS7Splitter = splitterModule;
})(typeof window !== 'undefined' ? window : global);
