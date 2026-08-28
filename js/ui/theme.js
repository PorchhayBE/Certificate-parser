(function(global) {
  'use strict';

  function initTheme() {
    let t = null;
    const m = location.hash.match(/theme=(light|dark)/);
    if (m) {
      t = m[1];
    } else {
      try {
        t = localStorage.getItem("pkcs7-theme");
      } catch (e) {}
      if (t !== "light" && t !== "dark") {
        t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
      }
    }
    document.documentElement.setAttribute("data-theme", t);
    applyThemeLabel();
  }

  function applyThemeLabel() {
    const light = document.documentElement.getAttribute("data-theme") === "light";
    const mt = document.querySelector('meta[name="theme-color"]');
    if (mt) mt.setAttribute("content", light ? "#ffffff" : "#151b24");
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", cur);
    try {
      localStorage.setItem("pkcs7-theme", cur);
    } catch (e) {}
    applyThemeLabel();
    return cur;
  }

  const themeModule = {
    initTheme,
    applyThemeLabel,
    toggleTheme
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = themeModule;
  }
  global.PKCS7Theme = themeModule;
})(typeof window !== 'undefined' ? window : global);
