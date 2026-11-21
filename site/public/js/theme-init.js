// Applies the theme before the first paint, so a page never flashes the wrong one. A classic script in
// <head>, ahead of the stylesheets, because the CSP allows no inline script. The choice lives in
// localStorage only (no cookie): "light", "dark" or "system" (Match device). Until the reader picks, the
// site is dark. It sets data-theme, which src/design/tokens.css reads, and the browser's theme color;
// src/scripts/site.ts takes over once the page's module loads. The "js" class shows the controls that
// need a script (the theme pill, copy buttons, tabs, search); without a script the page follows the device.
(function () {
  var root = document.documentElement;
  var choice = "dark";
  try { choice = localStorage.getItem("postkeep-theme") || choice; } catch (e) { /* storage blocked */ }
  if (choice !== "light" && choice !== "system") choice = "dark";
  var theme = choice === "system" ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : choice;
  root.setAttribute("data-theme", theme);
  root.setAttribute("data-theme-choice", choice);
  document.querySelectorAll('meta[name="theme-color"]').forEach(function (m) { m.content = m.getAttribute("data-" + theme); });
  root.classList.add("js");
})();
