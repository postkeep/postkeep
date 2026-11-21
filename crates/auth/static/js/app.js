/* postkeep app pages: optional progressive enhancement. Every page works without it.
   Serve same-origin and allow with CSP `script-src 'self'`. No inline handlers, no eval. */
(function () {
  "use strict";
  var doc = document;
  doc.documentElement.classList.add("js");

  // 1. Show / hide secret fields: <button data-toggle-password="ID" hidden>
  doc.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    var input = doc.getElementById(btn.getAttribute("data-toggle-password"));
    if (!input || !input.value && input.readOnly) return;
    var label = btn.querySelector("[data-label]") || btn;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
      label.textContent = show ? "Hide" : "Show";
    });
  });

  // 2. Copy to clipboard: <button data-copy="ID" hidden> copies an input value or element text.
  doc.querySelectorAll("[data-copy]").forEach(function (btn) {
    var src = doc.getElementById(btn.getAttribute("data-copy"));
    if (!src || !navigator.clipboard) return;
    var label = btn.querySelector("[data-label]") || btn;
    var original = label.textContent;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var text = "value" in src && src.tagName !== "CODE" ? src.value : src.textContent;
      navigator.clipboard.writeText(text || "").then(function () {
        label.textContent = "Copied";
        setTimeout(function () { label.textContent = original; }, 1600);
      });
    });
  });

  // 3. Busy state for forms marked data-busy-form: spinner, live status, no double submit.
  doc.querySelectorAll("form[data-busy-form]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var submitter = event.submitter;
      if (form.classList.contains("is-submitting")) { event.preventDefault(); return; }
      if (submitter && (submitter.value === "cancel" || submitter.hasAttribute("formaction"))) return;
      form.classList.add("is-submitting");
      form.setAttribute("aria-busy", "true");
      var status = form.querySelector("[data-busy-status]");
      if (status) { status.textContent = status.getAttribute("data-busy-status"); }
      // Disable after the form data set is built, so name=action value=connect is still sent.
      setTimeout(function () {
        form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; });
      }, 0);
    });
  });

  // 4. OAuth buttons: announce the redirect and prevent double clicks. The button art itself is never changed.
  var oauthStatus = doc.querySelector(".oauth__status");
  doc.querySelectorAll("[data-oauth]").forEach(function (a) {
    a.addEventListener("click", function (event) {
      if (a.classList.contains("is-busy")) { event.preventDefault(); return; }
      a.classList.add("is-busy");
      a.setAttribute("aria-disabled", "true");
      if (oauthStatus) {
        oauthStatus.textContent = (oauthStatus.getAttribute("data-busy-status-template") || "Redirecting…").replace("{provider}", a.getAttribute("data-oauth"));
      }
    });
  });

  // Restore everything if the page comes back from the back/forward cache.
  window.addEventListener("pageshow", function (e) {
    if (!e.persisted) return;
    doc.querySelectorAll("form.is-submitting").forEach(function (form) {
      form.classList.remove("is-submitting");
      form.removeAttribute("aria-busy");
      form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = false; });
    });
    doc.querySelectorAll("[data-oauth].is-busy").forEach(function (a) { a.classList.remove("is-busy"); a.removeAttribute("aria-disabled"); });
    if (oauthStatus) oauthStatus.textContent = "";
  });

  // 5. Guide: open on wide screens, collapsed on phones by default; remember the user's choice.
  var guide = doc.querySelector("details[data-remember]");
  if (guide) {
    var key = "postkeep:" + guide.getAttribute("data-remember");
    var saved = null;
    try { saved = localStorage.getItem(key); } catch (e) {}
    if (saved) guide.open = saved === "open";
    else if (guide.hasAttribute("data-collapse-mobile") && window.matchMedia("(max-width: 900px)").matches) guide.open = false;
    guide.addEventListener("toggle", function () {
      try { localStorage.setItem(key, guide.open ? "open" : "closed"); } catch (e) {}
    });
    doc.querySelectorAll('a[href="#guide"]').forEach(function (a) {
      a.addEventListener("click", function () { guide.open = true; });
    });
  }

  // 6. Typed confirmation: keep the destructive button disabled until the text matches.
  doc.querySelectorAll("[data-confirm-match]").forEach(function (input) {
    var form = input.form; if (!form) return;
    var btn = form.querySelector("[data-confirm-target]"); if (!btn) return;
    var want = input.getAttribute("data-confirm-match").trim().toLowerCase();
    var sync = function () { btn.disabled = input.value.trim().toLowerCase() !== want; };
    input.addEventListener("input", sync); sync();
  });

  // 7. Close an open confirm popover with Escape and return focus to its trigger.
  doc.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    doc.querySelectorAll("details.confirm[open]").forEach(function (d) { d.open = false; var s = d.querySelector("summary"); if (s) s.focus(); });
  });
})();

/* 8. Provider picker: swap the email placeholder to match the chosen provider (layout switching itself is CSS-only). */
(function () {
  var email = document.querySelector("[data-placeholder-imap]");
  if (!email) return;
  var icloud = email.getAttribute("placeholder");
  var sync = function () {
    var imap = document.getElementById("provider-imap");
    email.setAttribute("placeholder", imap && imap.checked ? email.getAttribute("data-placeholder-imap") : icloud);
  };
  document.querySelectorAll('input[name="provider"]').forEach(function (r) { r.addEventListener("change", sync); });
  sync();
})();

/* 9. An address at an offered preset's domain selects that preset and says so.
   Domain lists and the hint text are data-domains / data-override-hint on the options. */
(function () {
  var email = document.getElementById("email");
  var hint = document.getElementById("provider-override");
  if (!email || !hint) return;
  var options = document.querySelectorAll(".picker__opt[data-domains]");
  if (!options.length) return;

  function domainOf(value) {
    var at = value.lastIndexOf("@");
    if (at < 0) return "";
    return value.slice(at + 1).trim().toLowerCase();
  }

  function matched(value) {
    var domain = domainOf(value);
    if (!domain) return null;
    for (var i = 0; i < options.length; i++) {
      var domains = options[i].getAttribute("data-domains").toLowerCase().split(/\s+/);
      if (domains.indexOf(domain) !== -1) return options[i];
    }
    return null;
  }

  function show(text) {
    if (!text) {
      hint.textContent = "";
      hint.hidden = true;
      return;
    }
    hint.hidden = false;
    if (hint.textContent !== text) hint.textContent = text;
  }

  function sync() {
    var option = matched(email.value);
    if (!option) {
      show("");
      return;
    }
    var radio = option.querySelector('input[name="imap_server"]');
    if (radio && !radio.checked) radio.checked = true;
    show(option.getAttribute("data-override-hint") || "");
  }

  email.addEventListener("input", sync);
  email.addEventListener("change", sync);
  document.querySelectorAll('input[name="imap_server"]').forEach(function (radio) {
    radio.addEventListener("change", sync);
  });
  sync();
})();
