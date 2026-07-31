// UI behaviours moved out of inline on* attributes so the relay can ship
// a strict Content-Security-Policy (script-src 'self').
(function () {
  "use strict";

  // <form data-confirm="message"> — confirm before submitting.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // <button data-reveal="inputId"> — toggle a password field's visibility.
  document.querySelectorAll("button[data-reveal]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.reveal);
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
      btn.textContent = input.type === "password" ? "Reveal" : "Hide";
    });
  });

  // <button data-copy="inputId"> — copy a field's value to the clipboard.
  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.copy);
      if (!input || !navigator.clipboard) return;
      navigator.clipboard.writeText(input.value).then(function () {
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      });
    });
  });
})();
