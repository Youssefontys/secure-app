"use strict";

// Form behaviour, in one place. This is convenience, not security: a form
// sent from elsewhere never passes through this script.

// data-confirm: ask for confirmation first, as when deleting.
document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

// data-validate: the submit button stays off while a field does not meet required.
for (const form of document.querySelectorAll("form[data-validate]")) {
  const button = form.querySelector('button[type="submit"]');
  const update = () => { button.disabled = !form.checkValidity(); };
  form.addEventListener("input", update);
  update();
}

// An error message gets the focus, so a screen reader reads it out at once (tabindex="-1" in base.html).
document.querySelector(".error")?.focus();
