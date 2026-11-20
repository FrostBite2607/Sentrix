/**
 * SENTRIX — script.js
 *
 * Responsibilities:
 *  1. Sticky nav shadow on scroll
 *  2. Mobile hamburger toggle (open / close)
 *  3. Close mobile menu when a nav link is clicked
 *  4. Waitlist form validation and success state
 */

/* ----------------------------------------------------------------
   Utility: get element by ID with a fallback null-check helper
   ---------------------------------------------------------------- */
function $(id) {
  return document.getElementById(id);
}

/* ================================================================
   1. STICKY NAV — add .nav--scrolled when page is scrolled down
   ================================================================ */
(function initNavScroll() {
  const nav = document.getElementById('nav');
  if (!nav) return;

  /**
   * Adds or removes the .nav--scrolled class depending on
   * how far the user has scrolled. The class applies a shadow
   * and a backdrop-blur via CSS.
   */
  function handleScroll() {
    if (window.scrollY > 10) {
      nav.classList.add('nav--scrolled');
    } else {
      nav.classList.remove('nav--scrolled');
    }
  }

  // Run once on load in case the page is already scrolled
  handleScroll();

  // Listen for future scroll events (passive = better scroll performance)
  window.addEventListener('scroll', handleScroll, { passive: true });
})();


/* ================================================================
   2. MOBILE HAMBURGER MENU
   ================================================================ */
(function initHamburger() {
  const nav        = document.getElementById('nav');
  const hamburger  = document.getElementById('hamburger');
  const mobileMenu = document.getElementById('mobile-menu');
  if (!nav || !hamburger || !mobileMenu) return;

  /**
   * Toggles the .nav-open class on the <header>.
   * CSS handles the visual animation (bar → X, menu slide down).
   */
  function toggleMenu() {
    const isOpen = nav.classList.toggle('nav-open');

    // Keep aria-expanded in sync for screen readers
    hamburger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }

  /** Closes the menu without toggling */
  function closeMenu() {
    nav.classList.remove('nav-open');
    hamburger.setAttribute('aria-expanded', 'false');
  }

  hamburger.addEventListener('click', toggleMenu);

  /* ----------------------------------------------------------------
     3. CLOSE MOBILE MENU ON NAV LINK CLICK
        Loops over every link inside the mobile nav and attaches a
        click listener so the menu collapses when users navigate.
     ---------------------------------------------------------------- */
  const mobileLinks = mobileMenu.querySelectorAll('.nav__mobile-link, .nav__mobile-cta');
  mobileLinks.forEach(function(link) {
    link.addEventListener('click', closeMenu);
  });
})();


/* ================================================================
   4. WAITLIST FORM — validation + success state
   ================================================================ */
(function initForm() {
  const form       = document.getElementById('waitlist-form');
  const formWrap   = document.getElementById('form-wrap');
  const successMsg = document.getElementById('form-success');
  if (!form || !formWrap || !successMsg) return;

  /* -- Field references -- */
  const nameInput  = document.getElementById('field-name');
  const emailInput = document.getElementById('field-email');
  const roleSelect = document.getElementById('field-role');

  /* -- Error span references -- */
  const nameError  = document.getElementById('error-name');
  const emailError = document.getElementById('error-email');
  const roleError  = document.getElementById('error-role');

  /**
   * Simple email format check using a broadly-compatible regex.
   * Not exhaustive — just catches obvious mistakes.
   */
  function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
  }

  /**
   * Marks a field as invalid and sets its error message.
   * Removes the flag when the message is empty.
   */
  function setError(input, errorEl, message) {
    errorEl.textContent = message;
    if (message) {
      input.classList.add('is-invalid');
      input.setAttribute('aria-invalid', 'true');
    } else {
      input.classList.remove('is-invalid');
      input.removeAttribute('aria-invalid');
    }
  }

  /**
   * Validates all form fields.
   * Returns true only when every field passes.
   */
  function validateForm() {
    let valid = true;

    /* Name: must not be blank */
    if (!nameInput.value.trim()) {
      setError(nameInput, nameError, 'Please enter your name.');
      valid = false;
    } else {
      setError(nameInput, nameError, '');
    }

    /* Email: must be non-blank and match email pattern */
    if (!emailInput.value.trim()) {
      setError(emailInput, emailError, 'Please enter your work email.');
      valid = false;
    } else if (!isValidEmail(emailInput.value)) {
      setError(emailInput, emailError, 'Please enter a valid email address.');
      valid = false;
    } else {
      setError(emailInput, emailError, '');
    }

    /* Role: a non-empty option must be selected */
    if (!roleSelect.value) {
      setError(roleSelect, roleError, 'Please select your role.');
      valid = false;
    } else {
      setError(roleSelect, roleError, '');
    }

    return valid;
  }

  /* ----------------------------------------------------------------
     Clear individual field errors as the user types / changes value.
     Gives real-time feedback without waiting for re-submit.
     ---------------------------------------------------------------- */
  nameInput.addEventListener('input', function() {
    if (nameInput.value.trim()) {
      setError(nameInput, nameError, '');
    }
  });

  emailInput.addEventListener('input', function() {
    if (isValidEmail(emailInput.value)) {
      setError(emailInput, emailError, '');
    }
  });

  roleSelect.addEventListener('change', function() {
    if (roleSelect.value) {
      setError(roleSelect, roleError, '');
    }
  });

  /* ----------------------------------------------------------------
     Form submit handler
     ---------------------------------------------------------------- */
  form.addEventListener('submit', function(event) {
    // Always prevent the default browser submit
    event.preventDefault();

    // Run validation; bail if any field fails
    if (!validateForm()) return;

    /*
      TODO: replace this with your backend endpoint or form service
            (e.g. Formspree, Netlify Forms).

      Example using Formspree:
        fetch('https://formspree.io/f/YOUR_FORM_ID', {
          method: 'POST',
          headers: { 'Accept': 'application/json' },
          body: new FormData(form)
        })
        .then(function(res) {
          if (res.ok) showSuccess();
        })
        .catch(function(err) {
          console.error('Submission error', err);
        });

      For now we simply show the success message immediately.
    */

    showSuccess();
  });

  /**
   * Hides the form and reveals the success message.
   * Moves focus to the success message so screen readers announce it.
   */
  function showSuccess() {
    formWrap.hidden = true;
    successMsg.hidden = false;

    // Move focus to the success element so keyboard/screen-reader users
    // are aware that the form has been replaced.
    successMsg.focus();
  }
})();
