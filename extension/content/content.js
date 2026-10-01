/**
 * SafeBrowse X - Content Security & DOM Metadata Inspector
 * Privacy-first: NEVER captures, logs, or transmits user passwords or form inputs!
 */

(function () {
  'use strict';

  // Extract non-sensitive metadata about forms on the page
  function inspectForms() {
    const forms = document.querySelectorAll('form');
    const formMetadataList = [];

    forms.forEach((form) => {
      const inputs = form.querySelectorAll('input, select, textarea');
      let hasPassword = false;
      let hasEmailOrUsername = false;
      let hasOtpOrToken = false;
      let hasCreditCard = false;

      inputs.forEach((input) => {
        const type = (input.getAttribute('type') || '').toLowerCase();
        const name = (input.getAttribute('name') || '').toLowerCase();
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

        if (type === 'password') {
          hasPassword = true;
        }
        if (type === 'email' || name.includes('user') || name.includes('login') || autocomplete.includes('username')) {
          hasEmailOrUsername = true;
        }
        if (name.includes('otp') || name.includes('2fa') || name.includes('token') || name.includes('code') || autocomplete.includes('one-time-code')) {
          hasOtpOrToken = true;
        }
        if (autocomplete.includes('cc-number') || name.includes('card') || name.includes('cvv')) {
          hasCreditCard = true;
        }
      });

      // Check cross-origin action
      let isCrossOrigin = false;
      let actionUrl = form.getAttribute('action') || '';
      if (actionUrl && actionUrl.startsWith('http')) {
        try {
          const actionHost = new URL(actionUrl).hostname;
          if (actionHost !== window.location.hostname && !actionHost.endsWith('.' + window.location.hostname)) {
            isCrossOrigin = true;
          }
        } catch (e) {}
      }

      formMetadataList.push({
        action_url: actionUrl ? (actionUrl.startsWith('http') ? new URL(actionUrl).origin : 'relative') : 'current_page',
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        has_password: hasPassword,
        has_email_or_username: hasEmailOrUsername,
        has_otp_or_token: hasOtpOrToken,
        has_credit_card: hasCreditCard,
        input_count: inputs.length,
        is_cross_origin: isCrossOrigin,
      });
    });

    return formMetadataList;
  }

  // Inspect iframes
  function inspectIframes() {
    const iframes = document.querySelectorAll('iframe');
    const sources = [];
    iframes.forEach((ifr) => {
      const src = ifr.getAttribute('src');
      if (src && src.startsWith('http')) {
        try {
          sources.push(new URL(src).hostname);
        } catch (e) {}
      }
    });
    return sources;
  }

  // Monitor aggressive notification permission requests
  let notificationPromptCount = 0;
  if (window.Notification) {
    const originalRequestPermission = window.Notification.requestPermission;
    window.Notification.requestPermission = function () {
      notificationPromptCount++;
      return originalRequestPermission.apply(this, arguments);
    };
  }

  function sendPageAnalysis() {
    const forms = inspectForms();
    const iframes = inspectIframes();
    const title = document.title || '';

    // Only send if there are forms, iframes, or notification activity
    if (forms.length > 0 || iframes.length > 0 || notificationPromptCount > 0) {
      chrome.runtime.sendMessage({
        type: 'PAGE_DOM_ANALYSIS',
        data: {
          url: window.location.href,
          title: title,
          forms: forms,
          notification_prompt_count: notificationPromptCount,
          iframes: iframes,
          client_version: '1.0.0',
        },
      }).catch(() => {});
    }
  }

  // Run on page load
  if (document.readyState === 'complete') {
    sendPageAnalysis();
  } else {
    window.addEventListener('load', sendPageAnalysis);
  }

  // Re-check after dynamically injected forms (e.g. SPAs)
  setTimeout(sendPageAnalysis, 1500);
})();
