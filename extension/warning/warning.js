/**
 * SafeBrowse X - Warning Page Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url') || 'Unknown URL';
  const threatType = urlParams.get('threat') || 'CONFIRMED THREAT';
  const riskScore = urlParams.get('risk') || '95';
  const confidence = urlParams.get('confidence') || '98';
  
  let reasons = [];
  try {
    reasons = JSON.parse(urlParams.get('reasons') || '[]');
  } catch (e) {
    reasons = ['Threat signatures detected on destination server'];
  }

  // Populate UI
  document.getElementById('blockedUrl').textContent = targetUrl;
  document.getElementById('threatTag').textContent = `${threatType.replace(/_/g, ' ')} BLOCKED`;
  document.getElementById('riskBadge').textContent = `Risk: ${riskScore}/100`;
  document.getElementById('diagThreat').textContent = threatType;
  document.getElementById('diagConfidence').textContent = `${confidence}%`;

  const reasonsList = document.getElementById('reasonsList');
  reasonsList.innerHTML = '';
  if (reasons.length > 0) {
    reasons.forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'Server intelligence matches known malicious indicators';
    reasonsList.appendChild(li);
  }

  // Go Back to Safety
  document.getElementById('goBackBtn').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://www.google.com';
    }
  });

  // Toggle Technical Details
  const toggleBtn = document.getElementById('toggleDetailsBtn');
  const techDetails = document.getElementById('techDetails');
  toggleBtn.addEventListener('click', () => {
    techDetails.classList.toggle('hidden');
    toggleBtn.textContent = techDetails.classList.contains('hidden') ? 'Technical Details' : 'Hide Details';
  });

  // Override Proceed Anyway
  document.getElementById('overrideBtn').addEventListener('click', () => {
    if (confirm('Warning: You are attempting to navigate to an unsafe website. SafeBrowse cannot protect your data if you proceed. Are you certain?')) {
      window.location.href = targetUrl;
    }
  });
});
