/**
 * QRShield — Web Application Controller
 * Handles Camera Scanning (WebRTC), Image Upload & Clipboard Paste,
 * URL Security Analysis, and Progressive Disclosure of Diagnostics.
 */

(() => {
  'use strict';

  // --- State ---
  let videoStream = null;
  let cameraAnimationId = null;
  let activeFacingMode = 'environment';
  let barcodeDetector = null;
  let currentScanData = null;
  let urlPanelOpen = false;

  if ('BarcodeDetector' in window) {
    try {
      barcodeDetector = new BarcodeDetector({ formats: ['qr_code'] });
    } catch (_) {}
  }

  // --- DOM Elements ---
  const brandBtn           = document.getElementById('brandBtn');
  const historyNavBtn      = document.getElementById('historyNavBtn');
  const footerHistoryLink  = document.getElementById('footerHistoryLink');

  // Action buttons
  const openCameraBtn      = document.getElementById('openCameraBtn');
  const uploadImageBtn     = document.getElementById('uploadImageBtn');
  const filePickerInput    = document.getElementById('filePickerInput');
  const toggleUrlInputBtn  = document.getElementById('toggleUrlInputBtn');
  const urlInputCollapse   = document.getElementById('urlInputCollapse');
  const urlInputField      = document.getElementById('urlInputField');
  const pasteClipboardBtn  = document.getElementById('pasteClipboardBtn');
  const urlSubmitBtn       = document.getElementById('urlSubmitBtn');

  // Camera Modal
  const cameraModal        = document.getElementById('cameraModal');
  const closeCameraBtn     = document.getElementById('closeCameraBtn');
  const cameraVideo        = document.getElementById('cameraVideo');
  const cameraCanvas       = document.getElementById('cameraCanvas');
  const cameraFlipBtn      = document.getElementById('cameraFlipBtn');

  // Loading State
  const loadingModal       = document.getElementById('loadingModal');
  const loadingStatusText  = document.getElementById('loadingStatusText');

  // Result Modal
  const resultModal        = document.getElementById('resultModal');
  const resultCardContent  = document.getElementById('resultCardContent');

  // Technical Details Modal
  const detailsModal       = document.getElementById('detailsModal');
  const detailsBody        = document.getElementById('detailsBody');
  const closeDetailsBtn    = document.getElementById('closeDetailsBtn');

  // History Drawer
  const historyDrawer      = document.getElementById('historyDrawer');
  const closeHistoryBtn    = document.getElementById('closeHistoryBtn');
  const clearAllHistoryBtn = document.getElementById('clearAllHistoryBtn');
  const historyItemsList   = document.getElementById('historyItemsList');

  // Toast
  const toastPopup         = document.getElementById('toastPopup');
  let toastTimer           = null;

  // --- Startup ---
  document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
  });

  // --- Bind Events ---
  function bindEvents() {
    // Brand: reset page state
    brandBtn.addEventListener('click', () => {
      closeAllModals();
      collapseUrlPanel();
      urlInputField.value = '';
    });

    // 1. Camera
    openCameraBtn.addEventListener('click', startCamera);
    closeCameraBtn.addEventListener('click', stopCamera);
    cameraFlipBtn.addEventListener('click', toggleCameraFacing);

    // 2. Upload image
    uploadImageBtn.addEventListener('click', () => filePickerInput.click());
    filePickerInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        processUploadedFile(e.target.files[0]);
      }
      filePickerInput.value = '';
    });

    // Global paste (Ctrl+V screenshot)
    document.addEventListener('paste', (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          const blob = items[i].getAsFile();
          if (blob) {
            showToast('Pasted screenshot detected.');
            processUploadedFile(blob);
            return;
          }
        }
      }
    });

    // 3. URL toggle
    toggleUrlInputBtn.addEventListener('click', () => {
      if (urlPanelOpen) {
        collapseUrlPanel();
      } else {
        expandUrlPanel();
      }
    });

    // URL form submit
    urlInputCollapse.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = urlInputField.value.trim();
      if (val) {
        handleRawContent(val);
      }
    });

    // Paste into URL field
    pasteClipboardBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          urlInputField.value = text.trim();
          showToast('Pasted from clipboard.');
        } else {
          showToast('Clipboard is empty.');
        }
      } catch (_) {
        showToast('Clipboard permission denied. Use Ctrl+V.');
      }
    });

    // Close technical details
    closeDetailsBtn.addEventListener('click', () => {
      detailsModal.style.display = 'none';
    });

    // History
    historyNavBtn.addEventListener('click', openHistory);
    footerHistoryLink.addEventListener('click', openHistory);
    closeHistoryBtn.addEventListener('click', closeHistory);
    clearAllHistoryBtn.addEventListener('click', clearAllHistory);

    // Click outside backdrop to close
    [cameraModal, resultModal, detailsModal].forEach(el => {
      el.addEventListener('click', (e) => {
        if (e.target === el) {
          if (el === cameraModal) stopCamera();
          else el.style.display = 'none';
        }
      });
    });

    historyDrawer.addEventListener('click', (e) => {
      if (e.target === historyDrawer) closeHistory();
    });

    // Esc key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        stopCamera();
        closeAllModals();
      }
    });
  }

  function expandUrlPanel() {
    urlPanelOpen = true;
    urlInputCollapse.style.display = 'block';
    setTimeout(() => urlInputField.focus(), 50);
  }

  function collapseUrlPanel() {
    urlPanelOpen = false;
    urlInputCollapse.style.display = 'none';
  }

  function closeAllModals() {
    stopCamera();
    resultModal.style.display = 'none';
    detailsModal.style.display = 'none';
    loadingModal.style.display = 'none';
    historyDrawer.style.display = 'none';
  }

  // ==========================================================================
  // Camera Scanner (WebRTC + BarcodeDetector / jsQR)
  // ==========================================================================

  async function startCamera() {
    cameraModal.style.display = 'flex';
    try {
      const constraints = {
        video: {
          facingMode: activeFacingMode,
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      };

      videoStream = await navigator.mediaDevices.getUserMedia(constraints);
      cameraVideo.srcObject = videoStream;
      await cameraVideo.play();
      requestAnimationFrame(scanCameraFrame);
    } catch (err) {
      stopCamera();
      showToast('Camera error: ' + (err.message || 'Permission denied'));
    }
  }

  function stopCamera() {
    if (cameraAnimationId) {
      cancelAnimationFrame(cameraAnimationId);
      cameraAnimationId = null;
    }
    if (videoStream) {
      videoStream.getTracks().forEach(track => track.stop());
      videoStream = null;
    }
    cameraModal.style.display = 'none';
  }

  function toggleCameraFacing() {
    activeFacingMode = (activeFacingMode === 'environment') ? 'user' : 'environment';
    stopCamera();
    startCamera();
  }

  async function scanCameraFrame() {
    if (!videoStream || cameraVideo.readyState !== cameraVideo.HAVE_ENOUGH_DATA) {
      cameraAnimationId = requestAnimationFrame(scanCameraFrame);
      return;
    }

    try {
      // 1. Hardware-accelerated BarcodeDetector
      if (barcodeDetector) {
        const barcodes = await barcodeDetector.detect(cameraVideo);
        if (barcodes.length > 0 && barcodes[0].rawValue) {
          const raw = barcodes[0].rawValue.trim();
          stopCamera();
          handleRawContent(raw);
          return;
        }
      } else if (window.jsQR) {
        // 2. jsQR canvas fallback
        const canvas = cameraCanvas;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        canvas.width = cameraVideo.videoWidth;
        canvas.height = cameraVideo.videoHeight;
        ctx.drawImage(cameraVideo, 0, 0, canvas.width, canvas.height);

        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: 'attemptBoth'
        });

        if (code && code.data && code.data.trim()) {
          const raw = code.data.trim();
          stopCamera();
          handleRawContent(raw);
          return;
        }
      }
    } catch (_) {}

    cameraAnimationId = requestAnimationFrame(scanCameraFrame);
  }

  // ==========================================================================
  // Image & Screenshot Upload / Decode
  // ==========================================================================

  async function processUploadedFile(file) {
    showLoading('Decoding image...');

    try {
      const imageBitmap = await createImageBitmap(file);
      let detectedText = null;

      if (barcodeDetector) {
        const codes = await barcodeDetector.detect(imageBitmap);
        if (codes.length > 0 && codes[0].rawValue) {
          detectedText = codes[0].rawValue.trim();
        }
      }

      if (!detectedText && window.jsQR) {
        const canvas = document.createElement('canvas');
        canvas.width = imageBitmap.width;
        canvas.height = imageBitmap.height;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(imageBitmap, 0, 0);
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: 'attemptBoth'
        });
        if (code && code.data) {
          detectedText = code.data.trim();
        }
      }

      if (detectedText) {
        hideLoading();
        handleRawContent(detectedText);
        return;
      }

      // Backend OpenCV + pyzbar multi-pass fallback
      if (loadingStatusText) loadingStatusText.textContent = 'Applying server-side image enhancement...';
      const formData = new FormData();
      formData.append('file', file, file.name || 'screenshot.png');

      const resp = await fetch('/api/v1/scan/decode-image', {
        method: 'POST',
        body: formData
      });

      hideLoading();

      if (resp.ok) {
        const data = await resp.json();
        if (data.success && data.decoded_text) {
          handleRawContent(data.decoded_text.trim());
          return;
        }
      }

      showToast('No QR code found in this image.');
    } catch (err) {
      hideLoading();
      showToast('Could not process image file.');
    }
  }

  // ==========================================================================
  // QR Content Classifier
  // ==========================================================================

  function parseQR(raw) {
    const trimmed = raw.trim();
    const lower = trimmed.toLowerCase();

    // 1. UPI Payment
    if (lower.startsWith('upi://')) {
      const fields = {};
      try {
        const url = new URL(trimmed);
        const params = new URLSearchParams(url.search);
        if (params.get('pa')) fields['UPI ID'] = params.get('pa');
        if (params.get('pn')) fields['Payee Name'] = decodeURIComponent(params.get('pn'));
        if (params.get('am')) fields['Amount'] = `\u20b9${params.get('am')} ${params.get('cu') || 'INR'}`;
        if (params.get('tn')) fields['Note'] = decodeURIComponent(params.get('tn'));
      } catch (_) {
        const paMatch = trimmed.match(/[?&]pa=([^&]+)/);
        const pnMatch = trimmed.match(/[?&]pn=([^&]+)/);
        const amMatch = trimmed.match(/[?&]am=([^&]+)/);
        if (paMatch) fields['UPI ID'] = decodeURIComponent(paMatch[1]);
        if (pnMatch) fields['Payee Name'] = decodeURIComponent(pnMatch[1]);
        if (amMatch) fields['Amount'] = `\u20b9${decodeURIComponent(amMatch[1])} INR`;
      }
      return { type: 'upi', raw: trimmed, fields };
    }

    // 2. Wi-Fi
    if (lower.startsWith('wifi:')) {
      const fields = {};
      const body = trimmed.replace(/^wifi:/i, '');
      const parts = body.split(';');
      for (const part of parts) {
        if (part.startsWith('S:')) fields['Network SSID'] = part.substring(2);
        if (part.startsWith('T:')) fields['Security'] = part.substring(2);
        if (part.startsWith('P:')) fields['Password'] = part.substring(2);
      }
      return { type: 'wifi', raw: trimmed, fields };
    }

    // 3. vCard
    if (lower.startsWith('begin:vcard')) {
      const fields = {};
      const lines = trimmed.split(/\r?\n/);
      for (const line of lines) {
        if (line.startsWith('FN:')) fields['Name'] = line.substring(3);
        else if (line.startsWith('TEL')) fields['Phone'] = line.split(':').slice(1).join(':');
        else if (line.startsWith('EMAIL')) fields['Email'] = line.split(':').slice(1).join(':');
        else if (line.startsWith('ORG:')) fields['Organization'] = line.substring(4);
      }
      return { type: 'vcard', raw: trimmed, fields };
    }

    // 4. Web URL
    if (lower.startsWith('http://') || lower.startsWith('https://') || /^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(lower)) {
      let finalUrl = trimmed;
      if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
        finalUrl = 'https://' + trimmed;
      }
      return { type: 'url', raw: finalUrl, fields: {} };
    }

    // 5. Plain Text
    return { type: 'text', raw: trimmed, fields: {} };
  }

  // ==========================================================================
  // Router
  // ==========================================================================

  async function handleRawContent(raw) {
    const parsed = parseQR(raw);
    if (parsed.type === 'url') {
      await scanUrlSecurity(parsed.raw);
    } else {
      renderNonUrlResult(parsed);
    }
  }

  // ==========================================================================
  // Security Analysis Pipeline
  // ==========================================================================

  async function scanUrlSecurity(url) {
    showLoading('Analyzing destination...');

    try {
      const resp = await fetch('/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, client_platform: 'web' })
      });

      hideLoading();

      if (resp.ok) {
        const data = await resp.json();
        currentScanData = data;
        renderUrlResult(data);
      } else {
        const err = await resp.json().catch(() => ({}));
        showToast(err.detail || 'Analysis rejected by security policy.');
      }
    } catch (_) {
      hideLoading();
      showToast('Unable to connect to security engine.');
    }
  }

  // ==========================================================================
  // Render URL Security Result
  // ==========================================================================

  function renderUrlResult(data) {
    const verdict = data.verdict;
    const displayUrl = data.final_url || data.submitted_url;
    const isHttps = displayUrl.toLowerCase().startsWith('https://');

    const highFindings = (data.evidence || []).filter(f => f.severity === 'high' || f.critical).slice(0, 2);
    const medFindings  = (data.evidence || []).filter(f => f.severity === 'medium').slice(0, 2);
    const keyConcerns  = highFindings.length > 0 ? highFindings : medFindings;

    let headClass = 'safe';
    let iconSvg   = '';
    let title     = '';
    let subtitle  = '';

    if (verdict === 'LOW_RISK') {
      headClass = 'safe';
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20 6 9 17l-5-5"/>
        </svg>`;
      title    = 'Safe to Open';
      subtitle = 'No deceptive redirects, phishing patterns, or malicious signals detected.';
    } else if (verdict === 'SUSPICIOUS') {
      headClass = 'caution';
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>`;
      title    = 'Proceed with Caution';
      subtitle = 'Suspicious risk indicators detected on destination.';
    } else {
      headClass = 'danger';
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>`;
      title    = 'High Risk Threat Detected';
      subtitle = 'Severe security threats detected. Opening this site is not recommended.';
    }

    let warningCallout = '';
    if (verdict !== 'LOW_RISK' && keyConcerns.length > 0) {
      warningCallout = `
        <div class="concise-warning-callout ${verdict === 'HIGH_RISK' ? 'danger-variant' : ''}">
          <div class="callout-header-title">${verdict === 'HIGH_RISK' ? 'Critical Concerns' : 'Key Concerns'}</div>
          <ul class="callout-points-list">
            ${keyConcerns.map(f => `<li class="callout-point-item">${escapeHtml(f.description)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    let actionButtons = '';
    if (verdict === 'LOW_RISK') {
      actionButtons = `
        <div class="modal-actions-row">
          <button type="button" class="btn-dismiss-safe" id="resultBackBtn">Close</button>
          <a class="btn-open-link" href="${escapeHtml(displayUrl)}" target="_blank" rel="noopener noreferrer">
            <span>Open Link</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/></svg>
          </a>
        </div>
      `;
    } else if (verdict === 'SUSPICIOUS') {
      actionButtons = `
        <div class="modal-actions-row">
          <button type="button" class="btn-dismiss-safe" id="resultBackBtn">Cancel</button>
          <button type="button" class="btn-open-caution" id="proceedCautionBtn">
            <span>Open Anyway</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/></svg>
          </button>
        </div>
      `;
    } else {
      actionButtons = `
        <div class="modal-actions-row">
          <button type="button" class="btn-danger-cancel-wide" id="resultBackBtn">Do Not Open (Stay Safe)</button>
        </div>
        <div class="danger-override-caption">
          <a id="dangerOverrideLink">I understand the risks, open anyway</a>
        </div>
      `;
    }

    resultCardContent.innerHTML = `
      <div class="result-body">
        <div class="result-status-head ${headClass}">
          <div class="result-icon-disc">${iconSvg}</div>
          <h2 class="result-title">${title}</h2>
          <p class="result-subtitle">${subtitle}</p>
        </div>

        <div class="destination-pill-box">
          <div class="pill-lock-icon ${isHttps ? '' : 'insecure'}">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <span class="pill-url-text">${escapeHtml(displayUrl)}</span>
          <button type="button" class="pill-copy-btn" id="copyUrlBtn" title="Copy URL">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
              <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
            </svg>
          </button>
        </div>

        ${warningCallout}

        <div class="why-action-wrapper">
          <button type="button" class="why-action-button" id="openWhyDetailsBtn">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span>${verdict === 'LOW_RISK' ? 'View Technical Details' : 'Why is this flagged?'}</span>
          </button>
        </div>

        ${actionButtons}
      </div>
    `;

    resultModal.style.display = 'flex';

    document.getElementById('resultBackBtn')?.addEventListener('click', () => {
      resultModal.style.display = 'none';
    });

    document.getElementById('copyUrlBtn')?.addEventListener('click', () => {
      navigator.clipboard.writeText(displayUrl);
      showToast('URL copied to clipboard.');
    });

    document.getElementById('openWhyDetailsBtn')?.addEventListener('click', () => {
      renderTechnicalDetails(data);
    });

    document.getElementById('proceedCautionBtn')?.addEventListener('click', () => {
      if (confirm('Suspicious indicators were detected. Are you sure you want to open this link?')) {
        window.open(displayUrl, '_blank', 'noopener,noreferrer');
      }
    });

    document.getElementById('dangerOverrideLink')?.addEventListener('click', () => {
      if (confirm('Severe threats detected. Opening this site may compromise accounts or credentials. Proceed anyway?')) {
        window.open(displayUrl, '_blank', 'noopener,noreferrer');
      }
    });
  }

  // ==========================================================================
  // Render Non-URL Result (UPI, Wi-Fi, vCard, Text)
  // ==========================================================================

  function renderNonUrlResult(parsed) {
    let iconSvg  = '';
    let title    = '';
    let notice   = '';
    let rowsHtml = '';

    if (parsed.type === 'upi') {
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M6 3h12M6 8h12M6 13l8.5 8M6 13h3a4.5 4.5 0 0 0 0-9"/>
        </svg>`;
      title  = 'UPI Payment QR Code';
      notice = 'This is a UPI payment QR. Browsers cannot execute UPI payments. Scan with PhonePe, Google Pay, Paytm, or BHIM to pay.';

      rowsHtml = Object.entries(parsed.fields).map(([k, v]) => `
        <div class="non-url-row">
          <div class="non-url-label">${escapeHtml(k)}</div>
          <div class="non-url-value ${k === 'Amount' ? 'amount-tag' : ''}">${escapeHtml(v)}</div>
        </div>
      `).join('');
    } else if (parsed.type === 'wifi') {
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M5 13a10 10 0 0 1 14 0M8.5 16.5a5 5 0 0 1 7 0M12 20h.01"/>
        </svg>`;
      title  = 'Wi-Fi Network Configuration';
      notice = 'This QR code contains Wi-Fi credentials. Copy the password and connect via your device settings.';

      rowsHtml = Object.entries(parsed.fields).map(([k, v]) => `
        <div class="non-url-row">
          <div class="non-url-label">${escapeHtml(k)}</div>
          <div class="non-url-value">${escapeHtml(v)}</div>
        </div>
      `).join('');
    } else if (parsed.type === 'vcard') {
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/>
          <circle cx="12" cy="7" r="4"/>
        </svg>`;
      title  = 'Contact Card (vCard)';
      notice = 'This QR code contains contact details.';

      rowsHtml = Object.entries(parsed.fields).map(([k, v]) => `
        <div class="non-url-row">
          <div class="non-url-label">${escapeHtml(k)}</div>
          <div class="non-url-value">${escapeHtml(v)}</div>
        </div>
      `).join('');
    } else {
      iconSvg = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect width="18" height="18" x="3" y="3" rx="2"/>
          <path d="M7 7h10v10H7z"/>
        </svg>`;
      title  = 'QR Code — Text Content';
      notice = 'This QR contains plain text, not a web link. Nothing will open automatically.';

      rowsHtml = `
        <div class="non-url-row">
          <div class="non-url-label">Text</div>
          <div class="non-url-value">${escapeHtml(parsed.raw)}</div>
        </div>
      `;
    }

    resultCardContent.innerHTML = `
      <div class="result-body">
        <div class="result-status-head info">
          <div class="result-icon-disc">${iconSvg}</div>
          <h2 class="result-title">${title}</h2>
        </div>

        <div class="non-url-fields-panel">
          ${rowsHtml}
        </div>

        <div class="non-url-safe-notice">
          ${notice}
        </div>

        <div class="modal-actions-row">
          <button type="button" class="btn-dismiss-safe" id="resultBackBtn">Close</button>
          <button type="button" class="btn-open-link" id="copyNonUrlBtn">
            <span>Copy Details</span>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
              <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
            </svg>
          </button>
        </div>
      </div>
    `;

    resultModal.style.display = 'flex';

    document.getElementById('resultBackBtn')?.addEventListener('click', () => {
      resultModal.style.display = 'none';
    });

    document.getElementById('copyNonUrlBtn')?.addEventListener('click', () => {
      const copyVal = parsed.fields['UPI ID'] || parsed.fields['Password'] || parsed.raw;
      navigator.clipboard.writeText(copyVal);
      showToast('Copied to clipboard.');
    });
  }

  // ==========================================================================
  // Render Technical Details ("Why?") Modal
  // ==========================================================================

  function renderTechnicalDetails(data) {
    const score = data.score ?? 0;
    let scoreColor = 'var(--color-safe)';
    if (score >= 70) scoreColor = 'var(--color-danger)';
    else if (score >= 30) scoreColor = 'var(--color-caution)';

    let redirectHtml = '';
    if (data.redirect_chain && data.redirect_chain.length > 0) {
      redirectHtml = `
        <div>
          <div class="section-label-heading">Redirect Chain (${data.redirect_chain.length} hops)</div>
          <div class="redirect-hops-stack">
            ${data.redirect_chain.map(hop => `
              <div class="redirect-hop-row">
                <span class="hop-num-tag">${hop.hop}</span>
                <span class="hop-url-name" title="${escapeHtml(hop.url)}">${escapeHtml(hop.url)}</span>
                ${hop.status_code ? `<span class="hop-status-code">${hop.status_code}</span>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    let evidenceHtml = '';
    if (data.evidence && data.evidence.length > 0) {
      evidenceHtml = `
        <div>
          <div class="section-label-heading">Findings &amp; Threat Indicators (${data.evidence.length})</div>
          <div class="evidence-items-stack">
            ${data.evidence.map(item => `
              <div class="evidence-card-row">
                <div class="evidence-pill-row">
                  <span class="severity-pill-badge ${item.severity}">${escapeHtml(item.severity)}</span>
                  <span class="evidence-code-text">${escapeHtml(item.code)}</span>
                </div>
                <div class="evidence-desc-text">${escapeHtml(item.description)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } else {
      evidenceHtml = `
        <div>
          <div class="section-label-heading">Findings</div>
          <p style="font-size:13px; color:var(--text-faint);">No threat indicators detected.</p>
        </div>
      `;
    }

    const destUrl = data.final_url || data.submitted_url;
    detailsBody.innerHTML = `
      <div style="font-size:12px; color:var(--text-faint); margin-bottom:16px; word-break:break-all;">${escapeHtml(destUrl)}</div>
      <div class="rating-gauge-row">
        <div>
          <div class="rating-title">Calculated Risk Score</div>
          <div class="rating-sub">Multi-layer heuristic evaluation</div>
        </div>
        <div style="display:flex; align-items:baseline; gap:4px;">
          <span class="rating-number" style="color:${scoreColor};">${score}</span>
          <span style="color:var(--text-faint); font-size:12px;">/ 100</span>
        </div>
      </div>

      ${redirectHtml}
      ${evidenceHtml}
    `;

    detailsModal.style.display = 'flex';
  }

  // ==========================================================================
  // History Drawer
  // ==========================================================================

  async function openHistory() {
    historyDrawer.style.display = 'flex';
    historyItemsList.innerHTML = '<div style="text-align:center; padding:24px; color:var(--text-faint); font-size:13px;">Loading scans...</div>';

    try {
      const resp = await fetch('/api/v1/history?limit=30');
      if (resp.ok) {
        const data = await resp.json();
        renderHistoryItems(data.items || []);
      } else {
        throw new Error();
      }
    } catch (_) {
      historyItemsList.innerHTML = '<div class="history-empty-message">Could not load history.</div>';
    }
  }

  function renderHistoryItems(items) {
    if (items.length === 0) {
      historyItemsList.innerHTML = '<div class="history-empty-message">No scan records yet.</div>';
      return;
    }

    historyItemsList.innerHTML = items.map(item => {
      const displayUrl = item.final_url || item.submitted_url;
      let dotClass = 'safe';
      if (item.verdict === 'SUSPICIOUS') dotClass = 'caution';
      else if (item.verdict === 'HIGH_RISK') dotClass = 'danger';

      const timeStr = item.created_at
        ? new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';

      return `
        <div class="history-card-tile" data-url="${escapeHtml(displayUrl)}">
          <span class="history-dot ${dotClass}"></span>
          <div class="history-info-meta">
            <div class="history-destination-url">${escapeHtml(displayUrl)}</div>
            <div class="history-time-score">${timeStr} &bull; Score: ${item.score}/100</div>
          </div>
          <button type="button" class="history-delete-button" data-id="${item.id}" title="Delete record">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
          </button>
        </div>
      `;
    }).join('');

    // Click to re-scan
    historyItemsList.querySelectorAll('.history-card-tile').forEach(tile => {
      tile.addEventListener('click', (e) => {
        if (e.target.closest('.history-delete-button')) return;
        const url = tile.getAttribute('data-url');
        closeHistory();
        handleRawContent(url);
      });
    });

    // Delete single record
    historyItemsList.querySelectorAll('.history-delete-button').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = btn.getAttribute('data-id');
        try {
          await fetch(`/api/v1/history/${id}`, { method: 'DELETE' });
          btn.closest('.history-card-tile')?.remove();
        } catch (_) {}
      });
    });
  }

  function closeHistory() {
    historyDrawer.style.display = 'none';
  }

  async function clearAllHistory() {
    if (!confirm('Clear all scan records from history?')) return;
    try {
      const resp = await fetch('/api/v1/history?limit=100');
      if (resp.ok) {
        const data = await resp.json();
        for (const item of (data.items || [])) {
          await fetch(`/api/v1/history/${item.id}`, { method: 'DELETE' });
        }
        historyItemsList.innerHTML = '<div class="history-empty-message">History cleared.</div>';
      }
    } catch (_) {
      showToast('Could not clear history.');
    }
  }

  // ==========================================================================
  // Loading & Toast Helpers
  // ==========================================================================

  function showLoading(msg) {
    if (loadingStatusText) loadingStatusText.textContent = msg || 'Analyzing...';
    loadingModal.style.display = 'flex';
  }

  function hideLoading() {
    loadingModal.style.display = 'none';
  }

  function showToast(msg) {
    if (!toastPopup) return;
    if (toastTimer) clearTimeout(toastTimer);
    toastPopup.textContent = msg;
    toastPopup.style.display = 'block';
    toastPopup.style.opacity = '1';
    toastTimer = setTimeout(() => {
      toastPopup.style.opacity = '0';
      setTimeout(() => { toastPopup.style.display = 'none'; }, 300);
    }, 2800);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

})();
