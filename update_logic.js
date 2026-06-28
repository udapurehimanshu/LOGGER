const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

// Add filterByScreen to STATE
code = code.replace(
  /currentScreenFile: null,\n\};/,
  'currentScreenFile: null,\n  filterByScreen: false,\n};'
);

// We need to add the event listeners for screen-input back. Let's find initDashboardClicks
code = code.replace(
  /\/\/ File upload/,
  `// Screen JSON upload
  const uploadScreenBtn = document.getElementById('upload-screen-btn');
  if (uploadScreenBtn) {
    uploadScreenBtn.addEventListener('click', () => {
      const screenInput = document.getElementById('screen-input');
      if (screenInput) {
        screenInput.value = '';
        screenInput.click();
      }
    });
  }
  const screenInput = document.getElementById('screen-input');
  if (screenInput) {
    screenInput.addEventListener('change', e => {
      const file = e.target.files[0];
      if (!file) return;
      handleScreenSelect(file);
      e.target.value = '';
    });
  }

  // File upload`
);

// Now, add handleScreenSelect and modal logic right before `runScreenDebuggerAnalysis`
const injectionCode = `
function showScreenLoadingUI(filename) {
  const title = document.getElementById('upload-loading-title');
  if (title) title.textContent = "Parsing Screen Definition…";
  const steps = document.getElementById('upload-loading-steps');
  if (steps) steps.style.display = 'none';
  const bar = document.getElementById('upload-progress-bar');
  if (bar) { bar.style.display = 'block'; bar.classList.add('active'); }
  const fill = document.getElementById('upload-progress-fill');
  if (fill) fill.style.width = '0%';
  const cardFill = document.getElementById('upload-card-progress-fill');
  if (cardFill) cardFill.style.width = '0%';
  const card = document.getElementById('upload-loading-card');
  const fname = document.getElementById('upload-loading-filename');
  if (card) card.style.display = 'flex';
  if (fname) fname.textContent = filename || 'Screen JSON';
}

function handleScreenSelect(file) {
  showScreenLoadingUI(file.name);
  const reader = new FileReader();
  reader.onload = async ev => {
    try {
      const progressFill = pct => {
        const fill = document.getElementById('upload-progress-fill');
        if (fill) fill.style.width = pct + '%';
        const cardFill = document.getElementById('upload-card-progress-fill');
        if (cardFill) cardFill.style.width = pct + '%';
      };
      progressFill(50);
      await new Promise(r => setTimeout(r, 200));

      const data = JSON.parse(ev.target.result);
      if (!data.screenName && !data.title) {
        hideLoadingUI();
        alert("Invalid Screen JSON format. Must contain 'screenName' or 'title'.");
        return;
      }
      
      STATE.screenDefinition = data;
      STATE.currentScreenFile = file.name;
      const screenNameEl = document.getElementById('sidebar-screen-name');
      if (screenNameEl) screenNameEl.textContent = file.name;
      
      progressFill(100);
      await new Promise(r => setTimeout(r, 150));
      hideLoadingUI();
      
      // Prompt user with modal dialog
      showScreenFilterModal();

    } catch(err) {
      console.error(err);
      hideLoadingUI();
      alert("Error parsing Screen JSON file.");
    }
  };
  reader.readAsText(file);
}

function showScreenFilterModal() {
  const modal = document.getElementById('screen-filter-modal');
  if (!modal) return;
  modal.style.display = 'flex';

  const yesBtn = document.getElementById('screen-filter-yes-btn');
  const noBtn = document.getElementById('screen-filter-no-btn');

  // Remove old listeners to avoid duplicates
  const newYesBtn = yesBtn.cloneNode(true);
  const newNoBtn = noBtn.cloneNode(true);
  yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);
  noBtn.parentNode.replaceChild(newNoBtn, noBtn);

  newYesBtn.addEventListener('click', () => {
    STATE.filterByScreen = true;
    modal.style.display = 'none';
    if (STATE.analysis) {
      analyzeAll(); // Re-analyze entirely with filtering
      runScreenDebuggerAnalysis();
    }
  });

  newNoBtn.addEventListener('click', () => {
    STATE.filterByScreen = false;
    modal.style.display = 'none';
    if (STATE.analysis) {
      analyzeAll();
      runScreenDebuggerAnalysis();
    }
  });
}

function isLogRelatedToScreen(logMsg) {
  if (!STATE.screenDefinition) return true;
  const def = STATE.screenDefinition;
  const queryWords = [];
  if (def.screenName) queryWords.push(def.screenName.toLowerCase());
  if (def.title) queryWords.push(def.title.toLowerCase());
  if (def.module) queryWords.push(def.module.toLowerCase());
  
  if (def.fields) {
    Object.keys(def.fields).forEach(f => queryWords.push(f.toLowerCase()));
  }

  const msg = logMsg.toLowerCase();
  for (const qw of queryWords) {
    if (msg.includes(qw)) return true;
  }
  return false;
}

`;

code = code.replace(/function runScreenDebuggerAnalysis\(\) \{/, injectionCode + 'function runScreenDebuggerAnalysis() {');

// Update applyFilters to actually filter out rows if STATE.filterByScreen is true
// Currently applyFilters maps STATE.parsed to STATE.filtered.
code = code.replace(
  /STATE\.filtered = STATE\.parsed\.filter\(row => \{/,
  `STATE.filtered = STATE.parsed.filter(row => {
    if (STATE.filterByScreen && !isLogRelatedToScreen(row.message)) return false;`
);

fs.writeFileSync('app.js', code);
console.log('Update logic script successfully modified app.js');
