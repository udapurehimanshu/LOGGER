const fs = require('fs');

let js = fs.readFileSync('app.js', 'utf8');

// Replace the buggy modal logic in app.js
const correctModalLogic = `
function showScreenFilterModal() {
  const modal = document.getElementById('screen-filter-modal');
  if (!modal) return;
  modal.style.display = 'flex';

  const yesBtn = document.getElementById('screen-filter-yes-btn');
  const noBtn = document.getElementById('screen-filter-no-btn');

  const newYesBtn = yesBtn.cloneNode(true);
  const newNoBtn = noBtn.cloneNode(true);
  yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);
  noBtn.parentNode.replaceChild(newNoBtn, noBtn);

  const reAnalyze = () => {
    if (!STATE.parsed || STATE.parsed.length === 0) return;

    let targetParsed = STATE.parsed;
    if (STATE.filterByScreen) {
       targetParsed = STATE.parsed.filter(r => isLogRelatedToScreen(r.message));
    }

    // Re-run the full analysis on the filtered log data
    STATE.analysis = analyzeAll(targetParsed, STATE.rawLines);
    
    // Refresh all views
    renderDashboard(STATE.analysis);
    applyFilters();
    renderTimeline(targetParsed);
    if (typeof renderWMSFlow === 'function') renderWMSFlow(STATE.analysis.flow, STATE.analysis);
    if (typeof renderApiTracker === 'function') renderApiTracker(STATE.analysis.apis);
    runScreenDebuggerAnalysis();
  };

  newYesBtn.addEventListener('click', () => {
    STATE.filterByScreen = true;
    modal.style.display = 'none';
    reAnalyze();
  });

  newNoBtn.addEventListener('click', () => {
    STATE.filterByScreen = false;
    modal.style.display = 'none';
    reAnalyze();
  });
}
`;

js = js.replace(/function showScreenFilterModal\(\) \{[\s\S]*?function isLogRelatedToScreen\(/, correctModalLogic + '\nfunction isLogRelatedToScreen(');

fs.writeFileSync('app.js', js);
console.log('Fixed logic in app.js');
