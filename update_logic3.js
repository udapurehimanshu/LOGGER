const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

const injection = `
  let analysisHtml = '';

  if (screenDef.fields) {
    let screenCodeHtml = '<div style="display:flex; flex-direction:column; gap:12px;">';
    for (const [fieldName, events] of Object.entries(screenDef.fields)) {
      let eventsHtml = '';
      for (const [evName, ev] of Object.entries(events)) {
         if (ev.code) {
           eventsHtml += \`<div style="margin-bottom:8px;"><strong>\${escHtml(evName)}</strong>:<pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(ev.code)}</pre></div>\`;
         }
      }
      if (eventsHtml) {
         screenCodeHtml += \`<div style="background:rgba(255,255,255,0.02); padding:12px; border:1px solid rgba(255,255,255,0.04); border-radius:6px;">
           <h4 style="margin:0 0 8px 0; color:#38BDF8; font-size:13px;">Field: \${escHtml(fieldName)}</h4>
           \${eventsHtml}
         </div>\`;
      }
    }
    screenCodeHtml += '</div>';

    if (screenCodeHtml !== '<div style="display:flex; flex-direction:column; gap:12px;"></div>') {
      analysisHtml += \`
        <div class="dbg-copilot-section">
          <div class="dbg-copilot-title" style="color:#38BDF8;">
            <span>💻</span> UPLOADED SCREEN EVENT CODE
          </div>
          <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
            Code extracted directly from \${STATE.currentScreenFile || 'the uploaded JSON'}.
          </div>
          \${screenCodeHtml}
        </div>
      \`;
    }
  }
`;

code = code.replace(/let analysisHtml = '';/, injection);
fs.writeFileSync('app.js', code);
console.log('Appended code block to analysisHtml');
