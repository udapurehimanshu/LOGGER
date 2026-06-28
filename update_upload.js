const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

const replacement = `
      let data;
      try {
        data = JSON.parse(ev.target.result);
        if (!data.screenName && !data.title && !data.fields) {
           data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
        }
      } catch (err) {
        // Not a JSON file, treat as raw code
        data = { screenName: file.name, title: file.name, rawCode: ev.target.result };
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
`;

code = code.replace(/const data = JSON\.parse\(ev\.target\.result\);[\s\S]*?showScreenFilterModal\(\);/, replacement.trim());

// Also, update the UI to display raw code if it's there.
// Find the new injection we added in `update_logic3.js`
const rawCodeDisplayUpdate = `
  let analysisHtml = '';

  if (screenDef.rawCode) {
    analysisHtml += \`
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8;">
          <span>💻</span> UPLOADED CODE
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
          Raw code from \${STATE.currentScreenFile || 'the uploaded file'}.
        </div>
        <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(screenDef.rawCode)}</pre>
      </div>
    \`;
  } else if (screenDef.fields) {
`;

code = code.replace(/let analysisHtml = '';\s*if \(screenDef\.fields\) \{/, rawCodeDisplayUpdate);

// Also update the catch block of handleScreenSelect
code = code.replace(/} catch\(err\) {\s*console\.error\(err\);\s*hideLoadingUI\(\);\s*alert\("Error parsing Screen JSON file\."\);\s*}/, `} catch(err) {\n      console.error(err);\n      hideLoadingUI();\n      alert("Error reading file.");\n    }`);

fs.writeFileSync('app.js', code);
console.log("Flexible upload logic injected!");
