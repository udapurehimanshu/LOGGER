const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

const replacement = `
function runScreenDebuggerAnalysis() {
  const $ = id => document.getElementById(id);
  if (!STATE.analysis) {
    $('dbg-screen-title').textContent = "No Log File Active";
    $('dbg-screen-meta').textContent = "Please upload a log file or select a sample first.";
    $('dbg-workflow-container').innerHTML = \`<div style="font-size: 13px; color: var(--text-muted); padding: 20px; text-align: center;">Upload a log to start.</div>\`;
    $('dbg-analysis-panel').innerHTML = \`
      <div class="api-details-empty">
        <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        </svg>
        <h3>No Screen Definition or Log Active</h3>
        <p>Upload a Screen JSON file and a Log file, or load one of the generic samples from the sidebar to automatically run the Screen Debugger AI.</p>
      </div>\`;
    return;
  }

  const activeParsed = STATE.filterByScreen ? STATE.parsed.filter(r => isLogRelatedToScreen(r.message)) : STATE.parsed;
  const logText = activeParsed.map(e => e.message).join('\\n');
  const lowerLogText = logText.toLowerCase();

  const screenDef = STATE.screenDefinition;
  if (!screenDef) return;

  const name = screenDef.screenName || screenDef.title || "Unknown Screen";
  const title = screenDef.title || name;
  const module = screenDef.module || "General";
  
  // Build Flow
  let flow = screenDef.flow || [];
  if (flow.length === 0 && screenDef.fields) {
     flow = Object.keys(screenDef.fields);
  }

  $('dbg-screen-title').textContent = title;
  
  // Extract extra components if available
  const btnCount = screenDef.buttons ? Object.keys(screenDef.buttons).length : 0;
  const lovCount = screenDef.lovs ? Object.keys(screenDef.lovs).length : 0;
  
  $('dbg-screen-meta').textContent = \`Screen: \${name} | Module: \${module} | Fields: \${flow.length} | Buttons: \${btnCount} | LOVs: \${lovCount}\`;

  // Draw Workflow Diagram
  let workflowHtml = "";
  flow.forEach((step, idx) => {
    workflowHtml += \`
      <div class="dbg-flow-item active" style="border-color: rgba(56, 189, 248, 0.4);">
        <div style="font-weight: 700; font-size: 13px; color: var(--text-dark);">\${escHtml(step)}</div>
      </div>
    \`;
    if (idx < flow.length - 1) {
      workflowHtml += \`<div class="dbg-flow-arrow">↓</div>\`;
    }
  });
  $('dbg-workflow-container').innerHTML = workflowHtml || \`<div style="font-size:12px; color:var(--text-muted);">No structured workflow detected.</div>\`;

  let analysisHtml = '';

  // 1. RAW CODE DISPLAY (Fallback)
  if (screenDef.rawCode) {
    analysisHtml += \`
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8;">
          <span>💻</span> UPLOADED CODE (RAW)
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
          Raw code from \${STATE.currentScreenFile || 'the uploaded file'}.
        </div>
        <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(screenDef.rawCode)}</pre>
      </div>
    \`;
  }

  // 2. HEALTH SCORE & INVESTIGATION PATH
  if (screenDef.fields) {
     let fieldsWithLogic = 0;
     let fieldsWithLogger = 0;
     let fieldsWithStatus = 0;
     let fieldsWithValidation = 0;
     let totalFields = Object.keys(screenDef.fields).length;

     for (const events of Object.values(screenDef.fields)) {
        let hasLogic = false, hasLogger = false, hasStatus = false, hasValidation = false;
        for (const ev of Object.values(events)) {
           if (ev && ev.code) {
              hasLogic = true;
              if (/logger\\./i.test(ev.code)) hasLogger = true;
              if (/setStatusMessage/i.test(ev.code)) hasStatus = true;
              if (/(throw new|catch\\s*\\(|if\\s*\\([^{]*null|validation)/i.test(ev.code)) hasValidation = true;
           }
        }
        if (hasLogic) fieldsWithLogic++;
        if (hasLogger) fieldsWithLogger++;
        if (hasStatus) fieldsWithStatus++;
        if (hasValidation) fieldsWithValidation++;
     }

     const pct = (num) => totalFields > 0 ? Math.round((num / totalFields) * 100) : 0;

     analysisHtml += \`
      <div style="display:flex; gap:16px; margin-bottom:16px;">
        <!-- Health Score -->
        <div class="dbg-copilot-section" style="flex:1; margin-bottom:0;">
          <div class="dbg-copilot-title" style="color:#10B981; font-size:14px; margin-bottom:12px;">
            <span>🩺</span> SCREEN HEALTH SCORE
          </div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Field Coverage:</span> <strong>\${pct(fieldsWithLogic)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Logger Coverage:</span> <strong style="color:\${pct(fieldsWithLogger) < 50 ? '#EF4444' : '#10B981'}">\${pct(fieldsWithLogger)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Status Message Coverage:</span> <strong style="color:\${pct(fieldsWithStatus) < 50 ? '#EF4444' : '#10B981'}">\${pct(fieldsWithStatus)}%</strong>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-normal);">
              <span>Validation Coverage:</span> <strong>\${pct(fieldsWithValidation)}%</strong>
            </div>
          </div>
          \${pct(fieldsWithLogger) < 50 ? '<div style="margin-top:12px; font-size:11px; color:#F59E0B; background:rgba(245, 158, 11, 0.1); padding:8px; border-radius:4px;">⚠️ This screen is difficult to debug because it lacks loggers and status messages.</div>' : ''}
        </div>

        <!-- Investigation Path -->
        <div class="dbg-copilot-section" style="flex:2; margin-bottom:0; border-left: 4px solid var(--primary);">
          <div class="dbg-copilot-title" style="color:var(--primary); font-size:14px; margin-bottom:12px;">
            <span>🛤️</span> DEVELOPER INVESTIGATION PATH
          </div>
          <div style="font-size:11px; color:var(--text-muted); display:flex; align-items:center; flex-wrap:wrap; gap:8px; font-family:monospace;">
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Field</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Object</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Session Value</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify API Request</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify API Response</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(59,130,246,0.1); color:#60A5FA; padding:4px 8px; border-radius:4px;">Verify Validation</span>
            <span style="color:#64748B;">↓</span>
            <span style="background:rgba(16,185,129,0.1); color:#34D399; padding:4px 8px; border-radius:4px;">Identify Root Cause</span>
          </div>
        </div>
      </div>
     \`;
  }

  // 3. DETAILED FIELD AND WEBSERVICE CORRELATION
  if (screenDef.fields) {
    const severities = {
      CRITICAL: { color: '#EF4444', badge: '🔴 Critical', triggers: ['nullpointer', 'targeterror', 'evalerror', 'fatal'] },
      HIGH: { color: '#F97316', badge: '🟠 High', triggers: ['http 5', 'http 4'] },
      MEDIUM: { color: '#EAB308', badge: '🟡 Medium', triggers: ['json', 'validation', 'exception', 'ora-'] }
    };
    
    let screenCodeHtml = '<div style="display:flex; flex-direction:column; gap:16px;">';
    for (const [fieldName, events] of Object.entries(screenDef.fields)) {
      let severity = null;
      let errorReason = "";
      let failedEvent = "Unknown";
      
      const checkSeverity = (text, contextDesc, evName) => {
         for (const [level, rules] of Object.entries(severities)) {
            for (const t of rules.triggers) {
               if (text.includes(t)) {
                  if (!severity || level === 'CRITICAL' || (level === 'HIGH' && severity.badge === '🟡 Medium')) {
                     severity = rules;
                     errorReason = \`\${t.toUpperCase()} detected near \${contextDesc}.\`;
                     failedEvent = evName || "Execution Flow";
                  }
               }
            }
         }
      };

      // Check field match in logs
      const fieldRegex = new RegExp(fieldName, 'i');
      if (fieldRegex.test(logText)) {
         checkSeverity(lowerLogText, \`field \${fieldName}\`, null);
      }

      let eventsHtml = '';
      let associatedWS = null;

      for (const [evName, ev] of Object.entries(events)) {
         if (ev.code) {
           eventsHtml += \`
             <div style="margin-top:12px;">
               <strong style="color:#818CF8; font-size:12px;">\${escHtml(evName)} Logic:</strong>
               <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:4px 0 0 0; border:1px solid rgba(255,255,255,0.06);">\${escHtml(ev.code)}</pre>
             </div>
           \`;
           
           if (screenDef.webservices) {
             for (const wsName of Object.keys(screenDef.webservices)) {
               if (ev.code.includes(wsName)) {
                 associatedWS = { name: wsName, data: screenDef.webservices[wsName], event: evName };
               }
             }
           }
         }
      }

      let wsHtml = '';
      if (associatedWS) {
        const ws = associatedWS.data;
        wsHtml += \`
          <div style="margin-top:12px; background:rgba(0,0,0,0.2); padding:10px; border-radius:6px; border:1px solid rgba(245, 158, 11, 0.2);">
            <div style="font-size:12px; font-weight:bold; color:#F59E0B; margin-bottom:8px;">🔗 Webservice Mapping: \${escHtml(associatedWS.name)}</div>
            <div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Calling Event:</strong> \${escHtml(associatedWS.event)}</div>
            <div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>URL:</strong> \${escHtml(ws.request || ws.url || 'N/A')}</div>
        \`;
        if (ws.requestMap || ws.body) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Request Structure (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.requestMap || ws.body))}</pre></div>\`;
        }
        if (ws.responseMap || ws.response) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Response Structure (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.responseMap || ws.response))}</pre></div>\`;
        }
        if (ws.columnMap) {
           wsHtml += \`<div style="font-size:11px; color:#D1D5DB; margin-bottom:4px;"><strong>Column Mapping (if available):</strong> <pre style="display:inline; background:#111827; padding:2px 4px; border-radius:4px;">\${escHtml(JSON.stringify(ws.columnMap))}</pre></div>\`;
        }
        wsHtml += \`</div>\`;
        
        if (new RegExp(associatedWS.name, 'i').test(logText)) {
           checkSeverity(lowerLogText, \`API \${associatedWS.name}\`, associatedWS.event);
        }
      }

      // Default severity if none
      if (!severity && (eventsHtml || wsHtml)) severity = { color: '#10B981', badge: '🟢 Informational' };
      if (!severity) severity = { color: '#64748B', badge: '➖ None' };

      if (eventsHtml || wsHtml) {
         let debuggerAssitantHtml = '';
         if (severity.badge !== '🟢 Informational' && severity.badge !== '➖ None') {
            debuggerAssitantHtml = \`
              <div style="margin-top:16px; padding:16px; background:rgba(0,0,0,0.3); border-radius:8px; border-left:4px solid \${severity.color};">
                <h4 style="margin:0 0 12px 0; color:\${severity.color}; font-size:14px; text-transform:uppercase;">🛠️ Debugging Assistant</h4>
                
                <div style="display:flex; gap:16px;">
                  <div style="flex:1;">
                    <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">What Failed</div>
                    <div style="font-size:12px; color:var(--text-normal);">
                      <strong>Field:</strong> \${escHtml(fieldName)}<br>
                      <strong>Event:</strong> \${escHtml(failedEvent)}<br>
                      <strong style="color:\${severity.color};">Failure:</strong> \${escHtml(errorReason)}
                    </div>
                  </div>
                  
                  <div style="flex:1;">
                    <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">What To Verify</div>
                    <ul style="font-size:12px; color:var(--text-normal); margin:0; padding-left:16px;">
                      <li>Field Value</li>
                      <li>Object Value</li>
                      <li>Session Object</li>
                      <li>API Response</li>
                      <li>Response Code</li>
                    </ul>
                  </div>
                </div>

                <div style="margin-top:16px;">
                  <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">Suggested Logger Statements</div>
                  <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:0; border:1px dashed \${severity.color};">logger.debug("\${fieldName}=" + \${fieldName}.getValue());\n\${associatedWS ? \`logger.debug("Response Code=" + \${associatedWS.name}.getResponseCode());\\nlogger.debug("Response=" + \${associatedWS.name}.getRawResponse());\` : ''}</pre>
                </div>

                <div style="margin-top:12px;">
                  <div style="font-size:11px; color:#94A3B8; text-transform:uppercase; margin-bottom:4px;">Suggested Status Messages</div>
                  <pre style="background:#0F172A; color:#E2E8F0; padding:10px; border-radius:6px; font-family:monospace; font-size:11px; overflow-x:auto; margin:0; border:1px dashed \${severity.color};">flexi.setStatusMessage("Please select a valid \${fieldName} value");\n\${associatedWS ? \`flexi.setStatusMessage("\${associatedWS.name} API Failed");\` : ''}</pre>
                </div>
              </div>
            \`;
         }

         screenCodeHtml += \`
           <div style="background:\${severity.badge !== '🟢 Informational' ? \`rgba(\${hexToRgb(severity.color)}, 0.05)\` : 'rgba(255,255,255,0.02)'}; padding:16px; border:1px solid \${severity.badge !== '🟢 Informational' ? \`rgba(\${hexToRgb(severity.color)}, 0.3)\` : 'rgba(255,255,255,0.04)'}; border-radius:8px;">
             <div style="display:flex; justify-content:space-between; align-items:center;">
               <h4 style="margin:0; color:\${severity.color}; font-size:14px; display:flex; align-items:center; gap:8px;">
                 Field: \${escHtml(fieldName)}
               </h4>
               <span style="background:\${severity.color}20; color:\${severity.color}; padding:4px 8px; border-radius:12px; font-size:11px; font-weight:bold;">\${severity.badge}</span>
             </div>
             \${debuggerAssitantHtml}
             \${wsHtml}
             \${eventsHtml}
           </div>
         \`;
      }
    }
    screenCodeHtml += '</div>';

    analysisHtml += \`
      <div class="dbg-copilot-section">
        <div class="dbg-copilot-title" style="color:#38BDF8; font-size:14px; border-bottom:1px solid rgba(56, 189, 248, 0.2); padding-bottom:8px; margin-bottom:16px;">
          <span>🧠</span> FIELD-LEVEL INVESTIGATION & LOG CORRELATION
        </div>
        \${screenCodeHtml}
      </div>
    \`;
  }

  $('dbg-analysis-panel').innerHTML = analysisHtml;
}

// Helper to convert hex to rgb for rgba transparency
function hexToRgb(hex) {
  var result = /^#?([a-f\\d]{2})([a-f\\d]{2})([a-f\\d]{2})$/i.exec(hex);
  return result ? \`\parseInt(result[1], 16)}, \${parseInt(result[2], 16)}, \${parseInt(result[3], 16)}\` : '255, 255, 255';
}
`;

// Now replace the function
code = code.replace(/function runScreenDebuggerAnalysis\(\) \{[\s\S]*?(?=\n\/\/ ─── Helper Extractors ───)/, replacement.trim() + '\n');
fs.writeFileSync('app.js', code);
console.log('App.js updated with new Screen Debugger AI UI');
