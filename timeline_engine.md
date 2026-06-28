# Timeline Engine

**How to reconstruct chronological execution flow from logs and use it to identify where behavior diverged from expectations.**

A timeline is not just a list of events. It's a visualization of what should have happened vs. what actually happened, with gaps marked clearly.

---

## Core Concept

**Timeline = Expected Sequence vs. Actual Sequence**

```
Expected Timeline:
[1] User clicks search button
[2] _afterClick event fires
[3] Input validation runs
[4] callWebService("GetItems") invoked
[5] HTTP 200 response received
[6] Response parsed as JSONArray
[7] Items populated in screen
[8] Status message: "10 items found"

Actual Timeline from Log:
[1] User clicks search button ✓
[2] _afterClick event fires ✓
[3] Input validation runs ✓
[4] callWebService("GetItems") invoked ✓
[5] HTTP 200 response received ✓
[6] NullPointerException ✗
[7] ERROR: Cannot read property 'length' of null
[8] [Stops here]

Divergence Point: Between [5] and [6]
What's Missing: Response parsing step
Likely Issue: Response structure unexpected or null
```

---

## Building a Timeline

### Step 1: Extract All Log Entries

From raw log, extract every line with timestamp and event:

```
[08:34:52.100] TRACE ItemMaster._afterPageEntered - Page initialized
[08:34:52.110] TRACE ItemMaster._afterFocus - Focus on itemCodeField
[08:34:52.120] TRACE User action - Clicked search button
[08:34:52.121] TRACE ItemMaster._afterClick - Search button clicked
[08:34:52.122] TRACE ItemMaster._inputProcessor - Validating input
[08:34:52.123] TRACE Validation: itemCode not empty ✓
[08:34:52.124] TRACE Calling GetItems API with {orgId: 123, itemCode: ABC}
[08:34:52.125] TRACE callWebService("GetItems") started
[08:34:52.234] TRACE GetItems API response received
[08:34:52.235] TRACE Response Code: 200
[08:34:52.236] TRACE Raw Response: {items: [], result_count: 0}
[08:34:52.237] TRACE Processing response...
[08:34:52.238] ERROR NullPointerException: Cannot read property 'length' of null
```

### Step 2: Calculate Durations

For each API or significant operation, calculate how long it took:

```
[08:34:52.125] callWebService("GetItems") started
[08:34:52.234] callWebService("GetItems") completed
Duration: 234 - 125 = 109ms

Interpretation:
< 1s   = Normal
1-5s   = Acceptable
5-30s  = Slow (investigate query)
>30s   = Timeout likely
```

### Step 3: Identify Sequence

Order events chronologically:

```
Timeline (with durations):

[T+0ms]    Page Load → _afterPageEntered
[T+10ms]   Field Focus → _afterFocus
[T+20ms]   User clicks search button
[T+21ms]   Event fires → _afterClick
[T+22ms]   Validation runs → _inputProcessor
[T+23ms]   Validation passes
[T+24ms]   API call starts → GetItems
[T+109ms]  API returns HTTP 200 (duration: 85ms - normal)
[T+110ms]  Response parsing
[T+111ms]  NullPointerException (parsing failed)
[T+112ms]  Error displayed to user
```

### Step 4: Mark Expected vs. Actual

Compare timeline against what should happen:

```
EXPECTED SEQUENCE:

User Action
  ↓ [0ms delay]
Event fires
  ↓ [10-50ms]
Validation runs
  ↓ [if pass, <50ms]
API called
  ↓ [1-5s typical]
Response received
  ↓ [10-50ms]
Response parsed
  ↓ [<100ms]
Data validated
  ↓ [<50ms]
Screen updated
  ↓ [<100ms]
User feedback (status message)

ACTUAL SEQUENCE (from log):

User Action ✓
  ↓ 1ms
Event fires ✓
  ↓ 1ms
Validation runs ✓
  ↓ 1ms
Validation passes ✓
  ↓ 1ms
API called ✓
  ↓ 109ms
Response received ✓
  ↓ 1ms
Response parsing [EXPECTED 10-50ms, got ERROR]
  ↗ DIVERGENCE
NullPointerException ✗
Screen NOT updated
User sees error
```

---

## Timeline Patterns

### Pattern 1: Expected Event Missing

```
Timeline shows:
[T1] User clicked button
[T2] Data displayed

Missing between T1-T2:
- Event handler firing?
- API call?
- Validation?

Investigation:
- Is event handler registered?
- Is it conditional (only fires sometimes)?
- Does it have error handler?
```

### Pattern 2: Slow Operation

```
Timeline shows:
[T1] API called: GetItems
[T2] API response received
Duration: 45 seconds

Normal: <5 seconds
Actual: 45 seconds

Possible causes:
1. Oracle query is slow (missing index?)
2. Oracle Cloud overloaded (many concurrent requests?)
3. Network timeout and retry (took multiple attempts?)
4. Code has infinite loop (waiting for something)?

Investigation:
- Ask for: How many rows were returned?
- Check: Oracle Query Performance (APEX)
- Check: Oracle Cloud status page
- Check: Network retry loops in log
```

### Pattern 3: Event Fires Twice

```
Timeline shows:
[T1] _afterClick fires
[T2] API called: GetItems
[T3] API response
[T4] _afterClick fires AGAIN
[T5] API called: GetItems AGAIN
[T6] API response

Possible causes:
1. Event handler registered twice in page definition
2. Manual API call + event both trigger
3. Validation error, retry loop, fires again

Investigation:
- Check page definition: _afterClick registered twice?
- Check code: Any manual callWebService before event?
- Check validation: Is there a retry loop?
```

### Pattern 4: Long Silence (Gap in Log)

```
Timeline shows:
[T1] API called: GetItems
[T2] 10 second gap with no logs
[T3] ERROR: Timeout

Possible causes:
1. API is slow (Oracle query slow)
2. Network timeout (network issue)
3. Code is waiting (blocking call)
4. No logger.trace() between T1-T3

Investigation:
- If gap and no timeout error: Missing logger calls
  → Add logger.trace() to see what's happening
- If gap with timeout error: API took too long
  → Check Oracle performance, network, Oracle Cloud status
```

### Pattern 5: Correct Sequence, Wrong Data

```
Timeline shows:
[T1] API called
[T2] Response received (HTTP 200)
[T3] Data parsed
[T4] Validation passed ✓
[T5] Data saved ✓
[T6] Status message: "Success"

But in Oracle, data is WRONG.

Possible causes:
1. Validation logic incorrect (checks wrong condition)
2. Data transformation wrong (calculated wrong value)
3. Wrong field mapped to Oracle
4. Edge case not handled

This is a LOGIC BUG, not an integration issue.

Investigation:
- Review validation logic step by step
- Review data transformation step by step
- Add logger.trace() for calculated values
- Test with specific data that failed
```

---

## Timeline Reconstruction Algorithm

### Given: Raw log entries with timestamps

### Step 1: Normalize Timestamps

All timestamps to milliseconds since start:

```
[08:34:52.100] → 0ms
[08:34:52.125] → 25ms
[08:34:52.234] → 134ms
[08:34:52.238] → 138ms
```

### Step 2: Extract Events

For each line, identify:
- **Timestamp**
- **Event Name** (user action, API call, exception, etc.)
- **Component** (page, event handler, etc.)
- **Status** (success, error, pending)

```
0ms:    Event=PageLoad, Component=ItemMaster, Status=Success
25ms:   Event=FieldFocus, Component=itemCodeField, Status=Success
100ms:  Event=UserClick, Component=searchButton, Status=Success
121ms:  Event=EventFire, Component=_afterClick, Status=Success
125ms:  Event=APICall, Component=GetItems, Status=Pending
234ms:  Event=APIResponse, Component=GetItems, Status=Success (HTTP 200)
238ms:  Event=ResponseParsing, Component=_onResponseReceived, Status=Error
```

### Step 3: Calculate Durations

For each operation with start and end:

```
Operation: GetItems API
Start: 125ms
End: 234ms
Duration: 109ms
Status: Completed successfully
```

### Step 4: Identify Gaps

Where are log entries missing?

```
Between 234ms (API response) and 238ms (exception):
- Response parsing should take 10-50ms
- But we see exception at 238ms (only 4ms later)
- This suggests parsing failed immediately
- Not a slow parsing, but a FAILED parsing
```

### Step 5: Build Timeline Visualization

```
Timeline (milliseconds from start):

T+0ms ──────────────────────────────────────┐
      ItemMaster Page Loads                  │ Duration: 100ms
T+100ms ────────────────────────────────────┤ (user interaction delay)

T+100ms User Clicks Search
T+121ms ─┐
        _afterClick Event Fires
T+123ms ├─ Input Validation (PASS)
        │  Duration: 2ms
T+125ms │
        ├─ callWebService("GetItems")
T+234ms │  Duration: 109ms (normal)
        └─ HTTP 200 Received

T+234ms Response Parsing
T+238ms ─✗─ NullPointerException
          └─ Duration: 4ms
          └─ Expected: 10-50ms

Root Cause: Response parsing failed at 238ms
Likely Issue: Response structure unexpected
```

---

## Advanced Timeline Analysis

### Analyzing Multiple Concurrent Operations

If user has multiple pages/operations running:

```
Timeline with multiple operations:

ItemMaster Page:
T+0ms ──────┐ Page load
T+100ms ────┤ _afterPageEntered
T+125ms ────┼─┐ GetItems API call
T+234ms ────┼─┴─ GetItems response

ShipmentPage:
T+50ms ───────────┐ Page load
T+150ms ──────────┤ _afterPageEntered
T+180ms ──────────┼─┐ GetShipment API call
T+290ms ──────────┼─┴─ GetShipment response

Observations:
- Both pages initialized ~100ms after start
- Both called APIs ~30-80ms after their page load
- APIs run concurrently (not blocking each other)
- If one API fails, the other is unaffected
```

### Analyzing Chained API Calls

If multiple APIs called in sequence:

```
Timeline with API chaining:

T+0ms ──────────────────────────────────────────────────
      GetOrganizations API
T+234ms ─────────────────────┐
                             Next: Parse response, extract OrgId=123

T+240ms ──────────────────────────────────────────────────
        GetItems API (with OrgId=123)
T+380ms ──────────────────────┐
                              Next: Parse response, display items

Expected pattern:
API1 → Parse1 → Extract1 → API2 → Parse2 → Display

Actual pattern (from log):
API1 → Parse1 → Extract1 ✓
API2 → Error at Parse2 ✗

Root Cause: Chained API pattern broken at API2 parsing
Investigation: API2 response structure different?
```

---

## Timeline-Based Debugging

### Using Timeline to Pinpoint Exact Failure Point

**Question**: "When did the issue start?"

**Timeline answer**: "At T+238ms during response parsing in _onResponseReceived event."

**Question**: "What was the last successful operation?"

**Timeline answer**: "HTTP 200 response received at T+234ms from GetItems API. Parsing started at T+238ms."

**Question**: "What should have happened next?"

**Timeline answer**: "Response should have been parsed into JSONObject, then JSONArray extracted. Should take <50ms. But exception occurred after only 4ms."

**Question**: "What does this tell us?"

**Timeline answer**: "Parsing failed immediately, likely due to unexpected response structure. Raw response should be logged to see what API returned vs. what code expected."

---

## Timeline Checklist

When building timeline, verify:

- [ ] All timestamps present?
- [ ] Timestamps in chronological order?
- [ ] No gaps >1 second without explanation?
- [ ] Expected events present?
- [ ] Operations taking expected duration (API <5s, parse <50ms)?
- [ ] All error entries have context (where, why)?
- [ ] Timeline shows clear divergence point?
- [ ] Root cause narrowed down?

---

## Summary

**Timeline Engine teaches you to**:

1. ✅ Extract and normalize timestamps
2. ✅ Build chronological sequence
3. ✅ Calculate operation durations
4. ✅ Identify gaps and missing log entries
5. ✅ Compare expected vs. actual execution
6. ✅ Pinpoint exact failure point
7. ✅ Identify patterns (slow ops, missing events, etc.)

**You are done when**:
- You can visualize the entire execution flow
- You can point to exact line in log where behavior diverged
- You can identify what should have happened but didn't
- You can explain why the failure happened at that specific point

---

**Next**: Read `api_engine.md` to learn how to investigate API-specific issues.
