# Investigation Engine

**How to systematically investigate Flexi application issues.**

This is not a guide on how to read logs. This is a guide on how to think like a Senior L3 Support Engineer when debugging production issues.

---

## Core Principle

**Logs don't tell you what's wrong. Logs tell you what happened. You have to figure out what SHOULD have happened.**

The gap between what happened and what should have happened is your root cause.

---

## Investigation Framework

### Phase 1: Establish Context (5 minutes)

Before you read a single log line, you need to understand **what the user was trying to do**.

**Questions to ask:**

1. **What page were you on?**
   - Name of Flexi screen/page (e.g., "ItemMaster", "ShipmentConfirm")
   
2. **What field did you interact with?**
   - Which field triggered the issue (e.g., "Item Code search button")
   
3. **What event was triggered?**
   - What action happened (_afterFocus, _onResponseReceived, _beforeExit?)
   
4. **What business object were you processing?**
   - Item? PO? Shipment? Receipt?
   
5. **What API was called?**
   - Service name? URL? What data was sent?

**Why this matters:**

Without context, a NullPointerException in Java could mean:
- A session object wasn't set (scope issue)
- An API returned null (data issue)
- A validation failed (business logic issue)
- A LOV selection was skipped (user behavior issue)

With context, it narrows to one.

---

### Phase 2: Establish Timeline (10 minutes)

Build a **chronological sequence of events** from the log.

**Template:**

```
[HH:MM:SS.mmm] [LOG_LEVEL] [COMPONENT] Message
  ↓ Expected Event
[HH:MM:SS.mmm] [LOG_LEVEL] [COMPONENT] Message
  ↓ ACTUAL Event (matches or diverges?)
[HH:MM:SS.mmm] [LOG_LEVEL] [COMPONENT] Message
```

**Example (ItemMaster page, search for item):**

```
EXPECTED:
[1] User clicks "Search" button
[2] _afterClick event fires
[3] Input validation runs
[4] API callWebService("GetItems", filters) invoked
[5] HTTP 200 received
[6] Response parsed as JSONArray
[7] Items populated in screen grid
[8] Status message: "10 items found"

ACTUAL FROM LOG:
[08:34:52.123] TRACE ItemMaster._afterClick - Starting search
[08:34:52.234] TRACE ItemMaster._onResponseReceived - Response code: 200
[08:34:52.345] ERROR ItemMaster._onResponseReceived - NullPointerException at line 45
[08:34:52.456] WARN UI - Unable to populate items
```

**Gap Analysis:**
- Expected: Response parsing and JSONArray iteration
- Actual: NullPointerException before we see evidence of parsing
- Likely Issue: Response structure unexpected or null

**Key Rule**: If something you expected to see in the log is **missing**, it's a clue.

---

### Phase 3: Classify the Issue (5 minutes)

Categorize what you're looking at:

**By Component:**
- API Issue (HTTP error, response structure, timeout)
- Data Issue (NULL, empty array, unexpected structure)
- Logic Issue (validation failed, business rule rejected)
- Scope Issue (session vs. object scope mismatch)
- Configuration Issue (web service misconfigured)
- Performance Issue (API timeout, slow SQL)
- Missing Evidence Issue (not enough logging)
- Authorization Issue (missing role/duty role)

**By Impact:**
- Complete Failure (user can't proceed)
- Partial Failure (some data missing)
- Silent Failure (no error, but wrong data)
- Degraded (slow but works)

**By Certainty:**
- Definite (clear error message)
- Probable (evidence points to one cause)
- Possible (multiple causes)
- Unknown (not enough information)

---

### Phase 4: Extract Evidence (10 minutes)

For each suspect component, extract **specific facts** from the log:

#### Evidence Type 1: API Call Evidence

```
API: GetItems
URL: /fscm/api/v1/items
Request Method: POST
Request Body: {
  "filters": {
    "itemCode": "ABC123",
    "orgId": "123"
  }
}
Response Code: 200
Response Time: 234ms
Response Body: {
  "result_count": 0,
  "items": [],
  "status": "success"
}
```

**Questions**:
- Is the request correct?
- Is the response code expected?
- Is the response body what code expects?
- Are there required fields missing?

#### Evidence Type 2: Exception Evidence

```
Exception: java.lang.NullPointerException
Location: ItemMaster.js:45
Message: Cannot read property 'length' of null
Stack Trace: 
  at ItemMaster._onResponseReceived (ItemMaster.js:45)
  at callWebService.then (Flexi.js:234)
```

**Questions**:
- What null object caused the exception?
- What line tried to access it?
- What should have been non-null?

#### Evidence Type 3: State Evidence

```
Session Objects at [08:34:52]:
  - selected_org: "123"
  - selected_item: null

Object Scope at [08:34:52]:
  - item_count: 0
  - items_array: []
```

**Questions**:
- Is the state what you expected?
- Did a required object get set?
- Is there a scope mismatch?

#### Evidence Type 4: Logger Evidence

```
logger.trace("API Response: " + responseBody)  ✓ Present
logger.trace("Parsed Items: " + items.length) ✗ MISSING
logger.trace("Validation: " + validation)      ✗ MISSING
```

**Questions**:
- What key instrumentation is missing?
- Where would more logging help?

---

### Phase 5: Build Hypothesis (5 minutes)

Based on evidence, propose **one most likely root cause**:

**Format**:

```
Root Cause Hypothesis:
  API returned empty items array (count=0) but response code 200.
  Code did not check for empty array before iteration.
  When code called items[0], it got undefined/null.
  NullPointerException when trying to access property on null.

Why:
  - Evidence 1: Response body shows items=[]
  - Evidence 2: Exception is on line accessing items[0]
  - Evidence 3: No logger.trace() between response parse and array access
  - Evidence 4: No check for items.length > 0 before accessing

Confidence: HIGH
  Because: Response body and exception line align perfectly
```

---

### Phase 6: Validate Hypothesis (5 minutes)

Ask yourself: **Does my hypothesis explain all the evidence?**

If the hypothesis is "blank API returned zero records":

✅ Explains: Why response code is 200 (API succeeded, just no data)
✅ Explains: Why items array is empty
✅ Explains: Why NullPointerException on line accessing items[0]
✅ Explains: Why status message never shows "items found"
❓ Doesn't fully explain: Is this a query filtering issue or permission issue?

**If hypothesis doesn't explain all evidence, revise it.**

---

### Phase 7: Identify Root Cause Category (5 minutes)

Categorize the **actual root cause**:

#### 1. Missing Data
- API returned null or empty array
- User doesn't have permission (but got 403)
- Data doesn't exist in system

**Indicator**: HTTP 200 + empty/null response

**Recommendation**: 
- Add logger.trace() to log query parameters
- Verify user has permission
- Check if data exists in Oracle

#### 2. Unexpected Data Structure
- API returned nested structure code didn't expect
- API added new field that changed parsing logic
- Response structure changed between API versions

**Indicator**: JSONException or property access on undefined

**Recommendation**:
- Add logger.trace() to log raw response body
- Verify API version matches code
- Check for nested arrays/objects

#### 3. Scope Mismatch
- Object set in session scope, read in object scope
- Object cleared at wrong time
- Object never initialized

**Indicator**: Variable is null when it shouldn't be

**Recommendation**:
- Check all putObject/getObject calls for same scope
- Check initialization timing
- Add logger.trace() for object state

#### 4. Validation Logic Bug
- Code has wrong business rule
- Validation is inverted (checks when shouldn't)
- Missing edge case handling

**Indicator**: Data fails validation when it shouldn't

**Recommendation**:
- Review validation logic
- Add logger.trace() for each validation step
- Test with edge cases

#### 5. Configuration Error
- Web service URL is wrong
- Request payload missing required fields
- API endpoint doesn't exist

**Indicator**: HTTP 404, 400, or consistent failures

**Recommendation**:
- Verify web service configuration in Flexi
- Check API documentation
- Test API call manually

#### 6. Authorization Failure
- User missing duty role
- User missing data role
- Endpoint requires specific role not assigned

**Indicator**: HTTP 403, authorization error message

**Recommendation**:
- Check user's assigned roles in Oracle
- Consult Oracle Cloud documentation for endpoint
- Request role assignment

#### 7. Performance Issue
- API took too long to respond
- SQL query is slow
- Retry loop is infinite

**Indicator**: Timeout error, slow log timestamps

**Recommendation**:
- Check Oracle Query Performance (APEX)
- Identify slow SQL
- Optimize indexes or query

#### 8. Missing Logger
- Can't see what's happening
- Key step has no instrumentation
- No visibility into data flow

**Indicator**: Gap in log output, silent failures

**Recommendation**:
- Add logger.trace() at key points
- Log API request and response
- Log object state before/after update

#### 9. Duplicate Logic Execution
- Code runs twice (API called twice)
- Object updated twice
- Status message shown twice

**Indicator**: Log shows same operation twice

**Recommendation**:
- Check if event fires twice
- Check for async/await issues
- Add guard to prevent double execution

#### 10. Business Logic Bug
- Calculation is wrong
- Condition is inverted
- Edge case not handled

**Indicator**: Wrong output despite correct input

**Recommendation**:
- Review business logic step by step
- Test with specific data values
- Add logger.trace() for each calculation

---

## Investigation Rules

### Rule 1: Always Check the Basics First

```
Error: NullPointerException

Check in this order:
1. Is the object null? (logger.trace the object before use)
2. Did the API return null? (logger.trace the response)
3. Did the user skip a required step? (LOV selection?)
4. Is there a scope mismatch? (session vs. object scope)
5. Is the initialization missing? (object not created?)
```

### Rule 2: "200 OK" Doesn't Mean Success

```
Response Code: 200
Items: []
Count: 0

This is NOT a success.
This is "API worked, but returned no data" = Business Failure.

Never assume HTTP 200 means "happy path."
Always check the response body.
```

### Rule 3: Missing Logger Calls Are a Clue

```
Expected log sequence:
1. API request: logger.trace("Request: " + payload)
2. API response code: logger.trace("Response Code: " + code)
3. Response parsing: logger.trace("Response: " + body)
4. Array iteration: logger.trace("Items found: " + count)
5. Validation: logger.trace("Validation: " + result)

If step 3 or 4 is missing from the log, something went wrong there.
Add logger.trace() at missing step and rerun.
```

### Rule 4: Scope Mismatches Are Silent Killers

```
This is invisible in the log but deadly in behavior:

putSessionObject("item", itemData)  // Session scope
...
getObject("item")                   // Object scope
Result: null (but no error!)

Symptom: Variable is null, but no exception logged.
Investigation: Check all put/get pairs for same scope.
```

### Rule 5: Event Ordering Matters

```
If exception happens in _onResponseReceived:
  1. What event fired before? (_afterClick, _afterFocus?)
  2. Did the API actually return? (check response code)
  3. Was _onResponseReceived registered? (check page definition)

Event ordering issues cause silent failures.
```

### Rule 6: Nested Structures Cause Parsing Failures

```
Code expects:
{ "items": [...] }

API returns:
{ "shipments": [{ "shipmentLines": [...] }] }

Result: items is undefined, array access fails.

Investigation: Always logger.trace() the raw response first.
Then validate structure matches code.
```

### Rule 7: Authorization Failures Are Domain-Specific

```
If Oracle Fusion API returns 403:
  1. Check if user has Duty Role (e.g., "Item Management Specialist")
  2. Check if user has Job Role (e.g., "Procurement Manager")
  3. Check if user has Data Role (e.g., "OU-001")
  4. Check if endpoint requires specific role (Oracle docs)

Oracle doesn't return "missing role X" in the error—you have to deduce it.
Ask user what roles they have assigned.
```

### Rule 8: Timeout Issues Are Often Query Issues

```
Symptom: API returns after 30+ seconds, then timeout.

Causes (in order of likelihood):
  1. Slow SQL query in backend (check Oracle Query Performance)
  2. Oracle Cloud overloaded (check status page)
  3. Network latency (check network monitor)
  4. Code has infinite loop (check for exit condition)

Investigation: Ask for query parameters sent. Check if query is too broad.
```

### Rule 9: Duplicate API Calls Mean Event Registration Issue

```
Symptom: Same API called twice in 100ms.

Causes:
  1. Event handler registered twice (_afterClick twice?)
  2. Code calls API manually + event fires automatically
  3. Validation loop retries without clearing flag

Investigation: Check page definition for duplicate event handlers.
Check code for manual API call when event already handles it.
```

### Rule 10: Silent Failures Often Come From Missing Validation

```
Symptom: No error, no log, but wrong data in system.

Causes:
  1. Validation doesn't exist (code assumed it was there)
  2. Validation is in wrong event (runs too late)
  3. Validation result is ignored (code doesn't check return value)

Investigation: Add validation and logger.trace() results.
Check if validation is called before saving.
```

---

## Confidence Levels

### HIGH Confidence (>80%)
- Multiple evidence points to same root cause
- Root cause explains all observations
- Similar pattern in playbooks matches

**Example**: API returned empty array, code tried to access [0], got null. Root cause: missing empty array check. Confidence: HIGH.

### MEDIUM Confidence (50-80%)
- Root cause explains most observations
- One or two evidence pieces missing
- Could be one of two causes

**Example**: NullPointerException on line accessing object. Could be: (1) API returned null, or (2) scope mismatch. Confidence: MEDIUM. Need: logger showing response body or object state.

### LOW Confidence (<50%)
- Root cause is speculative
- Multiple possible causes
- Need significant more information

**Example**: Generic "Something went wrong" error. Could be: API issue, config issue, permission issue, or data issue. Confidence: LOW. Need: full log, API response, user role info, etc.

---

## Confidence Boosters

To move from MEDIUM to HIGH:

1. **Add logger.trace() to key points** → Get missing visibility
2. **Check API response directly** → Verify what was actually returned
3. **Review code logic line-by-line** → Confirm what should happen vs. what actually happens
4. **Check similar patterns in playbooks** → Confirm this matches known issue
5. **Ask user for missing context** → Page name, field, exact action, etc.
6. **Test hypothesis with same data** → Reproduce issue with same inputs

---

## Common Investigation Mistakes

### ❌ Mistake 1: Assuming HTTP 200 Means Success

```
API Response: HTTP 200
Response: { "result_count": 0, "items": [] }
Assumption: "API worked"
Reality: API returned no data (could be permission, filtering, or missing data)

Correct: Check response body, not just status code.
```

### ❌ Mistake 2: Ignoring Missing Log Lines

```
Expected: 5 logger.trace() calls
Actual: 3 logger.trace() calls
Missing: Lines 4-5 (response parsing, array iteration)
Assumption: "Those lines weren't important"
Reality: Exception happened at one of those lines

Correct: Missing log lines are clues. Add them and rerun.
```

### ❌ Mistake 3: Not Reconstructing Timeline

```
Error: NullPointerException
Assumption: "A variable is null"
Reality: Without timeline, don't know WHEN or WHY it became null

Correct: Build timeline from log. Identify when variable should have been set.
```

### ❌ Mistake 4: Forgetting About Scope

```
Error: getObject returns null
Assumption: "Object was never set"
Reality: Object was set in session scope, code reads from object scope

Correct: Check all put/get calls. Ensure same scope.
```

### ❌ Mistake 5: Not Checking Authorization

```
API Error: 403 Forbidden
Assumption: "User is blocked from using feature"
Reality: User might be missing specific Oracle role assignment

Correct: Ask for user's assigned roles. Check Oracle Cloud docs for endpoint requirements.
```

### ❌ Mistake 6: Over-Generalizing from One Error

```
Error: NullPointerException at line 45
Assumption: "We need to add null checks everywhere"
Reality: Only line 45 has the issue

Correct: Find root cause for line 45. Don't over-engineer.
```

---

## Recommended Logger Placements

Add `logger.trace()` at these points:

### Before API Call
```javascript
logger.trace("Preparing GetItems API call");
logger.trace("Request Payload: " + JSON.stringify(requestPayload));
logger.trace("Calling API: GetItems");
callWebService("GetItems", requestPayload, onSuccess, onError);
```

### After API Returns
```javascript
function onSuccess(response) {
  logger.trace("GetItems API response received");
  logger.trace("Response Code: " + response.getResponseCode());
  logger.trace("Raw Response Body: " + response.getResponseBody());
  
  // Parse
  var jsonResp = parseJSON(response.getResponseBody());
  logger.trace("Parsed JSON: " + JSON.stringify(jsonResp));
  
  // Extract array
  var items = jsonResp.items;
  logger.trace("Items array length: " + (items ? items.length : "null"));
  
  // Validation
  if (items && items.length > 0) {
    logger.trace("Validation: PASS (found " + items.length + " items)");
  } else {
    logger.trace("Validation: FAIL (no items found)");
    setStatusMessage("No Data", "No items found for selected criteria", "warning");
    return;
  }
}
```

### On Error
```javascript
function onError(error) {
  logger.error("GetItems API failed");
  logger.error("Error Message: " + error.message);
  logger.error("Error Code: " + error.code);
  logger.error("Error Details: " + JSON.stringify(error));
  setStatusMessage("Error", "Failed to load items: " + error.message, "error");
}
```

---

## Summary

**Investigation is not guessing. Investigation is**:

1. ✅ Establishing context (what was user doing?)
2. ✅ Building timeline (chronological sequence)
3. ✅ Classifying issue (API, data, logic, scope, config?)
4. ✅ Extracting evidence (facts from log)
5. ✅ Building hypothesis (most likely cause)
6. ✅ Validating hypothesis (does it explain all evidence?)
7. ✅ Identifying root cause (which category?)
8. ✅ Rating confidence (can I be certain?)
9. ✅ Recommending fix (logger, code change, or info request)

**You are done when**:
- Root cause is clearly identified
- Confidence is HIGH
- Recommendation is specific and actionable
- All evidence supports your conclusion

---

**Next**: Read `universal_log_engine.md` to learn how to parse and normalize logs.
