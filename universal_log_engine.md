# Universal Log Engine

**How to parse, normalize, and extract meaning from logs from any source.**

A Flexi application produces logs from multiple sources: Flexi client-side logger, Oracle backend, web service responses, network traces, browser console, etc. This engine teaches you how to extract signal from all of them.

---

## Log Sources

### Source 1: Flexi Client-Side Logger

**Format**: `[HH:MM:SS.mmm] [LEVEL] ComponentName - Message`

**Example**:
```
[08:34:52.123] TRACE ItemMaster._afterPageEntered - Initializing page
[08:34:52.234] DEBUG ItemMaster.GetItems - API call payload: {orgId: 123}
[08:34:52.345] TRACE ItemMaster._onResponseReceived - Response code: 200
[08:34:52.456] ERROR ItemMaster._onResponseReceived - NullPointerException: Cannot read property 'length' of null
```

**Parsing Rules**:
- `[HH:MM:SS.mmm]` = Timestamp (use to build timeline)
- `[LEVEL]` = TRACE, DEBUG, INFO, WARN, ERROR (use to identify severity)
- `ComponentName` = Page or event (use to identify context)
- `Message` = Human-readable log (extract facts from this)

**Key Indicators**:
- TRACE = Instrumentation (good—developer added this intentionally)
- DEBUG = Informational (something noteworthy)
- INFO = Standard flow (ok)
- WARN = Something unexpected but continued
- ERROR = Something failed

---

### Source 2: API Response Logs

**Format**: Depends on API (Oracle, third-party, custom)

**Oracle Cloud API Response**:
```json
{
  "statusCode": 200,
  "responseTime": "234ms",
  "body": {
    "items": [
      { "itemId": "ABC123", "itemName": "Widget" },
      { "itemId": "DEF456", "itemName": "Gadget" }
    ],
    "result_count": 2,
    "status": "success"
  },
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token..."
  }
}
```

**Parsing Rules**:
- Extract `statusCode` (200 = HTTP success, but check body for business success)
- Extract `responseTime` (>5s = slow, >30s = timeout likely)
- Extract `body.result_count` (0 = blank API)
- Extract `body.items` (array structure tells you parsing requirements)
- Check `headers` for auth/version info

---

### Source 3: Stack Traces

**Format**: Exception with call stack

**Example**:
```
java.lang.NullPointerException: Cannot read property 'length' of null
  at ItemMaster._onResponseReceived (ItemMaster.js:45)
  at Flexi.callWebService.then (Flexi.js:234)
  at Java.invoke (Native Method)
```

**Parsing Rules**:
- Line 1: Exception type and message
  - `NullPointerException` = accessing property on null
  - `ArrayIndexOutOfBoundsException` = accessing array out of bounds
  - `JSONException` = JSON parsing failed
  - `ClassCastException` = type mismatch
  
- Line 2+: Stack trace (read from top)
  - Top of stack = where exception occurred
  - Next lines = what called it
  - Bottom = entry point

**Example parsing**:
```
Exception: NullPointerException
Location: ItemMaster.js:45 (this is where null access happened)
Function: ItemMaster._onResponseReceived
Caller: Flexi.callWebService.then

Interpretation: API returned successfully, code tried to process response,
something in the response was null that code didn't expect.
```

---

### Source 4: Network Traces (Browser DevTools)

**Format**: HTTP request/response pairs

**Example**:
```
Request:
  GET /fscm/api/v1/items?orgId=123&itemCode=ABC HTTP/1.1
  Host: oracle-instance.cloud.oracle.com
  Authorization: Bearer eyJhbGc...
  Accept: application/json

Response:
  HTTP/1.1 200 OK
  Content-Type: application/json
  Content-Length: 1234
  
  {
    "items": [],
    "result_count": 0,
    "status": "success"
  }
```

**Parsing Rules**:
- Extract request method (GET, POST, PUT, DELETE)
- Extract request URL and query parameters
- Extract request headers (especially Authorization, Content-Type)
- Extract response status code
- Extract response body (raw JSON, not parsed)

**Key Questions**:
- Is the request URL correct?
- Are query parameters what code sent?
- Is the response what's expected?
- Is there an Authorization header?

---

### Source 5: Browser Console

**Format**: JavaScript console output

**Example**:
```
ItemMaster._afterPageEntered starting
Getting selected item from session: ABC123
Calling GetItemDetails API with payload: {...}
Response received: Object { items: Array(0) }
ERROR: Cannot iterate over null
```

**Parsing Rules**:
- Treat as context (what was user doing)
- Look for "ERROR", "Exception", or stack traces
- Follow console.log/console.error breadcrumbs
- Check for warnings (⚠️)

---

## Log Normalization

Different logs use different formats. Normalize them to a standard:

### Standard Log Entry Format

```
{
  "timestamp": "2026-06-26T08:34:52.345Z",
  "level": "ERROR",
  "source": "Flexi Client",
  "component": "ItemMaster",
  "event": "_onResponseReceived",
  "message": "NullPointerException: Cannot read property 'length' of null",
  "context": {
    "page": "ItemMaster",
    "field": "itemCode",
    "api": "GetItemDetails",
    "businessObject": "Item"
  },
  "evidence": {
    "exceptionType": "NullPointerException",
    "exceptionLocation": "ItemMaster.js:45",
    "lastSuccessfulStep": "API response received (HTTP 200)",
    "failedStep": "Array iteration"
  }
}
```

### How to Normalize

**From Flexi log**:
```
[08:34:52.345] ERROR ItemMaster._onResponseReceived - NullPointerException: Cannot read property 'length' of null
```

**Normalize to**:
```json
{
  "timestamp": "2026-06-26T08:34:52.345Z",
  "level": "ERROR",
  "source": "Flexi Client",
  "component": "ItemMaster",
  "event": "_onResponseReceived",
  "message": "NullPointerException: Cannot read property 'length' of null"
}
```

**From API response**:
```json
{
  "statusCode": 200,
  "responseBody": { "items": [], "result_count": 0 }
}
```

**Normalize to**:
```json
{
  "timestamp": "2026-06-26T08:34:52.350Z",
  "level": "INFO",
  "source": "Oracle API",
  "api": "GetItemDetails",
  "httpStatus": 200,
  "message": "API returned 0 items",
  "evidence": {
    "itemsCount": 0,
    "resultCount": 0,
    "status": "success"
  }
}
```

---

## Log Extraction Rules

### Rule 1: Extract Timestamps

```
[08:34:52.123] TRACE ItemMaster._afterPageEntered - ...
         ↑
    This is your timeline anchor.

Use timestamps to:
1. Order events chronologically
2. Calculate duration (from T1 to T2 = T2 - T1)
3. Identify slow operations (duration > 5 seconds)
4. Identify rapid sequences (multiple calls in <100ms)
```

**Example**: 
```
[08:34:52.100] TRACE GetItems API called
[08:34:52.340] TRACE GetItems API response received
Duration: 240ms (normal, <5s)

vs.

[08:34:52.100] TRACE GetItems API called
[08:35:12.100] TRACE GetItems API response received
Duration: 20s (SLOW, likely timeout or Oracle overload)
```

### Rule 2: Extract Log Levels

```
TRACE = Developer instrumentation (intentional logging)
DEBUG = Informational (noteworthy but not error)
INFO = Standard operation
WARN = Unexpected but recovered
ERROR = Something failed
```

**Interpretation**:
- If you see many TRACE lines → good instrumentation
- If you see ERROR with no TRACE before it → missing logger placement
- If you see WARN without ERROR → application recovered

**Example**:
```
TRACE CallAPI → DEBUG APIResponse → ERROR JSONParsing

Good: Developer anticipated this and added TRACE. But they didn't add DEBUG/TRACE
after API call returned, so we don't see the raw response. 
Recommendation: Add logger.trace("Raw Response: " + body)
```

### Rule 3: Extract Component & Event Names

```
[08:34:52.123] TRACE ItemMaster._afterPageEntered - ...
                     ↑                     ↑
                 Component             Event

Component = Page/Screen name
Event = Which event fired in page lifecycle

Use to understand:
1. What page was user on?
2. What event triggered the issue?
3. Were events fired in correct order?
```

### Rule 4: Extract API Calls

```
logger.trace("API Call: GetItems")
logger.trace("Request Payload: {orgId: 123, itemCode: ABC}")
logger.trace("Response Code: 200")
logger.trace("Response Body: {items: [], result_count: 0}")

Extract:
- API name: GetItems
- Request params: orgId=123, itemCode=ABC
- Response code: 200
- Response body: {...}

Use to:
1. Verify request is correct
2. Check response matches expectations
3. Identify if API returned blank result
```

### Rule 5: Extract Exception Information

```
ERROR ItemMaster._onResponseReceived - NullPointerException: Cannot read property 'length' of null

Extract:
- Exception type: NullPointerException
- Exception message: Cannot read property 'length' of null
- Location: ItemMaster._onResponseReceived

Interpret:
- Type tells you the category (null access, index out of bounds, type mismatch)
- Message tells you what was null/out of bounds/mismatched
- Location tells you where in the code it happened
```

### Rule 6: Extract Missing Lines

```
Expected sequence:
1. logger.trace("API Response: " + code)
2. logger.trace("Parse Response: " + body)
3. logger.trace("Items found: " + items.length)

Actual log:
1. logger.trace("API Response: 200")
[MISSING]
ERROR: NullPointerException

Interpretation: Missing line means exception happened between 1-3.
Most likely: Between parse and array access.
Recommendation: Add logger.trace() at lines 2-3 and rerun.
```

---

## Log Pattern Recognition

### Pattern 1: Blank API (HTTP 200 + 0 Records)

**Log signs**:
```
[T1] TRACE API Response Code: 200
[T2] TRACE Response Body: {items: [], result_count: 0}
[T3] No ERROR (application may or may not handle it)
```

**Interpretation**: API succeeded but returned no data.

**Root causes** (in order of likelihood):
1. User doesn't have permission to see data (but Oracle returned 200, not 403)
2. Query filter is too restrictive
3. Data doesn't exist in system
4. Data was recently purged

**Investigation**:
- Add logger.trace() for query parameters sent
- Check user's assigned roles
- Verify data exists in Oracle

---

### Pattern 2: Scope Mismatch

**Log signs**:
```
[T1] TRACE Initializing itemData = {id: 123, name: "Widget"}
[T2] TRACE Storing item in session: putSessionObject("item", itemData)
[T3] [silence - no logger.trace() when reading]
[T4] ERROR NullPointerException: Cannot read property 'id' of null
```

**Interpretation**: Object was stored in session scope, code tried to read from object scope.

**Diagnostic**: Check all putObject/getObject pairs:
```javascript
// Wrong pattern:
flexi.putSessionObject("item", data)  // Session scope
...
var item = flexi.getObject("item")    // Object scope - returns null!

// Correct pattern:
flexi.putObject("item", data)         // Object scope
...
var item = flexi.getObject("item")    // Object scope - returns data
```

---

### Pattern 3: Nested Array Structure

**Log signs**:
```
[T1] TRACE Response: {shipments: [{shipmentLines: [...]}]}
[T2] TRACE Getting items array: var items = response.items
[T3] TRACE Items length: undefined (not a number!)
[T4] ERROR NullPointerException when accessing items[0]
```

**Interpretation**: Code expected `{items: [...]}` but API returned `{shipments: [{shipmentLines: [...]}]}`

**Diagnostic**: Always log raw response first:
```javascript
logger.trace("Raw Response: " + JSON.stringify(response))
```

Then validate structure matches what code expects.

---

### Pattern 4: Duplicate API Calls

**Log signs**:
```
[08:34:52.100] TRACE GetItems API called
[08:34:52.340] TRACE GetItems API Response: {items: [...]}
[08:34:52.342] TRACE GetItems API called (AGAIN!)
[08:34:52.582] TRACE GetItems API Response: {items: [...]}
```

**Interpretation**: Same API called twice in quick succession.

**Root causes**:
1. Event handler registered twice in page definition
2. Code manually calls API + event fires automatically
3. Validation loop retries without clearing flag

**Investigation**:
- Check if _afterClick registered twice
- Check if manual API call and event both trigger
- Look for while/for loop without exit condition

---

### Pattern 5: Missing Logger Instrumentation

**Log signs**:
```
[T1] TRACE CallGetItems API
[T2] [Long silence, no logs for 2 seconds]
[T3] ERROR NullPointerException

What we're missing:
- Response code (did API succeed?)
- Response body (what did API return?)
- Parsing steps (where did parsing fail?)
```

**Diagnostic**: The gap means missing logger calls.

**Recommendation**: Add logger.trace() at these points:
```javascript
// After API returns:
function onSuccess(response) {
  logger.trace("Response Code: " + response.getResponseCode());  // Add this
  logger.trace("Raw Response: " + response.getResponseBody());   // Add this
  
  // Parse:
  var json = parseJSON(...);
  logger.trace("Parsed: " + JSON.stringify(json));               // Add this
  
  // Extract:
  var items = json.items;
  logger.trace("Items: " + items);                               // Add this
  
  // Validate:
  if (items && items.length > 0) { ... }
}
```

---

### Pattern 6: Authorization Failure

**Log signs**:
```
[T1] TRACE CallGetItems API
[T2] TRACE Response Code: 403 Forbidden
[T3] TRACE Error Message: "Access Denied"
[T4] ERROR Authorization failed
```

**Interpretation**: User is missing permission.

**Root causes** (Oracle Fusion specific):
1. Missing Duty Role (e.g., "Item Management Specialist")
2. Missing Job Role (e.g., "Procurement Manager")
3. Missing Data Role (e.g., OU-001 not accessible)
4. Endpoint requires specific role not in docs

**Investigation**:
- Ask user: What roles are you assigned?
- Check Oracle Cloud docs for endpoint role requirements
- Verify role assignment in Oracle Identity

---

### Pattern 7: Performance Degradation

**Log signs**:
```
[08:34:52.100] TRACE GetItems API called
[08:35:12.100] TRACE GetItems API response (after 20 seconds!)
[08:35:12.200] ERROR Timeout: Request took longer than 30s

or

[08:34:52.100] TRACE GetItems API response Time: 234ms (normal)
[08:34:53.100] TRACE GetItems API response Time: 3245ms (SLOW)
[08:34:54.100] TRACE GetItems API response Time: 8765ms (VERY SLOW)
[08:34:55.100] TIMEOUT
```

**Interpretation**: API is getting progressively slower.

**Root causes** (in order of likelihood):
1. Oracle is slow (check Oracle Query Performance)
2. Query is inefficient (too many rows, missing index)
3. Oracle Cloud is overloaded (check status page)
4. Network latency (unlikely if it was fast before)

**Investigation**:
- Ask for query parameters (how many rows requested?)
- Check Oracle APEX Query Performance
- Look for missing indexes
- Check Oracle Cloud status page

---

### Pattern 8: Silent Failure (Wrong Data, No Error)

**Log signs**:
```
[T1] TRACE API Response: 200
[T2] TRACE Items loaded: 5 items
[T3] TRACE Validation: PASS (no ERROR!)
[T4] TRACE Saving data
[T5] TRACE Save successful

But in Oracle, data is WRONG.
```

**Interpretation**: No error logged, but data saved is incorrect.

**Root causes**:
1. Validation logic is wrong (checks wrong condition)
2. Data transformation is wrong (calculated wrong value)
3. Wrong field mapped (sent to wrong column)
4. Edge case not handled (worked for 95% of inputs)

**Investigation**:
- Review validation logic step by step
- Add logger.trace() for each validation check
- Add logger.trace() for each transformation
- Test with specific data values that failed

**Recommendation**: Add more logging:
```javascript
logger.trace("Input data: " + JSON.stringify(input));
logger.trace("Validation rule 1: " + check1);
logger.trace("Validation rule 2: " + check2);
logger.trace("Transformation result: " + result);
logger.trace("Output data: " + JSON.stringify(output));
```

---

## Log Analysis Checklist

When analyzing a log, ask yourself:

### Questions About Timeline
- [ ] What is the first event? (user action or system initialization?)
- [ ] What is the sequence of events? (chronological from first to last?)
- [ ] Where are the gaps? (jumps in time? missing logs?)
- [ ] What is the last successful step before error?
- [ ] At what point did behavior diverge from expected?

### Questions About Components
- [ ] What page/screen is involved?
- [ ] What events fired? (in correct order?)
- [ ] What APIs were called?
- [ ] What data was processed?
- [ ] What was the final state?

### Questions About Evidence
- [ ] Is HTTP status code consistent with success/failure?
- [ ] Does response body match what code expects?
- [ ] Are required fields present in response?
- [ ] Is there a stack trace? (what line?)
- [ ] Are there TRACE logs? (good instrumentation or missing?)

### Questions About Root Cause
- [ ] Is this a known pattern? (check playbooks)
- [ ] What category? (API, data, logic, scope, config, auth, perf, missing logger, duplicate, business logic)
- [ ] What is the most likely cause?
- [ ] What would confirm this cause?
- [ ] What is my confidence level?

### Questions About Fix
- [ ] Is it a code fix or logger addition?
- [ ] Where exactly should the fix go?
- [ ] What should the fix do?
- [ ] How can user verify the fix worked?

---

## Summary

**Universal Log Engine teaches you to**:

1. ✅ Identify log sources (Flexi, API, stack trace, network, console)
2. ✅ Normalize logs to standard format
3. ✅ Extract timestamps, levels, components, events
4. ✅ Recognize patterns (blank API, scope mismatch, nested structure, etc.)
5. ✅ Identify missing instrumentation (gaps in log = missing logger calls)
6. ✅ Build complete picture from incomplete logs

**You are done when**:
- You can classify the issue category
- You can identify the root cause
- You can recommend specific fix or logger placement
- Your analysis explains all the evidence in the log

---

**Next**: Read `timeline_engine.md` to learn how to reconstruct execution timelines from logs.
