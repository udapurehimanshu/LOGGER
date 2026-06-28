# API Engine

**How to systematically investigate REST API calls, HTTP responses, and web service failures.**

An API issue is not just an HTTP error. It's a mismatch between what code sent and what API returned, or between what API returned and what code expected.

---

## Core Principle

**API Investigation = Request Analysis + Response Analysis + Expectation Validation**

```
3 Parts of an API call:

1. REQUEST
   ├─ URL correct?
   ├─ Method correct (GET/POST/PUT)?
   ├─ Headers correct (Auth, Content-Type)?
   └─ Payload correct (query params, body)?

2. RESPONSE
   ├─ Status code (200/400/403/404/500)?
   ├─ Headers correct?
   ├─ Body parseable (valid JSON)?
   └─ Body structure as expected?

3. EXPECTATION
   ├─ Code expects which status code?
   ├─ Code expects which response structure?
   ├─ Code has fallback for errors?
   └─ Code validates response before using it?
```

---

## HTTP Status Code Classification

### 2xx Success Codes

#### 200 OK
- Request succeeded, response body contains result
- ✅ Normal case
- ❌ But check response body! (could be empty/null = blank API)

#### 201 Created
- Request succeeded, new resource created
- Usually POST requests
- Response typically includes new resource ID

#### 202 Accepted
- Request accepted but not yet processed
- Async operation
- Code should poll for status or check callback

#### 204 No Content
- Request succeeded but no response body
- Typical for DELETE operations
- Don't expect JSON response

### 3xx Redirect Codes

#### 301/302 Moved Permanently/Temporarily
- Resource moved to new URL
- Client should follow redirect
- If not auto-following: missing location header handling

#### 304 Not Modified
- Cache is valid, don't re-fetch
- Typical for GET requests with If-Modified-Since header

### 4xx Client Error Codes

#### 400 Bad Request
- Request is malformed (syntax error in payload)
- Missing required parameter
- Invalid parameter value

**Example**:
```
Request: POST /api/items
Body: { "itemCode": "", "orgId": "ABC" }
Response: 400 Bad Request
Error: "itemCode is required and cannot be empty"

Root Cause: Code didn't validate itemCode before sending
Fix: Add validation check before API call
```

#### 401 Unauthorized
- Authentication required (user not logged in)
- Token missing or expired
- API requires authorization header

**Example**:
```
Request: POST /api/items
Headers: [No Authorization header]
Response: 401 Unauthorized
Error: "Authentication required"

Root Cause: User session expired, token not sent
Fix: Re-login user, refresh token, resend request
```

#### 403 Forbidden
- User authenticated but not authorized (missing permission)
- Missing role or duty role
- Missing data role (e.g., OU access)

**Example**:
```
Request: POST /api/items
Headers: Authorization: Bearer token123
Response: 403 Forbidden
Error: "User doesn't have permission to create items"

Root Cause: User missing "Item Management Specialist" duty role
Fix: Assign required role to user in Oracle Identity
```

#### 404 Not Found
- Resource doesn't exist
- Wrong URL/endpoint
- API version changed

**Example**:
```
Request: GET /api/v1/items/ABC123
Response: 404 Not Found
Error: "Item ABC123 not found"

Root Cause 1: Item doesn't exist in system
Root Cause 2: Wrong endpoint (should be /api/v2/)
Root Cause 3: Typo in item code

Investigation: Check if item exists. Verify API version.
```

#### 405 Method Not Allowed
- Wrong HTTP method (GET instead of POST)
- API doesn't support that operation

**Example**:
```
Request: GET /api/items (should be POST)
Response: 405 Method Not Allowed
Error: "This endpoint only supports POST"

Root Cause: Code uses GET instead of POST
Fix: Change callWebService to use POST
```

#### 429 Too Many Requests
- Rate limit exceeded (too many requests too fast)
- Oracle Cloud enforces rate limits

**Example**:
```
Response: 429 Too Many Requests
Headers: Retry-After: 60

Root Cause: Code is making requests too fast
Fix: Add delay between requests or use bulk API
```

### 5xx Server Error Codes

#### 500 Internal Server Error
- Server error (Oracle backend error)
- Exception in server code
- Check Oracle logs

**Example**:
```
Request: POST /api/items
Response: 500 Internal Server Error
Error: "An unexpected error occurred"

Root Cause: Oracle threw exception (not user's fault)
Investigation: Check Oracle error logs, contact support
```

#### 502 Bad Gateway
- Gateway/proxy error
- Oracle Cloud network issue
- Temporary outage

**Example**:
```
Response: 502 Bad Gateway
Root Cause: Network between client and Oracle is broken
Fix: Retry request (might be temporary)
```

#### 503 Service Unavailable
- Server overloaded or down
- Maintenance window
- Cloud provider outage

**Example**:
```
Response: 503 Service Unavailable
Root Cause: Oracle Cloud infrastructure issue
Fix: Retry request later or check Oracle status page
```

#### 504 Gateway Timeout
- Server took too long to respond
- Network issue
- Query too slow

**Example**:
```
Response: 504 Gateway Timeout (after 30s)
Root Cause: Oracle query took >30s, request timed out
Investigation: Check Oracle Query Performance (APEX)
```

---

## Request Analysis

### Analyzing Request URL

```
Example URL:
GET /fscm/api/v1/items?orgId=123&itemCode=ABC123&limit=500

Parts:
├─ Protocol: GET (method)
├─ Path: /fscm/api/v1/items (endpoint)
├─ Query params:
│  ├─ orgId=123 (organization)
│  ├─ itemCode=ABC123 (search filter)
│  └─ limit=500 (max records)
```

**Questions to Ask**:

1. **Is the method correct?**
   ```
   - GET for retrieving data
   - POST for creating/updating data
   - PUT for updating existing
   - DELETE for removing
   - PATCH for partial update
   ```

2. **Is the path correct?**
   ```
   - Does API documentation match?
   - Is version correct (/v1/ vs /v2/)?
   - Is endpoint name spelled correctly?
   ```

3. **Are query parameters correct?**
   ```
   - Are required parameters present?
   - Are parameters spelled correctly?
   - Are parameter values valid?
   - Are parameter values in correct format?
   ```

**Example Bug**:
```
Code sends:
GET /items?limit=500

But API expects:
GET /items?limit=500&offset=0

Symptom: API returns first 500 items every time
Root Cause: No offset parameter, pagination doesn't work
Fix: Add offset parameter
```

### Analyzing Request Headers

```
Example headers:
Authorization: Bearer eyJhbGc...
Content-Type: application/json
Accept: application/json
X-Custom-Header: value
```

**Key Headers**:

1. **Authorization**
   ```
   - Bearer token: OAuth 2.0 (most common)
   - Basic auth: Base64 encoded username:password
   - API key: Custom header or query param
   
   Missing authorization header?
   → API returns 401 Unauthorized
   
   Expired token?
   → API returns 401 Unauthorized (need to refresh)
   
   Invalid token format?
   → API returns 401 Unauthorized
   ```

2. **Content-Type**
   ```
   - application/json: Sending/expecting JSON
   - application/x-www-form-urlencoded: Form data
   - multipart/form-data: File upload
   
   Wrong Content-Type?
   → API returns 400 Bad Request
   ```

3. **Accept**
   ```
   - Tells server what format you want back
   - Usually: Accept: application/json
   
   Server sends different format?
   → Code can't parse response
   ```

### Analyzing Request Payload

```
Example POST payload:
{
  "itemCode": "ABC123",
  "itemName": "Widget",
  "organizationId": 123,
  "isActive": true,
  "costCenter": null
}
```

**Questions**:

1. **Are all required fields present?**
   ```
   API expects: itemCode, itemName, organizationId
   Code sends: itemCode, itemName (missing organizationId!)
   Result: 400 Bad Request
   ```

2. **Are field values valid types?**
   ```
   API expects: organizationId (number)
   Code sends: organizationId: "123" (string)
   Result: Might work or might fail depending on API
   ```

3. **Are field values within constraints?**
   ```
   API expects: itemCode (max 50 chars)
   Code sends: itemCode (100 chars)
   Result: 400 Bad Request or silent truncation
   ```

4. **Are relationships valid?**
   ```
   API expects: If isActive=true, then costCenter must be set
   Code sends: isActive=true, costCenter=null
   Result: 400 Bad Request (validation error)
   ```

**Example Bug**:
```
Code sends:
{
  "filters": {
    "itemCode": "ABC123",
    "orgId": 123
  }
}

API expects:
{
  "itemCode": "ABC123",
  "organizationId": 123
}

Symptom: API returns 400 Bad Request
Root Cause: Wrong request structure (nested vs. flat)
Fix: Remove "filters" wrapper, flatten structure
```

---

## Response Analysis

### Analyzing Response Status Code

```
Status Code: 200 OK (success)

But ALSO check:
- Response body not empty?
- Response body valid JSON?
- Response body has expected fields?

Example: Blank API
Status: 200 OK
Body: { "items": [], "count": 0 }

Is this a success?
Technically yes (API returned 200).
But is business successful?
No (no items found).

Code must check response body, not just status code!
```

### Analyzing Response Headers

```
Response headers:
Content-Type: application/json
Content-Length: 1234
X-Rate-Limit-Remaining: 98
Retry-After: 60
```

**Useful headers**:

1. **Content-Type**
   ```
   - Tells what format body is in
   - Usually: application/json
   - If text/html? → Error page returned, not API response
   ```

2. **X-Rate-Limit-Remaining**
   ```
   - How many requests left before rate limit
   - If 0, next request returns 429 Too Many Requests
   ```

3. **Retry-After**
   ```
   - When to retry request (in seconds)
   - Typically with 429 or 503 responses
   ```

### Analyzing Response Body

**Step 1: Check if valid JSON**

```
Response body: { "items": [...] }  ✓ Valid JSON

Response body: <html><body>Error</body></html>  ✗ HTML, not JSON!
Interpretation: Error page returned, not API response
Cause: Endpoint wrong or authentication failed (returned login page)
```

**Step 2: Check if response structure matches expectations**

```
Code expects:
{
  "items": [
    { "id": 1, "name": "Widget" }
  ],
  "count": 1
}

API returns:
{
  "data": {
    "shipments": [
      { "shipmentLines": [...] }
    ]
  }
}

Mismatch! Code looks for "items" array, but API returned nested structure.

Investigation:
- Is API version correct?
- Is code looking at right part of response?
- Should code traverse nested structure?
```

**Step 3: Check for expected fields**

```
Code expects:
{
  "items": [
    { "id": 123, "name": "Widget", "price": 9.99 }
  ]
}

API returns:
{
  "items": [
    { "id": 123, "name": "Widget" }  // Missing "price" field!
  ]
}

Code accesses items[0].price → undefined
Then tries to use price in calculation → NaN or error
```

**Step 4: Check for null/empty values**

```
API returns:
{
  "items": [],              // Empty array
  "count": 0,               // Count is 0
  "result": null,           // Null result
  "status": "success"       // But status says success!
}

Interpretation: Blank API
- HTTP 200 = API worked
- items=[] = No records found
- status="success" = Query executed successfully
- But business impact: No data to display

This is NOT an API failure. It's a business failure (no matching records).
```

---

## Common API Failure Patterns

### Pattern 1: Blank API (HTTP 200 + 0 Records)

**Log signature**:
```
Response Code: 200
Response Body: { "items": [], "count": 0, "status": "success" }
```

**Interpretation**: API succeeded but returned no data.

**Root causes**:
1. User doesn't have permission (but Oracle returned 200, not 403)
2. Query filter too restrictive (wrong parameters)
3. Data doesn't exist in system
4. Data was recently deleted/purged

**Investigation**:
- Add logger.trace() for query parameters sent
- Ask user: What data are you searching for?
- Check Oracle: Does matching data exist?

**Fix**:
```javascript
// Before:
callWebService("GetItems", payload);

// After:
callWebService("GetItems", payload);
if (response.getResponseCode() == 200) {
  var json = parseJSON(response.getResponseBody());
  if (json.items && json.items.length > 0) {
    // Process items
  } else {
    // Handle blank API
    logger.warn("No items found for criteria: " + JSON.stringify(payload));
    setStatusMessage("No Data", "No items matching your search criteria");
  }
}
```

### Pattern 2: Unexpected Response Structure

**Log signature**:
```
Response Code: 200
Response Body: { "shipments": [{ "shipmentLines": [...] }] }
Code expects: { "items": [...] }
Exception: items is undefined
```

**Root cause**: API returns nested structure, code expects flat.

**Investigation**:
- Add logger.trace() for raw response
- Compare with API documentation
- Check if API version changed

**Fix**: Update code to handle nested structure:
```javascript
// Before:
var items = response.items;

// After:
var items = response.shipments[0].shipmentLines;
// or
var items = response.items || response.shipments[0].shipmentLines;
```

### Pattern 3: Missing Authorization

**Log signature**:
```
Response Code: 403 Forbidden
Error Message: "Access Denied"
or
Response Code: 401 Unauthorized
Error Message: "Authentication required"
```

**Root causes**:
1. User missing duty role (e.g., "Item Management Specialist")
2. User missing job role (e.g., "Procurement Manager")
3. User missing data role (e.g., OU-001)
4. Token expired

**Investigation**:
- Ask user: What roles are you assigned?
- Check Oracle Cloud docs for endpoint role requirements
- Verify token/session is valid

**Fix**:
```javascript
// Before:
callWebService("GetItems", payload);

// After:
callWebService("GetItems", payload);
if (response.getResponseCode() == 403) {
  setStatusMessage("Access Denied", 
    "You don't have permission to access this data. " +
    "Contact your administrator to request access.");
  logger.error("Authorization failed: User missing required role");
  return;
}
```

### Pattern 4: Malformed Request

**Log signature**:
```
Response Code: 400 Bad Request
Error Message: "itemCode is required"
or
Error Message: "Invalid JSON in request body"
```

**Root cause**: Request is incorrect (missing field, wrong format, invalid value).

**Investigation**:
- Add logger.trace() for request payload
- Compare with API documentation
- Validate request before sending

**Fix**:
```javascript
// Before:
var payload = { itemCode: userInput };
callWebService("GetItems", payload);

// After:
if (!userInput || userInput.trim() == "") {
  setStatusMessage("Validation Error", "Please enter an item code");
  return;
}
var payload = { itemCode: userInput.toUpperCase() };
logger.trace("Sending request: " + JSON.stringify(payload));
callWebService("GetItems", payload);
```

### Pattern 5: Slow or Timeout

**Log signature**:
```
[T1] API call started: 08:34:52.100
[T2] API response: 08:35:12.100 (20 seconds later!)
or
Error: Timeout after 30 seconds
```

**Root cause**: Oracle query is slow, network is slow, or Oracle Cloud is down.

**Investigation**:
- Ask for: How many records expected to return?
- Check: Oracle Query Performance (APEX) for slow SQL
- Check: Oracle Cloud status page for outages
- Check: Network latency

**Fix**:
```javascript
// Before:
callWebService("GetItems", { orgId: 123 });

// After:
// Add timeout and retry logic
var maxRetries = 3;
var retryCount = 0;

function callWithRetry() {
  logger.trace("Calling GetItems API (attempt " + (retryCount + 1) + ")");
  callWebService("GetItems", { orgId: 123, limit: 500 }, 
    function(response) {
      if (response.getResponseCode() == 200) {
        handleSuccess(response);
      } else if (response.getResponseCode() == 504) { // Timeout
        if (retryCount < maxRetries) {
          retryCount++;
          setTimeout(callWithRetry, 5000); // Retry after 5s
        } else {
          setStatusMessage("Timeout", "Request took too long. Please try again.");
        }
      }
    }
  );
}
callWithRetry();
```

---

## API Investigation Checklist

When API call fails, ask:

### For 2xx (Success) Responses
- [ ] Response code is 200-204?
- [ ] Response body is valid JSON?
- [ ] Response body matches expected structure?
- [ ] Expected fields present in response?
- [ ] Array fields not empty?
- [ ] Handling blank API (items=[])?

### For 4xx (Client Error) Responses
- [ ] Is request URL correct?
- [ ] Is HTTP method correct?
- [ ] Are required headers present?
- [ ] Is request payload valid JSON?
- [ ] Are required fields in payload?
- [ ] Is authentication header present?
- [ ] Is token/session expired?

### For 5xx (Server Error) Responses
- [ ] Is Oracle Cloud up? (check status page)
- [ ] Is endpoint correct?
- [ ] Is request valid (might still be user's fault)?
- [ ] Should code retry? (503 yes, 500 maybe)

### For Timeouts
- [ ] How long did request take?
- [ ] Is that longer than timeout configured?
- [ ] Is Oracle query slow?
- [ ] Is network slow?
- [ ] Is Oracle Cloud overloaded?

---

## Recommended API Logger Placements

```javascript
// 1. Log request being sent
logger.trace("API Call: " + serviceName);
logger.trace("Request Method: " + method);
logger.trace("Request URL: " + url);
logger.trace("Request Headers: " + JSON.stringify(headers));
logger.trace("Request Payload: " + JSON.stringify(payload));

// 2. Log response received
callWebService(serviceName, payload, function(response) {
  logger.trace("API Response Code: " + response.getResponseCode());
  logger.trace("Response Headers: " + JSON.stringify(response.getHeaders()));
  logger.trace("Raw Response Body: " + response.getResponseBody());
  
  // 3. Log parsing
  try {
    var json = parseJSON(response.getResponseBody());
    logger.trace("Parsed Response: " + JSON.stringify(json));
  } catch (e) {
    logger.error("JSON Parsing Error: " + e.message);
    logger.error("Raw body was: " + response.getResponseBody());
    return;
  }
  
  // 4. Log extraction
  var items = json.items;
  logger.trace("Items extracted: " + (items ? items.length : "null"));
  
  // 5. Log validation
  if (response.getResponseCode() == 200) {
    if (items && items.length > 0) {
      logger.trace("Validation: PASS (found " + items.length + " items)");
    } else {
      logger.warn("Validation: Blank API (0 items found)");
      setStatusMessage("No Data", "No records matching your criteria");
      return;
    }
  } else {
    logger.error("API Error: " + response.getResponseCode());
    setStatusMessage("Error", "API call failed: " + response.getResponseCode());
    return;
  }
  
  // 6. Log usage
  logger.trace("Using items for: [what you're doing]");
});

// 7. Log error handling
function onError(error) {
  logger.error("API Call Failed: " + serviceName);
  logger.error("Error: " + error.message);
  logger.error("Details: " + JSON.stringify(error));
  setStatusMessage("Error", "Failed to load data: " + error.message);
}
```

---

## Summary

**API Engine teaches you to**:

1. ✅ Classify HTTP status codes
2. ✅ Analyze request correctness (URL, method, headers, payload)
3. ✅ Analyze response structure
4. ✅ Identify blank APIs (200 + 0 records)
5. ✅ Identify scope mismatches (unexpected response structure)
6. ✅ Identify authorization failures
7. ✅ Identify performance issues
8. ✅ Recommend specific logger placements
9. ✅ Recommend specific fixes

**You are done when**:
- You can classify API failure by status code and response
- You can identify root cause (request, response, or expectation mismatch)
- You can recommend specific fix or logger placement
- You understand why blank API is a business issue, not API issue

---

**Next**: Proceed to Phase 2 for language-specific debugging engines (Java, Groovy, JavaScript, etc.).

**Or**: For immediate Flexi-specific knowledge, see `knowledge/flexi_engine.md`.
