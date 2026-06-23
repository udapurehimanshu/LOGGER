// ─── LogRadar:AI Log Investigator – Generic Sample Logs ─────────────────────────────
// All samples are technology-agnostic and PII-free.
// Usernames → SVC_USER_01 / APP_USER_02 etc.
// IPs → [REDACTED_IP]
// Internal URLs → https://api.internal/...
// Customer/Order IDs → [REDACTED_ID]
const SAMPLE_LOGS = {

  auth_403: {
    name: "API Auth Failure (HTTP 403)",
    description: "REST API call rejected with 403 Forbidden — user lacks required access privilege",
    content:
`[TRACE] 2026-06-21 08:15:15.650 [SVC_USER_01(71)-[Thread-137]] IntegrationClient - IntegrationClient.callWebService:name:INSPECTION_PLAN_API
[TRACE] 2026-06-21 08:15:15.651 [SVC_USER_01(71)-[Thread-137]] IntegrationClient - IntegrationClient.runWebService:ID=INSPECTION_PLAN_API
[TRACE] 2026-06-21 08:15:15.652 [SVC_USER_01(71)-[Thread-137]] RestClient - RestClient. Request Method = GET
[TRACE] 2026-06-21 08:15:15.653 [SVC_USER_01(71)-[Thread-137]] RestClient - RestClient. URL = https://api.internal/v1/resources/inspectionPlans?itemId=[REDACTED_ID]&status=APPROVED
[TRACE] 2026-06-21 08:15:15.927 [SVC_USER_01(71)-[Thread-137]] RestClient - RestClient.Response Code = 403, Content-Type = application/json
[TRACE] 2026-06-21 08:15:15.927 [SVC_USER_01(71)-[Thread-137]] IntegrationClient - IntegrationClient.runWebService:finish INSPECTION_PLAN_API
[TRACE] 2026-06-21 08:15:15.927 [SVC_USER_01(71)-[Thread-137]] IntegrationClient - IntegrationClient.runWebService: Total time = 268 ms
[ERROR] 2026-06-21 08:15:15.929 [SVC_USER_01(71)-[Thread-137]] ScriptExecutor - Script execution context: com.app.integration.ScriptEngine
org.json.JSONException: A JSONObject text must begin with '{' at 1 [character 2 line 1]
	at org.json.JSONTokener.syntaxError(JSONTokener.java:433)
	at org.json.JSONObject.<init>(JSONObject.java:197)
	at org.json.JSONObject.<init>(JSONObject.java:324)
[ERROR] 2026-06-21 08:15:15.929 [SVC_USER_01(71)-[Thread-137]] ScriptExecutor - Script engine error: bsh.TargetError: inline evaluation of: \`\` JSONObject result = new JSONObject(INSPECTION_PLAN_API.getRawResponse()); JSON . . . \`\` : Typed variable declaration : Object constructor
	at bsh.BSHAllocationExpression.constructObject(Unknown Source)
[TRACE] 2026-06-21 08:15:16.142 [SVC_USER_01(71)-[Thread-137]] AppRuntime - AppRuntime.handleInputData:render page TRANSACTION_COMPLETE, status: A JSONObject text must begin with '{' at 1 [character 2 line 1]. Check log for more details`
  },

  api_timeout: {
    name: "API Timeout & 404 Not Found",
    description: "HTTP client timed out after 5234ms — endpoint not found (404)",
    content:
`2026-06-21 11:15:30.220 [http-thread-exec-1] INFO  app.client.HttpClient - Initiating API call: ITEM_SERVICE
2026-06-21 11:15:30.225 [http-thread-exec-1] DEBUG app.client.HttpClient - URL = https://api.internal/v2/items
2026-06-21 11:15:30.230 [http-thread-exec-1] DEBUG app.client.HttpClient - Request Payload: {"orgCode":"ORG_01","itemCode":"[REDACTED_ID]"}
2026-06-21 11:15:30.231 [http-thread-exec-1] INFO  app.client.HttpClient - ITEM_SERVICE.callWebService() started
2026-06-21 11:15:35.464 [http-thread-exec-1] WARN  app.client.HttpClient - Long hold time detected. Approaching timeout threshold (5000ms).
2026-06-21 11:15:35.465 [http-thread-exec-1] ERROR app.client.HttpClient - ITEM_SERVICE.callWebService() : 5234 ms
2026-06-21 11:15:35.466 [http-thread-exec-1] ERROR app.client.HttpClient - HTTP Response Code : 404
2026-06-21 11:15:35.467 [http-thread-exec-1] DEBUG app.client.HttpClient - Response Body: {"status":404,"message":"Resource not found — endpoint version mismatch"}
2026-06-21 11:15:35.470 [http-thread-exec-1] ERROR app.runtime.Engine - Script stopped due to service failure. Transaction: Item Lookup. User: APP_USER_02`
  },

  db_constraint: {
    name: "Database Constraint Violation",
    description: "SQL ORA-00904 invalid column identifier in onhand query",
    content:
`2026-06-21 11:20:40.002 [main] INFO  app.db.Connection - Fetching connection pool for org: ORG_PROD_01
2026-06-21 11:20:40.005 [main] DEBUG app.db.QueryEngine - executeQuery started
2026-06-21 11:20:40.008 [main] DEBUG app.db.QueryEngine - SQL: SELECT ITEM_ID, ONHAND_QTY, LPN_REF FROM INV_ONHAND_STATUS_V WHERE ORG_ID = ? AND LOCATION_CODE = ?
2026-06-21 11:20:40.010 [main] DEBUG app.db.QueryEngine - Parameters: ORG_ID=ORG_PROD_01, LOCATION_CODE=ZONE_A
2026-06-21 11:20:40.035 [main] ERROR app.db.QueryEngine - executeQuery failed
java.sql.SQLException: ORA-00904: "LPN_REF": invalid identifier
	at oracle.jdbc.driver.T4CTTIoer11.processError(T4CTTIoer11.java:494)
	at oracle.jdbc.driver.T4C8Oall.processError(T4C8Oall.java:1107)
	at oracle.jdbc.driver.T4CPreparedStatement.executeQuery(T4CPreparedStatement.java:1614)
	at app.db.QueryExecutor.runSelect(QueryExecutor.java:88)
2026-06-21 11:20:40.038 [main] ERROR app.runtime.Engine - DB query failed. Module: Inventory. User: SVC_USER_DB`
  },

  json_schema: {
    name: "JSON Schema Mismatch",
    description: "JSONException: 'items' key not found — downstream API response schema changed",
    content:
`2026-06-21 11:22:15.110 [http-thread-exec-4] INFO  app.integration.Receiver - Callback received for correlation-id: [REDACTED_ID]
2026-06-21 11:22:15.115 [http-thread-exec-4] DEBUG app.integration.Receiver - Raw Response: {"requestId":"[REDACTED_ID]","receipts":[{"lineNum":1,"quantity":50}]}
2026-06-21 11:22:15.118 [http-thread-exec-4] INFO  app.integration.Receiver - Parsing response for module: Inbound Integration
2026-06-21 11:22:15.122 [http-thread-exec-4] ERROR app.integration.Receiver - JSON parsing failed
org.json.JSONException: JSONObject["items"] not found.
	at org.json.JSONObject.get(JSONObject.java:471)
	at org.json.JSONObject.getJSONArray(JSONObject.java:640)
	at app.integration.ReceiptService.parseResponse(ReceiptService.java:34)
	at app.integration.Receiver.processCallback(Receiver.java:80)
2026-06-21 11:22:15.124 [http-thread-exec-4] ERROR app.integration.Receiver - Integration callback processing failed. Correlation: [REDACTED_ID]. User: SVC_INTEGRATION_01`
  },

  null_pointer: {
    name: "Null Reference Script Crash",
    description: "TargetError at Line 15 — variable is null before method call",
    content:
`2026-06-21 10:15:01.002 [main] INFO  app.runtime.Engine - Session started. User: APP_USER_03, Org: ORG_01, Screen: TASK_SCREEN_11
2026-06-21 10:15:01.105 [main] INFO  app.runtime.Engine - Loading script: FIELD_VALIDATION for transaction: Stock Adjustment
2026-06-21 10:15:01.120 [main] DEBUG app.runtime.Session - Variables bound: ORG=ORG_01, ITEM=[REDACTED_ID], LOCATION=ZONE_A
2026-06-21 10:15:01.125 [main] WARN  app.runtime.Session - SUBINV field was skipped by user. Value is null.
2026-06-21 10:15:01.130 [main] INFO  app.runtime.Engine - Beginning inline evaluation of FIELD_VALIDATION
2026-06-21 10:15:01.144 [main] DEBUG app.runtime.Engine - Line 12: String org = ORG.getValue(); => ORG_01
2026-06-21 10:15:01.145 [main] DEBUG app.runtime.Engine - Line 13: String item = ITEM.getValue(); => [REDACTED_ID]
2026-06-21 10:15:01.146 [main] ERROR app.runtime.Executor - Script execution failed: FIELD_VALIDATION
app.runtime.TargetError: Cannot invoke method getValue() on null object : at Line: 15
	at FIELD_VALIDATION.inline evaluation.method(FIELD_VALIDATION:15)
	at app.runtime.Executor.evaluate(Executor.java:142)
	at app.runtime.Engine.validateFields(Engine.java:82)
2026-06-21 10:15:01.148 [main] ERROR app.runtime.Engine - Transaction aborted. User: APP_USER_03. Transaction: Stock Adjustment`
  },

  validation: {
    name: "Input Validation Failure",
    description: "ValidationException — negative quantity and invalid item reference",
    content:
`2026-06-21 11:45:00.100 [main] INFO  app.runtime.Engine - Session started. User: APP_USER_04, Org: ORG_01, Screen: RECEIPT_SCREEN_04
2026-06-21 11:45:00.105 [main] DEBUG app.runtime.Engine - Input parameters bound: ITEM=[REDACTED_ID]_INVALID, LOT=LOT_REF_9988, QTY=-10
2026-06-21 11:45:00.110 [main] ERROR app.runtime.Validator - Validation failed for transaction: Goods Receipt
app.runtime.ValidationException: Field Validation Error:
- ITEM ([REDACTED_ID]_INVALID) does not exist in Item Master
- TRANSACTION QTY (-10) cannot be negative or zero
	at app.runtime.Validator.validateFields(Validator.java:144)
	at app.runtime.Engine.processTransaction(Engine.java:95)
2026-06-21 11:45:00.115 [main] ERROR app.runtime.Engine - Validation failed. Goods Receipt aborted. User: APP_USER_04`
  },

  service_down: {
    name: "Downstream Service Unavailable (503)",
    description: "External service returned HTTP 503 — maintenance window or outage",
    content:
`2026-06-21 11:40:05.120 [http-thread-exec-5] INFO  app.client.HttpClient - Initiating integration call: CREATE_RECORD_API
2026-06-21 11:40:05.125 [http-thread-exec-5] DEBUG app.client.HttpClient - URL = https://api.internal/v1/records
2026-06-21 11:40:07.450 [http-thread-exec-5] WARN  app.client.HttpClient - Downstream server returned Gateway Timeout or Service Unavailable.
2026-06-21 11:40:07.452 [http-thread-exec-5] ERROR app.client.HttpClient - Service unavailable. CREATE_RECORD_API.callWebService() : 2320 ms
2026-06-21 11:40:07.453 [http-thread-exec-5] ERROR app.client.HttpClient - HTTP Response Code : 503
2026-06-21 11:40:07.454 [http-thread-exec-5] DEBUG app.client.HttpClient - Response Body: {"status":503,"message":"Service Unavailable - Maintenance in progress. Retry after 15 minutes."}
2026-06-21 11:40:07.455 [http-thread-exec-5] ERROR app.runtime.Engine - Downstream integration failed. Transaction: Record Sync. User: SVC_USER_05`
  },

  perf_slow: {
    name: "Performance Degradation (Slow Query + API)",
    description: "Compound performance issue — slow DB query causing API chain delay",
    content:
`2026-06-21 14:05:10.001 [http-thread-exec-7] INFO  app.runtime.Engine - Processing request. User: APP_USER_06. Transaction: Report Generation
2026-06-21 14:05:10.005 [http-thread-exec-7] INFO  app.client.HttpClient - Initiating API call: REPORT_DATA_API
2026-06-21 14:05:10.010 [http-thread-exec-7] DEBUG app.client.HttpClient - URL = https://api.internal/v1/reports/summary
2026-06-21 14:05:10.015 [http-thread-exec-7] DEBUG app.client.HttpClient - Request Payload: {"orgId":"[REDACTED_ID]","dateRange":"LAST_30_DAYS"}
2026-06-21 14:05:10.016 [http-thread-exec-7] INFO  app.client.HttpClient - REPORT_DATA_API.callWebService() started
2026-06-21 14:05:16.820 [http-thread-exec-7] WARN  app.client.HttpClient - Long hold time detected (6800ms). Threshold exceeded.
2026-06-21 14:05:16.821 [http-thread-exec-7] ERROR app.client.HttpClient - REPORT_DATA_API.callWebService() : 6811 ms
2026-06-21 14:05:16.822 [http-thread-exec-7] ERROR app.client.HttpClient - HTTP Response Code : 200
2026-06-21 14:05:16.823 [http-thread-exec-7] DEBUG app.db.QueryEngine - executeQuery started (triggered by API response processing)
2026-06-21 14:05:16.830 [http-thread-exec-7] DEBUG app.db.QueryEngine - SQL: SELECT r.*, d.description FROM REPORT_SUMMARY r JOIN DEPARTMENT_DATA d ON r.dept_id = d.id WHERE r.org_id = ? AND r.created_date >= ?
2026-06-21 14:05:16.832 [http-thread-exec-7] DEBUG app.db.QueryEngine - Parameters: org_id=[REDACTED_ID], created_date=2026-05-22
2026-06-21 14:05:21.140 [http-thread-exec-7] WARN  app.db.QueryEngine - Query execution time: 4308ms — exceeds slow query threshold (2000ms)
2026-06-21 14:05:21.141 [http-thread-exec-7] DEBUG app.db.QueryEngine - Rows returned: 15420
2026-06-21 14:05:21.142 [http-thread-exec-7] INFO  app.runtime.Engine - Report generation completed. Total processing time: 11132ms. User: APP_USER_06`
  },

};
