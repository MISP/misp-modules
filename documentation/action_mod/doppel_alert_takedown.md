# Doppel Alert and Takedown

Create an alert for an explicit URL or request takedown for an existing alert through the Doppel V1 API.

Configure `DOPPEL_API_KEY` on the module server. Optional `DOPPEL_USER_API_KEY` selects a user-specific identity, and `DOPPEL_ORGANIZATION_CODE` selects the organization for users belonging to several organizations. Credentials are not workflow parameters.

Set workflow `action` to `create_alert` and supply `entity`, an HTTP(S) URL. The provider returns an existing alert when the entity is already registered. A successful call can therefore return an existing alert ID.

For `request_takedown`, supply exactly one of `alert_id` and `entity`, with an optional `comment`. The module reads the alert before updating it. Alerts already in `actioned` or `taken_down` return their existing state. Other alerts receive `PUT /v1/alert` with `queue_state=actioned`, the provider's documented Request Takedown mapping. `actioned` means requested; completion is represented by `taken_down` and can only be confirmed by the provider. Concurrent workflow executions can still race between the read and update; provider queue policy rejects duplicate state transitions.

Provider queue policy may reject a request, including exhausted trial allowances, unsupported dark-web takedowns, or a missing rationale for potential false positives. Supply at least 15 non-whitespace characters in the comment for potential false positives. Errors report the HTTP status without copying provider bodies or keys. After a timeout, inspect Doppel before repeating the workflow. Calls verify TLS, reject redirects, use connection/read timeouts of 5/30 seconds, and are never automatically retried.

The result includes the alert ID, link, queue state and `request_performed` flag. An enrichment lookup does not invoke this action.

References:

- https://doppel.readme.io/docs/authentication
- https://doppel.readme.io/docs/request-takedown
