# Issue #830: Secure API Gateway with Dynamic Policy Enforcement

## Implemented Components

- Global API gateway middleware at `/api/*`
- Dynamic policy service with hot reload from `config/apiGatewayPolicies.json`
- Policy-based enforcement for:
  - JWT and OAuth2 token validation
  - Route-specific rate limiting
  - Request validation (content type + required fields)
  - Real-time SQL injection / XSS / NoSQL injection threat detection
- Centralized gateway request/security logging
- Admin API endpoints for runtime policy management

## Files Added

- `config/apiGatewayPolicies.json`
- `services/apiGatewayPolicyService.js`
- `middleware/apiGateway.js`
- `routes/apiGateway.js`

## Files Updated

- `server.js`

## Runtime Gateway Endpoints

- `GET /api/gateway/policies` (admin)
- `PUT /api/gateway/policies` (admin)

## Dynamic Policy Updates

Policies are loaded from `config/apiGatewayPolicies.json` and reloaded automatically when the file changes.

Runtime updates are also supported via `PUT /api/gateway/policies`.

## JWT / OAuth2 Integration

- JWT uses `JWT_SECRET`
- OAuth2 token verification supports:
  - `OAUTH2_JWT_PUBLIC_KEY` (RS256/RS384/RS512)
  - or `OAUTH2_JWT_SECRET` (HS256/HS384/HS512)
- Optional claim constraints:
  - `OAUTH2_AUDIENCE`
  - `OAUTH2_ISSUER`

## Security Outcomes

- Unauthorized requests are blocked at gateway level before reaching microservice handlers
- High-risk payloads are detected and blocked/logged by policy
- Request abuse is constrained by policy-driven throttling
- All gateway decisions are logged in centralized structured logs

## High Availability / Scalability Notes

- Gateway remains stateless for auth and policy evaluation
- Policy updates do not require service restart
- Rate-limit storage is in-memory for this implementation; distributed storage can be added for multi-instance deployments
