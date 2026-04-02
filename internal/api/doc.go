// Package api implements the AgentKMS HTTP API handlers.
//
// Handlers: /sign, /encrypt, /decrypt, /keys, /credentials, /auth.
// Every handler must: validate the session token, evaluate policy,
// call the Backend interface (never a concrete backend directly),
// write an AuditEvent, and return only the minimal response.
//
// Backlog: C-01 to C-07.
package api
