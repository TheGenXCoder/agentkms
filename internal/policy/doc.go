// Package policy implements the AgentKMS policy engine.
//
// Every operation is evaluated against policy before it reaches the Backend.
// The engine is deny-by-default: an empty policy denies ALL operations.
// Policy dimensions: identity, key scope, operation type, rate, time window.
//
// Backlog: P-01 to P-08.
package policy
