// export_test.go exposes internal state for white-box testing.
// This file is compiled only during tests (package github, not github_test).
package github

// SetTestBaseURL overrides the GitHub API base URL for the named App's client.
// It is only available in test binaries; it does not exist in the production binary.
func (p *Plugin) SetTestBaseURL(appName, baseURL string) {
	p.mu.RLock()
	c, ok := p.apps[appName]
	p.mu.RUnlock()
	if !ok {
		return
	}
	c.mu.Lock()
	c.baseURL = baseURL
	c.mu.Unlock()
}
