// Package fixture is the red Go fixture of paxel/gates: the planted finding is an unchecked
// error, which errcheck reports, so the Go gate must fail.
package fixture

import "os"

// Add adds two numbers and drops a file it never checks.
func Add(a, b int) int {
	os.Remove("gates-fixture")
	return a + b
}
