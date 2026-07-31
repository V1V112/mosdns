//go:build linux

package nft_add

import "testing"

func TestCleanupRoutingOnlyRemovesOwnedRules(t *testing.T) {
	var commands []string
	p := &NftAdd{runCmdFn: func(command string) {
		commands = append(commands, command)
	}}

	p.cleanupRouting()
	if len(commands) != 0 {
		t.Fatalf("cleanup without ownership ran %d commands", len(commands))
	}

	p.routingSetup.Store(true)
	p.cleanupRouting()
	if len(commands) != 10 {
		t.Fatalf("owned cleanup ran %d commands, want 10", len(commands))
	}

	p.cleanupRouting()
	if len(commands) != 10 {
		t.Fatalf("second cleanup ran commands again: %d total", len(commands))
	}
}
