package sequence

import "testing"

func TestChainWalkerForkCopiesJumpBackCursors(t *testing.T) {
	root := ChainWalker{p: 1}
	parent := ChainWalker{p: 2, jumpBack: &root}
	walker := ChainWalker{p: 3, jumpBack: &parent}

	fork := walker.Fork()
	fork.p = 30
	fork.jumpBack.p = 20
	fork.jumpBack.jumpBack.p = 10

	if walker.p != 3 {
		t.Fatalf("original walker cursor changed: got %d, want 3", walker.p)
	}
	if walker.jumpBack.p != 2 {
		t.Fatalf("original parent cursor changed: got %d, want 2", walker.jumpBack.p)
	}
	if walker.jumpBack.jumpBack.p != 1 {
		t.Fatalf("original root cursor changed: got %d, want 1", walker.jumpBack.jumpBack.p)
	}
}
