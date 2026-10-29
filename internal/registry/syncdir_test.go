package registry

import (
	"path/filepath"
	"testing"
)

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on an existing directory: %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDir on a missing directory: want an error")
	}
}
