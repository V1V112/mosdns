package cache

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestWriteFileAtomicallyReplacesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.dump")
	if err := os.WriteFile(path, []byte("old dump"), 0o600); err != nil {
		t.Fatal(err)
	}

	var tempPath string
	err := writeFileAtomically(path, func(f *os.File) error {
		tempPath = f.Name()
		if got := filepath.Clean(filepath.Dir(tempPath)); got != filepath.Clean(dir) {
			t.Fatalf("temporary file directory = %q, want %q", got, dir)
		}
		_, err := f.Write([]byte("new dump"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new dump" {
		t.Fatalf("destination contents = %q, want %q", got, "new dump")
	}
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file was not removed after replacement: %v", err)
	}
}

func TestWriteFileAtomicallyFailurePreservesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.dump")
	const oldDump = "known-good dump"
	if err := os.WriteFile(path, []byte(oldDump), 0o600); err != nil {
		t.Fatal(err)
	}

	writeErr := errors.New("injected serialization failure")
	var tempPath string
	err := writeFileAtomically(path, func(f *os.File) error {
		tempPath = f.Name()
		if _, err := f.Write([]byte("partial replacement")); err != nil {
			return err
		}
		return writeErr
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("write error = %v, want %v", err, writeErr)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != oldDump {
		t.Fatalf("failed replacement changed destination to %q", got)
	}
	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file was not removed after failure: %v", err)
	}
}

func TestDumpCacheAtomicReplacementRemainsV3Compatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.dump")
	c := newCacheForTest(t, &Args{Size: 16, DumpFile: path}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("atomic-dump.example.", dns.TypeA, dns.ClassINET, true)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.10", time.Hour)
	if !c.commitPrepared(testCacheKey(t, qCtx), nil, 0, prepared) {
		t.Fatal("failed to seed cache entry")
	}
	if err := os.WriteFile(path, []byte("previous dump"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := c.dumpCache(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := c.decodeDump(f)
	if err != nil {
		t.Fatalf("atomic dump is not v3-compatible: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("decoded entries = %d, want 1", len(entries))
	}
}

func TestFlushWithoutDumpFileDoesNotClaimPersistence(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	rr := httptest.NewRecorder()
	c.Api().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/flush", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("flush status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "Cache flushed.\n" {
		t.Fatalf("flush response = %q, want an in-memory-only result", got)
	}
	if strings.Contains(strings.ToLower(rr.Body.String()), "persist") {
		t.Fatalf("flush without dump_file claimed persistence: %q", rr.Body.String())
	}
}

func TestFlushAPIMethodCompatibility(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()
	router := c.Api()

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			qCtx := newTestQuery(strings.ToLower(method)+"-flush-method.example.", dns.TypeA, dns.ClassINET, true)
			prepared := testPreparedA(t, qCtx.Q(), "192.0.2.30", time.Hour)
			if !c.commitPrepared(testCacheKey(t, qCtx), nil, 0, prepared) {
				t.Fatal("failed to seed cache entry")
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, httptest.NewRequest(method, "/flush", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("flush status = %d, want %d", rr.Code, http.StatusOK)
			}
			if got := rr.Body.String(); got != "Cache flushed.\n" {
				t.Fatalf("flush response = %q", got)
			}

			deprecated := rr.Header().Get("Deprecated")
			warning := rr.Header().Get("Warning")
			if method == http.MethodGet {
				if deprecated != "true" {
					t.Fatalf("Deprecated header = %q, want true", deprecated)
				}
				if !strings.Contains(warning, "GET /flush is deprecated") {
					t.Fatalf("Warning header = %q", warning)
				}
			} else if deprecated != "" || warning != "" {
				t.Fatalf("%s response unexpectedly marked deprecated: Deprecated=%q Warning=%q", method, deprecated, warning)
			}
			if got := c.backend.Len(); got != 0 {
				t.Fatalf("cache size after %s flush = %d, want 0", method, got)
			}
		})
	}
}

func TestFlushAPIIsIdempotent(t *testing.T) {
	c := newCacheForTest(t, &Args{Size: 16}, Opts{})
	defer c.Close()

	qCtx := newTestQuery("flush-idempotent.example.", dns.TypeA, dns.ClassINET, true)
	prepared := testPreparedA(t, qCtx.Q(), "192.0.2.20", time.Hour)
	if !c.commitPrepared(testCacheKey(t, qCtx), nil, 0, prepared) {
		t.Fatal("failed to seed cache entry")
	}

	router := c.Api()
	var firstBody string
	for attempt := 0; attempt < 2; attempt++ {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/flush", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("flush attempt %d status = %d, want %d", attempt+1, rr.Code, http.StatusOK)
		}
		if attempt == 0 {
			firstBody = rr.Body.String()
		} else if got := rr.Body.String(); got != firstBody {
			t.Fatalf("second flush response = %q, want %q", got, firstBody)
		}
		if got := c.backend.Len(); got != 0 {
			t.Fatalf("cache size after flush attempt %d = %d, want 0", attempt+1, got)
		}
	}
}
