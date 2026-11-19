package geodata

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Two node instances starting together share geo_data_dir. A fixed temp name
// let their writes interleave into one file, and ensureFile never re-downloads
// a non-empty (corrupt) database. The final file must be one complete body.
func TestAtomicDownloadConcurrentWritersProduceOneCompleteFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")
	bodyA := bytes.Repeat([]byte{'A'}, minGeoFileSize+16)
	bodyB := bytes.Repeat([]byte{'B'}, minGeoFileSize+32)

	serve := func(body []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
	}
	srvA := serve(bodyA)
	defer srvA.Close()
	srvB := serve(bodyB)
	defer srvB.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, url := range []string{srvA.URL, srvB.URL} {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			errs <- atomicDownload(dst, url)
		}(url)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("download: %v", err)
		}
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bodyA) && !bytes.Equal(got, bodyB) {
		t.Fatalf("file is interleaved or truncated: %d bytes", len(got))
	}
	leftovers, err := filepath.Glob(dst + ".tmp.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}
