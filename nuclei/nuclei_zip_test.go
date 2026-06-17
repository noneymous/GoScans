/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestUnzip verifies that unzip correctly extracts valid archives, rejects non-existent or malformed ZIP files,
// blocks path-traversal entries (zip slip prevention), and creates explicit directory entries from the archive.
func TestUnzip(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		setup   func(t *testing.T) (zipPath, destDir string)
		wantErr bool
	}{
		{
			name: "valid-zip-extracts-correctly",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "archive.zip")
				test_makeZip(t, zipPath, map[string]string{
					"hello.txt": "hello world",
					"sub/b.txt": "nested file",
				})
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: false,
		},
		{
			name: "non-existent-zip-returns-error",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				return filepath.Join(dir, "missing.zip"), filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "malformed-zip-returns-error",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "bad.zip")
				if errWrite := os.WriteFile(zipPath, []byte("this is not a zip"), 0600); errWrite != nil {
					t.Fatalf("unzip() setup error = '%v'", errWrite)
				}
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "zip-slip-prevention",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "slip.zip")
				test_makeZipWithTraversal(t, zipPath, "../evil.txt", "evil content")
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "zip-with-directory-entry-creates-dir",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "withdir.zip")
				destDir := filepath.Join(dir, "out")
				test_makeZipWithDir(t, zipPath, "mydir/", "mydir/file.txt", "inside")
				return zipPath, destDir
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare unit test data
			zipPath, destDir := tt.setup(t)

			// Execute and verify the expected error outcome
			if err := unzip(zipPath, destDir); (err != nil) != tt.wantErr {
				t.Errorf("unzip() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestScannerTargetAddr verifies that targetAddr returns "host:port" when a port is set on the scanner
// and just the host string when no port is configured.
func TestScannerTargetAddr(t *testing.T) {

	// Prepare and run test cases
	port443 := 443
	tests := []struct {
		name string
		scan Scanner
		want string
	}{
		{
			name: "with-port",
			scan: Scanner{target: "192.168.1.1", port: &port443},
			want: "192.168.1.1:443",
		},
		{
			name: "without-port",
			scan: Scanner{target: "192.168.1.1", port: nil},
			want: "192.168.1.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Execute and verify the returned address
			got := tt.scan.targetAddr()
			if got != tt.want {
				t.Errorf("targetAddr() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestScannerSetContext verifies that SetContext stores the provided context on the first call and ignores
// subsequent calls, preserving the originally set context.
func TestScannerSetContext(t *testing.T) {

	// Prepare unit test data
	scan := &Scanner{}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	// Verify the first call stores the context
	scan.SetContext(ctx1)
	if scan.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v'", scan.contextInner, ctx1)
	}

	// Verify a second call does not overwrite the stored context
	scan.SetContext(ctx2)
	if scan.contextInner != ctx1 {
		t.Errorf("SetContext() second call changed contextInner = '%v', want = '%v'", scan.contextInner, ctx1)
	}
}

// test_makeZip creates a ZIP archive at zipPath containing one entry per key-value pair in entries,
// where the key is the archive path and the value is the file content.
func test_makeZip(t *testing.T, zipPath string, entries map[string]string) {
	t.Helper()

	// Create the zip file on disk
	f, errCreate := os.Create(zipPath)
	if errCreate != nil {
		t.Fatalf("test_makeZip() could not create zip file: '%v'", errCreate)
	}
	defer func() { _ = f.Close() }()

	// Write each entry into the zip archive
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()
	for name, content := range entries {
		fw, errCreate := w.Create(name)
		if errCreate != nil {
			t.Fatalf("test_makeZip() could not create zip entry '%s': '%v'", name, errCreate)
		}
		if _, errWrite := io.WriteString(fw, content); errWrite != nil {
			t.Fatalf("test_makeZip() could not write zip entry '%s': '%v'", name, errWrite)
		}
	}
}

// test_makeZipWithDir creates a ZIP archive at zipPath containing an explicit directory entry and one file entry.
func test_makeZipWithDir(t *testing.T, zipPath, dirEntry, fileEntry, fileContent string) {
	t.Helper()

	// Create the zip file on disk
	f, errCreate := os.Create(zipPath)
	if errCreate != nil {
		t.Fatalf("test_makeZipWithDir() could not create zip file: '%v'", errCreate)
	}
	defer func() { _ = f.Close() }()

	// Write directory and file entries into the zip archive
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	// Add explicit directory entry
	hdr := &zip.FileHeader{Name: dirEntry, Method: zip.Store}
	hdr.SetMode(0700 | os.ModeDir)
	if _, errDir := w.CreateHeader(hdr); errDir != nil {
		t.Fatalf("test_makeZipWithDir() could not create dir entry: '%v'", errDir)
	}

	// Add file entry inside the directory
	fw, errFile := w.Create(fileEntry)
	if errFile != nil {
		t.Fatalf("test_makeZipWithDir() could not create file entry: '%v'", errFile)
	}
	if _, errWrite := io.WriteString(fw, fileContent); errWrite != nil {
		t.Fatalf("test_makeZipWithDir() could not write file entry: '%v'", errWrite)
	}
}

// test_makeZipWithTraversal creates a ZIP archive at zipPath containing a single entry with the given
// entryName (which may include path traversal sequences like "../") and content.
func test_makeZipWithTraversal(t *testing.T, zipPath, entryName, content string) {
	t.Helper()

	// Create the zip file on disk
	f, errCreate := os.Create(zipPath)
	if errCreate != nil {
		t.Fatalf("test_makeZipWithTraversal() could not create zip file: '%v'", errCreate)
	}
	defer func() { _ = f.Close() }()

	// Write the traversal entry directly via CreateHeader to preserve the raw name
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()
	hdr := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	fw, errHdr := w.CreateHeader(hdr)
	if errHdr != nil {
		t.Fatalf("test_makeZipWithTraversal() could not create header: '%v'", errHdr)
	}
	if _, errWrite := io.WriteString(fw, content); errWrite != nil {
		t.Fatalf("test_makeZipWithTraversal() could not write content: '%v'", errWrite)
	}
}
