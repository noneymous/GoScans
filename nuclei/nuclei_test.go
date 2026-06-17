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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the nuclei package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmp := os.MkdirTemp(".", "goscans-nuclei-test-*")
	if errTmp != nil {
		panic(errTmp)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}

// TestNewScanner verifies that NewScanner returns an error for invalid template paths and no error for valid configurations.
func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNucleiTemplates == "" {
		t.Skip("Integration test skipped: PathNucleiTemplates not configured in _test/settings.go")
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		target        string
		pathTemplates string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid",
			args:    args{target: "127.0.0.1", pathTemplates: testSettings.PathNucleiTemplates},
			wantErr: false,
		},
		{
			name:    "invalid-templates-notexisting",
			args:    args{target: "127.0.0.1", pathTemplates: "notexisting"},
			wantErr: true,
		},
		{
			name:    "invalid-templates-empty",
			args:    args{target: "127.0.0.1", pathTemplates: ""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(testLogger, tt.args.target, nil, tt.args.pathTemplates, "", "", nil, nil, nil, nil, "", "", "", "", "")
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestMoveDirSafe verifies that moveDirSafe correctly moves files and directories, and errors on missing sources.
func TestMoveDirSafe(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		setup   func(t *testing.T) (src, dst string)
		wantErr bool
	}{
		{
			name: "move-file",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				src := filepath.Join(dir, "file.txt")
				if errWrite := os.WriteFile(src, []byte("content"), 0o644); errWrite != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errWrite)
				}
				return src, filepath.Join(dir, "moved.txt")
			},
			wantErr: false,
		},
		{
			name: "move-directory",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				src := filepath.Join(dir, "srcdir")
				if errMkdir := os.MkdirAll(filepath.Join(src, "sub"), 0o755); errMkdir != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errMkdir)
				}
				if errWrite := os.WriteFile(filepath.Join(src, "sub", "a.txt"), []byte("hi"), 0o644); errWrite != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errWrite)
				}
				return src, filepath.Join(dir, "dstdir")
			},
			wantErr: false,
		},
		{
			name: "src-not-exist",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent"), filepath.Join(dir, "dst")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup(t)

			// Execute and check for expected error
			if err := moveDirSafe(src, dst); (err != nil) != tt.wantErr {
				t.Errorf("moveDirSafe() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}

			// Verify source was removed after a successful move
			if !tt.wantErr {
				if _, errSrc := os.Stat(src); !os.IsNotExist(errSrc) {
					t.Errorf("moveDirSafe() source still exists after successful move")
				}
			}
		})
	}
}

// TestSanitizeTemplateIds verifies that sanitizeTemplateIds expands base IDs to include port-split file variants.
func TestSanitizeTemplateIds(t *testing.T) {

	// Prepare a temp directory containing split variant YAML files
	templatesDir := t.TempDir()
	for _, name := range []string{"ssl-heartbleed_443.yaml", "http-redirect_8080.yaml", "unrelated.yaml"} {
		if errWrite := os.WriteFile(filepath.Join(templatesDir, name), []byte(""), 0o644); errWrite != nil {
			t.Fatalf("TestSanitizeTemplateIds setup error = '%v'", errWrite)
		}
	}

	// Prepare and run test cases
	tests := []struct {
		name         string
		includeIds   []string
		excludeIds   []string
		wantIncludes []string
		wantExcludes []string
		wantErr      bool
	}{
		{
			name:         "both-empty-no-walk",
			includeIds:   nil,
			excludeIds:   nil,
			wantIncludes: nil,
			wantExcludes: nil,
			wantErr:      false,
		},
		{
			name:         "base-id-in-include-adds-variant",
			includeIds:   []string{"ssl-heartbleed"},
			excludeIds:   nil,
			wantIncludes: []string{"ssl-heartbleed", "ssl-heartbleed_443"},
			wantExcludes: nil,
			wantErr:      false,
		},
		{
			name:         "base-id-in-exclude-adds-variant",
			includeIds:   nil,
			excludeIds:   []string{"http-redirect"},
			wantIncludes: nil,
			wantExcludes: []string{"http-redirect", "http-redirect_8080"},
			wantErr:      false,
		},
		{
			name:         "unmatched-base-id-unchanged",
			includeIds:   []string{"not-in-templates"},
			excludeIds:   nil,
			wantIncludes: []string{"not-in-templates"},
			wantExcludes: nil,
			wantErr:      false,
		},
		{
			name:         "single-part-filename-not-treated-as-variant",
			includeIds:   []string{"unrelated"},
			excludeIds:   nil,
			wantIncludes: []string{"unrelated"},
			wantExcludes: nil,
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIncludes, gotExcludes, err := sanitizeTemplateIds(templatesDir, tt.includeIds, tt.excludeIds)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeTemplateIds() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
			if !testStringslicesmatch(gotIncludes, tt.wantIncludes) {
				t.Errorf("sanitizeTemplateIds() includes = '%v', want = '%v'", gotIncludes, tt.wantIncludes)
			}
			if !testStringslicesmatch(gotExcludes, tt.wantExcludes) {
				t.Errorf("sanitizeTemplateIds() excludes = '%v', want = '%v'", gotExcludes, tt.wantExcludes)
			}
		})
	}
}

// TestFilterIntersection verifies that filterIntersection returns the correct intersection of two CSV strings.
func TestFilterIntersection(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		existing string
		enforced string
		want     string
	}{
		{
			name:     "empty-existing-returns-enforced",
			existing: "",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "both-empty",
			existing: "",
			enforced: "",
			want:     "",
		},
		{
			name:     "no-overlap",
			existing: "http,tcp",
			enforced: "dns,whois",
			want:     "",
		},
		{
			name:     "single-overlap",
			existing: "dns,http,tcp",
			enforced: "dns,whois",
			want:     "dns",
		},
		{
			name:     "full-overlap",
			existing: "dns,whois",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "spaces-in-csv-trimmed",
			existing: "dns, http",
			enforced: "dns",
			want:     "dns",
		},
		{
			name:     "duplicate-in-existing-deduped",
			existing: "dns,dns",
			enforced: "dns",
			want:     "dns",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterIntersection(tt.existing, tt.enforced)
			if testSortedcsv(got) != testSortedcsv(tt.want) {
				t.Errorf("filterIntersection() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestMergeCsv verifies that mergeCsv returns a deduplicated union of two CSV strings.
func TestMergeCsv(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		existing string
		enforced string
		want     string
	}{
		{
			name:     "empty-existing-returns-enforced",
			existing: "",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "both-empty",
			existing: "",
			enforced: "",
			want:     "",
		},
		{
			name:     "no-overlap-merges-both",
			existing: "http",
			enforced: "dns",
			want:     "dns,http",
		},
		{
			name:     "partial-overlap-deduped",
			existing: "dns,http",
			enforced: "dns,whois",
			want:     "dns,http,whois",
		},
		{
			name:     "full-overlap-deduped",
			existing: "dns",
			enforced: "dns",
			want:     "dns",
		},
		{
			name:     "spaces-in-csv-trimmed",
			existing: "dns, http",
			enforced: "dns",
			want:     "dns,http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeCsv(tt.existing, tt.enforced)
			if testSortedcsv(got) != testSortedcsv(tt.want) {
				t.Errorf("mergeCsv() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// testSortedcsv splits a comma-separated string into items, sorts them, and rejoins them.
// Used for order-independent comparison of CSV outputs produced by map iteration.
func testSortedcsv(s string) string {

	// Return empty for empty input
	if s == "" {
		return ""
	}

	// Split, sort and rejoin
	items := strings.Split(s, ",")
	sort.Strings(items)

	// Return the canonically ordered CSV
	return strings.Join(items, ",")
}

// TestFetchLatestReleaseTag verifies that fetchLatestReleaseTag extracts the tag name on a valid response
// and returns an error for a non-200 status, malformed JSON, and an empty tag_name.
func TestFetchLatestReleaseTag(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantTag string
		wantErr bool
	}{
		{
			name: "valid-response-returns-tag",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","name":"nuclei-templates v9.9.9"}`))
			},
			wantTag: "v9.9.9",
			wantErr: false,
		},
		{
			name: "non-200-status-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found", http.StatusNotFound)
			},
			wantTag: "",
			wantErr: true,
		},
		{
			name: "malformed-json-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{not-valid-json`))
			},
			wantTag: "",
			wantErr: true,
		},
		{
			name: "empty-tag-name-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":""}`))
			},
			wantTag: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare unit test data
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			// Execute and check for expected error and tag value
			got, err := fetchLatestReleaseTag(&http.Client{Timeout: 5 * time.Second}, srv.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchLatestReleaseTag() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
			if got != tt.wantTag {
				t.Errorf("fetchLatestReleaseTag() tag = '%v', want = '%v'", got, tt.wantTag)
			}
		})
	}
}

// testStringslicesmatch reports whether two string slices contain the same elements regardless of order.
func testStringslicesmatch(a, b []string) bool {

	// Lengths must match
	if len(a) != len(b) {
		return false
	}

	// Both empty or nil — trivially equal
	if len(a) == 0 {
		return true
	}

	// Sort copies and compare element-by-element
	aCopy := make([]string, len(a))
	copy(aCopy, a)
	bCopy := make([]string, len(b))
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {

			// Return false as an element differs
			return false
		}
	}

	// Return true as slices match
	return true
}
