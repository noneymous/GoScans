/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"path/filepath"
	"testing"

	"github.com/siemens/GoScans/_test"
	"golang.org/x/sys/windows/registry"
)

// TestCheckWinpcap verifies that CheckWinpcap returns an error when WinPcap is not installed.
func TestCheckWinpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "valid", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckWinpcap(); (err != nil) != tt.wantErr {
				t.Errorf("CheckWinpcap() error = '%v', wantErr = '%v'", err, tt.wantErr) // throws error if winpcap is not installed.
			}
		})
	}
}

// TestCheckNpcap verifies that CheckNpcap returns no error when Npcap is installed.
func TestCheckNpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "valid", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNpcap(); (err != nil) != tt.wantErr {
				t.Errorf("CheckNpcap() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestImportRegistryFile verifies that ImportRegistryFile returns an error without admin privileges or for invalid paths.
func TestImportRegistryFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Prepare unit test data
	patchPath := filepath.Join(testSettings.PathNmapDir, "nmap_performance.reg")

	// Prepare and run test cases
	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "invalid-privileges",
			filePath: patchPath,
			wantErr:  true,
		}, // throws error without admin process privileges
		{
			name:     "invalid-path",
			filePath: "notexisting",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ImportRegistryFile(tt.filePath); (err != nil) != tt.wantErr {
				t.Errorf("ImportRegistryFile() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestCheckNmapPerformancePatch verifies that CheckNmapPerformancePatch detects whether the performance patch is applied.
func TestCheckNmapPerformancePatch(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "patch-should-be-applied", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNmapPerformancePatch(); (err != nil) != tt.wantErr {
				t.Errorf("CheckNmapPerformancePatch() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestCheckRegistryIntValue verifies that CheckRegistryIntValue validates registry integer values and covers GetRegistryIntValue.
func TestCheckRegistryIntValue(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		root  registry.Key
		path  string
		key   string
		value int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 1},
			wantErr: false,
		},
		{
			name:    "invalid-path",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key", 815},
			wantErr: true,
		},
		{
			name:    "invalid-key",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting", 815},
			wantErr: true,
		},
		{
			name:    "invalid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 815},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckRegistryIntValue(tt.args.root, tt.args.path, tt.args.key, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("CheckRegistryIntValue() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestGetRegistryStringValue verifies that GetRegistryStringValue retrieves the correct string value from the registry.
func TestGetRegistryStringValue(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		root registry.Key
		path string
		key  string
	}
	tests := []struct {
		name    string
		args    args
		wantVal string
		wantErr bool
	}{
		{
			name:    "valid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Print`, "ConfigModule"},
			wantVal: "PrintConfig.dll",
			wantErr: false,
		},
		{
			name:    "invalid-path",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key"},
			wantVal: "",
			wantErr: true,
		},
		{
			name:    "invalid-key",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting"},
			wantVal: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, err := GetRegistryStringValue(tt.args.root, tt.args.path, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRegistryStringValue() error = '%v', wantErr = '%v'", err, tt.wantErr)
			} else if str != tt.wantVal {
				t.Errorf("GetRegistryStringValue() = '%v', want = '%v'", str, tt.wantVal)
			}
		})
	}
}

// TestCheckNmapFirewall verifies that CheckNmapFirewall returns an error for an executable not in the Windows firewall list.
func TestCheckNmapFirewall(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		appPath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "declined-app",
			args:    args{`C:\notexisting.exe`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNmapFirewall(tt.args.appPath); (err != nil) != tt.wantErr {
				t.Errorf("CheckNmapFirewall() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestSetNmapFirewall verifies that SetNmapFirewall returns an error without admin process privileges.
func TestSetNmapFirewall(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Prepare and run test cases
	tests := []struct {
		name     string
		nmapPath string
		wantErr  bool
	}{
		{
			name:     "invalid-privileges",
			nmapPath: testSettings.PathNmap,
			wantErr:  true,
		}, // throws error without admin process privileges
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SetNmapFirewall(tt.nmapPath); (err != nil) != tt.wantErr {
				t.Errorf("SetNmapFirewall() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}
