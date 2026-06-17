package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/siemens/GoScans/utils"
)

// chownDirTree sets the ownership of all files and folders within the given path
// to match the owner of the currently executing binary
func chownDirTree(logger utils.Logger, pathTemplates string) error {

	// Get the path to the currently executing binary
	exePath, errExecPath := os.Executable()
	if errExecPath != nil {
		return fmt.Errorf("could not get executable path: %w", errExecPath)
	}

	// Get absolute path
	exePathAbs, errExecPathAbs := filepath.Abs(exePath)
	if errExecPathAbs != nil {
		return fmt.Errorf("could not get absolute path of executable: %w", errExecPathAbs)
	}

	// Get info of the binary
	info, errInfo := os.Stat(exePathAbs)
	if errInfo != nil {
		return fmt.Errorf("could not stat executable: %w", errInfo)
	}

	// Get stat_t to extract UID/GID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not get raw stat for executable")
	}

	// Get UID/GID
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Recursively walk template directory and set ownership
	return filepath.WalkDir(pathTemplates, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if errChown := os.Chown(p, uid, gid); err != nil {
			logger.Warningf("could not chown '%s': %v", p, errChown) // log a warning but continue
		}
		return nil
	})
}
