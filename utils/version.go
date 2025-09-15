/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major int
	Minor int
	Patch int
}

// NewVersion generates a Version struct from a dot separated version string, such as, 5.0.5
func NewVersion(version string) (Version, error) {
	versionSlice := strings.Split(version, ".")
	versionSliceInt := make([]int, 3)
	for i, v := range versionSlice {
		var errAtoi error
		versionSliceInt[i], errAtoi = strconv.Atoi(v)
		if errAtoi != nil {
			return Version{}, fmt.Errorf("could not parse version string '%s'", version)
		}
	}
	return Version{
		Major: versionSliceInt[0],
		Minor: versionSliceInt[1],
		Patch: versionSliceInt[2],
	}, nil
}

func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v *Version) IsGreaterThan(otherVersion Version) bool {
	if v.Major > otherVersion.Major {
		return true
	}
	if v.Major == otherVersion.Major && v.Minor > otherVersion.Minor {
		return true
	}
	if v.Major == otherVersion.Major && v.Minor == otherVersion.Minor && v.Patch > otherVersion.Patch {
		return true
	}
	return false
}

func (v *Version) IsGreaterEqualThan(otherVersion Version) bool {
	if v.IsGreaterThan(otherVersion) {
		return true
	} else if v.Major == otherVersion.Major && v.Minor == otherVersion.Minor && v.Patch == otherVersion.Patch {
		return true
	}
	return false
}
