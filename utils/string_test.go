/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"reflect"
	"strings"
	"testing"
)

// TestRemoveDuplicates verifies that UniqueStrings correctly removes duplicate entries while preserving order and handling nil and empty slices.
func TestRemoveDuplicates(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		elements []string
		want     []string
	}{
		{
			name:     "duplicates1",
			elements: []string{"a", "b", "a", "a", "c"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "duplicates2",
			elements: []string{"a", "a"},
			want:     []string{"a"},
		},
		{
			name:     "duplicates3",
			elements: []string{"a", "  ", "  ", "c"},
			want:     []string{"a", "  ", "c"},
		},
		{
			name:     "no-duplicates1",
			elements: []string{"a", "b", "c"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "no-duplicates2",
			elements: []string{"a", "A", "aA"},
			want:     []string{"a", "A", "aA"},
		},
		{
			name:     "no-duplicates3",
			elements: []string{"a", "  ", "   ", "c"},
			want:     []string{"a", "  ", "   ", "c"},
		},
		{
			name:     "empty",
			elements: []string{},
			want:     []string{},
		},
		{
			name:     "nil",
			elements: nil,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UniqueStrings(tt.elements); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UniqueStrings() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestTrimToLower verifies that TrimToLower correctly trims whitespace and converts each string in the slice to lowercase.
func TestTrimToLower(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name  string
		slice []string
		want  []string
	}{
		{
			name:  "all-upper",
			slice: []string{"A", "B", "C"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "mixed-upper",
			slice: []string{"A", "b", "C"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "mixed-upper-untrimmed1",
			slice: []string{"A", "b ", "C"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "mixed-upper-untrimmed2",
			slice: []string{" A ", "b ", " C"},
			want:  []string{"a", "b", "c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimToLower(tt.slice); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimToLower() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestShuffle verifies that Shuffle returns a reordered copy of the input slice that differs from the original order.
func TestShuffle(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		strings []string
	}{
		{name: "new!=old", strings: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		{name: "new!=old-2", strings: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Shuffle(tt.strings); reflect.DeepEqual(got, tt.strings) {
				t.Errorf("Shuffle() = '%v', DON'T want = '%v'", got, tt.strings)
			}
		})
	}
}

// TestFilter verifies that Filter correctly retains only the elements that satisfy the provided predicate function.
func TestFilter(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		input  []string
		filter func(string) bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "a-only",
			args: args{
				input:  []string{"a", "b", "A", "a", "a", "c"},
				filter: func(s string) bool { return s == "a" },
			},
			want: []string{"a", "a", "a"},
		},
		{
			name: "a-containing",
			args: args{
				input:  []string{"Anton", "Berta", "Caesar", "Doris", "Esat", "Friedrich"},
				filter: func(s string) bool { return strings.Contains(s, "a") },
			},
			want: []string{"Berta", "Caesar", "Esat"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Filter(tt.args.input, tt.args.filter); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Filter() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestReverse verifies that Reverse correctly reverses the elements of a slice in-place.
func TestReverse(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "valid",
			input: []string{"7", "6", "5", "A", "3", "2", "1", "0"},
			want:  []string{"0", "1", "2", "3", "A", "5", "6", "7"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reverse(tt.input)
			if !reflect.DeepEqual(tt.input, tt.want) {
				t.Errorf("Reverse() = '%v', want = '%v'", tt.input, tt.want)
			}
		})
	}
}

// TestAlter verifies that Map correctly applies the manipulator function to each element of the input slice.
func TestAlter(t *testing.T) {
	manipulatorFunc := func(elem string) string { return "'" + elem + "'" }

	// Prepare and run test cases
	type args struct {
		slice       []string
		manipulator func(string) string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "sample",
			args: args{slice: []string{"1", "1", "2"}, manipulator: manipulatorFunc},
			want: []string{"'1'", "'1'", "'2'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Map(tt.args.slice, tt.args.manipulator); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Map() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestStrContained verifies that StrContained correctly reports whether a candidate string appears in any of the provided slices.
func TestStrContained(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		candidate string
		slices    [][]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "one-slice-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "test"}},
			},
			want: true,
		},
		{
			name: "one-slice-not-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "d"}},
			},
			want: false,
		},

		{
			name: "multiple-slices-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "test"}, {"a", "b", "c", "d"}},
			},
			want: true,
		},
		{
			name: "multiple-slices-not-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "e"}, {"a", "b", "c", "d"}},
			},
			want: false,
		},

		{
			name: "known-1",
			args: args{
				candidate: "test1",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: true,
		},
		{
			name: "known-2",
			args: args{
				candidate: "test1",
				slices:    [][]string{{"test1", "test2", "test3"}, {"test1", "test2", "test3"}},
			},
			want: true,
		},
		{
			name: "known-3",
			args: args{
				candidate: "probe1",
				slices:    [][]string{{}, {"probe1", "probe2", "probe3"}},
			},
			want: true,
		},
		{
			name: "unknown-1",
			args: args{
				candidate: "test4",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-2",
			args: args{
				candidate: "test",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-3",
			args: args{
				candidate: "test",
				slices:    [][]string{{}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-4",
			args: args{
				candidate: "test",
				slices:    [][]string{{}, {}},
			},
			want: false,
		},
		{
			name: "unknown-5",
			args: args{
				candidate: "test",
				slices:    [][]string{{}},
			},
			want: false,
		},
		{
			name: "unknown-6",
			args: args{
				candidate: "test",
				slices:    [][]string{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StrContained(tt.args.candidate, tt.args.slices...); got != tt.want {
				t.Errorf("StrContained() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestSubstrContained verifies that SubstrContained correctly reports whether any element in the provided slices contains the candidate as a substring.
func TestSubstrContained(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		candidate string
		slices    [][]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "multiple-slices-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "test"}, {"a", "b", "c", "d"}},
			},
			want: true,
		},
		{
			name: "multiple-slices-not-contained",
			args: args{
				candidate: "test",
				slices:    [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "e"}, {"a", "b", "c", "d"}},
			},
			want: false,
		},

		{
			name: "known-substr-1",
			args: args{
				candidate: "obe2",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: true,
		},
		{
			name: "known-substr-2",
			args: args{
				candidate: "test",
				slices:    [][]string{{"test1", "test2", "test3"}, {"test1", "test2", "test3"}},
			},
			want: true,
		},
		{
			name: "known-substr-3",
			args: args{
				candidate: "e2",
				slices:    [][]string{{}, {"probe1", "probe2", "probe3"}},
			},
			want: true,
		},
		{
			name: "unknown-substr-1",
			args: args{
				candidate: "test5",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-substr-2",
			args: args{
				candidate: "5",
				slices:    [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-substr-3",
			args: args{
				candidate: "other",
				slices:    [][]string{{}, {"probe1", "probe2", "probe3"}},
			},
			want: false,
		},
		{
			name: "unknown-substr-4",
			args: args{
				candidate: "other",
				slices:    [][]string{{}, {}},
			},
			want: false,
		},
		{
			name: "unknown-substr-5",
			args: args{
				candidate: "other",
				slices:    [][]string{{}},
			},
			want: false,
		},
		{
			name: "unknown-substr-6",
			args: args{
				candidate: "other",
				slices:    [][]string{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SubstrContained(tt.args.candidate, tt.args.slices...); got != tt.want {
				t.Errorf("SubstrContained() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestSameElementsSlices verifies that Equals correctly identifies when two slices contain the same elements regardless of order, including nil and empty edge cases.
func TestSameElementsSlices(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice1 []string
		slice2 []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "both-empty",
			args: args{slice1: []string{}, slice2: []string{}},
			want: true,
		},
		{
			name: "both-nil",
			args: args{slice1: nil, slice2: nil},
			want: true,
		},
		{
			name: "same-one-elem",
			args: args{slice1: []string{"ab"}, slice2: []string{"ab"}},
			want: true,
		},
		{
			name: "same-three-elem",
			args: args{slice1: []string{"a", "b", "c"}, slice2: []string{"a", "b", "c"}},
			want: true,
		},
		{
			name: "same-elem-diff-order",
			args: args{slice1: []string{"a", "b", "a"}, slice2: []string{"b", "a", "a"}},
			want: true,
		},
		{
			name: "one-nil",
			args: args{slice1: nil, slice2: []string{"a"}},
			want: false,
		},
		{
			name: "one-nil-2",
			args: args{slice1: []string{"a"}, slice2: nil},
			want: false,
		},
		{
			name: "one-nil-one-empty",
			args: args{slice1: nil, slice2: []string{}},
			want: false,
		},
		{
			name: "diff-elem",
			args: args{slice1: []string{"a", "b"}, slice2: []string{"a", "c"}},
			want: false,
		},
		{
			name: "diff-elem-2",
			args: args{slice1: []string{"a", "a"}, slice2: []string{"a", "c"}},
			want: false,
		},
		{
			name: "diff-amount",
			args: args{slice1: []string{"a"}, slice2: []string{"a", "c"}},
			want: false,
		},
		{
			name: "same-elem-diff-amount",
			args: args{slice1: []string{"a", "b", "a"}, slice2: []string{"a", "b", "b"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Equals(tt.args.slice1, tt.args.slice2); got != tt.want {
				t.Errorf("Equals() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestAppendUnique verifies that AppendUnique correctly appends only elements not already present in the slice, preserving existing duplicates.
func TestAppendUnique(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice    []string
		elements []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty",
			args: args{slice: []string{}, elements: []string{}},
			want: []string{},
		},
		{
			name: "all-duplicates",
			args: args{slice: []string{"1", "2", "3"}, elements: []string{"1", "2", "3"}},
			want: []string{"1", "2", "3"},
		},
		{
			name: "most-duplicates",
			args: args{slice: []string{"1", "2", "3"}, elements: []string{"1", "2", "3", "4"}},
			want: []string{"1", "2", "3", "4"},
		},
		{
			name: "one-to-one",
			args: args{slice: []string{"1"}, elements: []string{"2"}},
			want: []string{"1", "2"},
		},
		{
			name: "three-to-none",
			args: args{slice: []string{}, elements: []string{"1", "2", "3"}},
			want: []string{"1", "2", "3"},
		},
		{
			name: "none-to-three",
			args: args{slice: []string{"1", "2", "3"}, elements: []string{}},
			want: []string{"1", "2", "3"},
		},
		{
			name: "duplicates-to-none",
			args: args{slice: []string{}, elements: []string{"1", "2", "3", "3", "3"}},
			want: []string{"1", "2", "3"},
		},
		{
			name: "duplicates-to-duplicates",
			args: args{slice: []string{"1", "1", "1", "1"}, elements: []string{"1", "2", "3", "3", "3"}},
			want: []string{"1", "1", "1", "1", "2", "3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AppendUnique(tt.args.slice, tt.args.elements...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AppendUnique() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestRemoveFromSlice verifies that RemoveFromSlice correctly removes all occurrences of the target string from the slice.
func TestRemoveFromSlice(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice []string
		s     string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty",
			args: args{slice: []string{}, s: "3"},
			want: nil,
		},
		{
			name: "no-occurrence",
			args: args{slice: []string{"1", "2"}, s: "3"},
			want: []string{"1", "2"},
		},
		{
			name: "one-occurrence",
			args: args{slice: []string{"1", "2", "3"}, s: "3"},
			want: []string{"1", "2"},
		},
		{
			name: "multiple-occurrences",
			args: args{slice: []string{"3", "1", "3", "3", "2", "3"}, s: "3"},
			want: []string{"1", "2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveFromSlice(tt.args.slice, tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveFromSlice() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestTitleFirstLetter verifies that TitleFirstLetter correctly capitalizes the first letter of a string while leaving the rest unchanged.
func TestTitleFirstLetter(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "multiple-words",
			args: args{s: "this is a sentence."},
			want: "This is a sentence.",
		},
		{
			name: "empty-string",
			args: args{s: ""},
			want: "",
		},
		{
			name: "uppercase-already",
			args: args{s: "The bear"},
			want: "The bear",
		},
		{
			name: "one-letter",
			args: args{s: "x"},
			want: "X",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TitleFirstLetter(tt.args.s); got != tt.want {
				t.Errorf("TitleFirstLetter() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
