/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package filecrawler

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestCrawler_Crawl verifies that the crawler correctly traverses directories and returns expected file and folder results.
func TestCrawler_Crawl(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare exceeded context
	ctxExceeded, ctxExceededCancel := context.WithTimeout(context.Background(), -3*time.Second)
	defer ctxExceededCancel()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	type fields struct {
		crawlDepth                int
		excludedFolders           map[string]struct{}
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int64
		onlyAccessibleFiles       bool
		threads                   int
		context                   context.Context
	}
	type args struct {
		startInfo *EntryPoint
	}
	tests := []struct {
		name                string
		fields              fields
		args                args
		wantFoldersReadable int
		wantFilesReadable   int
		wantFilesWritable   int
		wantFileInfos       []File
		wantStatus          string
		wantException       bool
	}{
		{
			name: "normal",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   1,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "filecrawler",
				IsShare:   true,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   5,
			wantFilesWritable:   5,
			wantFileInfos: []File{
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "empty.txt"),
					Name:       "empty.txt",
					Extension:  "txt",
					Mime:       "text/plain",
					Readable:   true,
					Writable:   true,
					SizeKb:     0,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "file1.txt"),
					Name:       "file1.txt",
					Extension:  "txt",
					Mime:       "text/plain",
					Readable:   true,
					Writable:   true,
					SizeKb:     0,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "file_with_content.txt"),
					Name:       "file_with_content.txt",
					Extension:  "txt",
					Mime:       "text/csv",
					Readable:   true,
					Writable:   true,
					SizeKb:     3,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{},
				},
				{
					Share:      "filecrawler",
					Path:       filepath.Join(crawlFolder, "folder_with_files", "file_with_content.txt"),
					Name:       "file_with_content.txt",
					Extension:  "txt",
					Mime:       "text/plain; charset=utf-8",
					Readable:   true,
					Writable:   true,
					SizeKb:     0,
					Depth:      2,
					IsSymlink:  false,
					Properties: []string{},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "excluded-folders",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           map[string]struct{}{"filecrawler": {}},
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "excluded-extensions",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   1,
			wantFilesWritable:   1,
			wantFileInfos: []File{
				{
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "excluded-last-modified",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "excluded-filesize",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     10,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 2,
			wantFilesReadable:   1,
			wantFilesWritable:   1,
			wantFileInfos: []File{
				{
					Path:       filepath.Join(crawlFolder, "empty document.docx"),
					Name:       "empty document.docx",
					Extension:  "docx",
					Mime:       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					Readable:   true,
					Writable:   true,
					SizeKb:     12,
					Depth:      1,
					IsSymlink:  false,
					Properties: []string{"Document_Confidentiality: Unrestricted", "DateProp: 1970-01-01T10:00:00Z", "BoolProp: true", "IntegerProp: -10", "FloatProp: 1.2345"},
				},
			},
			wantStatus:    utils.StatusCompleted,
			wantException: false,
		},
		{
			name: "deadline",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   ctxExceeded,
			},
			args: args{startInfo: &EntryPoint{
				Path:      crawlFolder,
				InsideDfs: false,
				Share:     "",
				IsShare:   false,
			},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusDeadline,
			wantException:       false,
		},
		{
			name: "nil-argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{
				startInfo: nil,
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "empty-argument",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{
				startInfo: &EntryPoint{},
			},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
		{
			name: "nonexistent-path",
			fields: fields{
				crawlDepth:                -1,
				excludedFolders:           nil,
				excludedExtensions:        nil,
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
				threads:                   0,
				context:                   context.Background(),
			},
			args: args{startInfo: &EntryPoint{
				Path:      "/does/not/exist/folder",
				InsideDfs: false,
				Share:     "nonexistent",
				IsShare:   false,
			}},
			wantFoldersReadable: 0,
			wantFilesReadable:   0,
			wantFilesWritable:   0,
			wantFileInfos:       nil,
			wantStatus:          utils.StatusCompleted,
			wantException:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), tt.fields.crawlDepth, tt.fields.excludedFolders, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, tt.fields.threads, tt.fields.context)
			got := c.Crawl(tt.args.startInfo)
			if len(got.Data) != len(tt.wantFileInfos) {
				t.Errorf("Crawler.Crawl() data length = '%v', want = '%v'", len(got.Data), len(tt.wantFileInfos))
				return
			}

			var gotFiles []File
			for i, obj := range got.Data {
				tt.wantFileInfos[i].LastModified = obj.LastModified
				gotFiles = append(gotFiles, *obj)
			}

			if !reflect.DeepEqual(gotFiles, tt.wantFileInfos) {
				t.Errorf("Crawler.Crawl() files = '%v', want = '%v'", gotFiles, tt.wantFileInfos)
			}
			if !reflect.DeepEqual(got.FoldersReadable, tt.wantFoldersReadable) {
				t.Errorf("Crawler.Crawl() foldersReadable = '%v', want = '%v'", got.FoldersReadable, tt.wantFoldersReadable)
			}
			if !reflect.DeepEqual(got.FilesReadable, tt.wantFilesReadable) {
				t.Errorf("Crawler.Crawl() filesReadable = '%v', want = '%v'", got.FilesReadable, tt.wantFilesReadable)
			}
			if !reflect.DeepEqual(got.FilesWritable, tt.wantFilesWritable) {
				t.Errorf("Crawler.Crawl() filesWritable = '%v', want = '%v'", got.FilesWritable, tt.wantFilesWritable)
			}
			if !reflect.DeepEqual(got.Status, tt.wantStatus) {
				t.Errorf("Crawler.Crawl() status = '%v', want = '%v'", got.Status, tt.wantStatus)
			}
			if !reflect.DeepEqual(got.Exception, tt.wantException) {
				t.Errorf("Crawler.Crawl() exception = '%v', want = '%v'", got.Exception, tt.wantException)
			}
		})
	}
}

// TestCrawler_processFile verifies that processFile correctly processes individual files and applies exclusion filters.
func TestCrawler_processFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	type args struct {
		filePath string
		share    string
		isDFS    bool
		depth    int
	}
	type fields struct {
		excludedExtensions        map[string]struct{}
		excludedLastModifiedBelow time.Time
		excludedFileSizeBelow     int64
		onlyAccessibleFiles       bool
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantResult *File
		wantTasks  []*task
	}{
		{
			name: "average-case",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args: args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: &File{
				Share:           "TestShare",
				Path:            filepath.Join(crawlFolder, "file_with_content.txt"),
				Name:            "file_with_content.txt",
				Extension:       "txt",
				Mime:            "text/csv",
				Readable:        true,
				Writable:        true,
				SizeKb:          3,
				LastModified:    time.Time{},
				Depth:           2,
				IsSymlink:       false,
				IsDfs:           false,
				NfsRestrictions: nil,
				Properties:      []string{},
			},
			wantTasks: nil,
		},
		{
			name: "excluded-extensions",
			fields: fields{
				excludedExtensions:        map[string]struct{}{"txt": {}},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "excluded-last-modified",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Now(),
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "excluded-file-size-below",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Date(2007, 12, 22, 11, 25, 44, 5876554000, time.Local),
				excludedFileSizeBelow:     4,
				onlyAccessibleFiles:       true,
			},
			args:       args{filepath.Join(crawlFolder, "file_with_content.txt"), "TestShare", false, 2},
			wantResult: nil,
			wantTasks:  nil,
		},
		{
			name: "nonexistent-path",
			fields: fields{
				excludedExtensions:        map[string]struct{}{},
				excludedLastModifiedBelow: time.Time{},
				excludedFileSizeBelow:     0,
				onlyAccessibleFiles:       false,
			},
			args:       args{"/does/not/exist/file.txt", "TestShare", false, 1},
			wantResult: nil,
			wantTasks:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrawler(utils.NewTestLogger(), 0, nil, tt.fields.excludedExtensions, tt.fields.excludedLastModifiedBelow, tt.fields.excludedFileSizeBelow, tt.fields.onlyAccessibleFiles, 0, context.Background())
			var chProcessResults = make(chan *processResult)
			go c.processFile(&task{
				isFolder:      false,
				path:          tt.args.filePath,
				isInsideDfs:   false,
				isShareFolder: false,
				depth:         tt.args.depth,
				share:         "TestShare",
			}, 0, chProcessResults)
			procRes := <-chProcessResults

			if tt.wantResult != nil && procRes.data != nil {
				tt.wantResult.LastModified = procRes.data.LastModified
			}

			if !reflect.DeepEqual(procRes.data, tt.wantResult) {
				t.Errorf("Crawler.processFile() data = '%v', want = '%v'", procRes.data, tt.wantResult)
			}
			if !reflect.DeepEqual(procRes.newTasks, tt.wantTasks) {
				t.Errorf("Crawler.processFile() newTasks = '%v', want = '%v'", procRes.newTasks, tt.wantTasks)
			}
		})
	}
}
