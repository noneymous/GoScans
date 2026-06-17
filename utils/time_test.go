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
	"context"
	"testing"
	"time"
)

// TestContextExpired verifies that ContextExpired returns true for cancelled or timed-out contexts and false otherwise.
func TestContextExpired(t *testing.T) {

	ctxTimeoutExceeded, ctxTimeoutExceededCancel := context.WithTimeout(context.Background(), -time.Second*3)
	defer ctxTimeoutExceededCancel()
	ctxTimeout, ctxTiemoutCancel := context.WithTimeout(context.Background(), time.Second*3)
	defer ctxTiemoutCancel()
	ctxCancelCancelled, ctxCancelCancelledCancel := context.WithCancel(context.Background())
	ctxCancelCancelledCancel() // Immediately cancelled
	ctxCancel, ctxCancelCancel := context.WithCancel(context.Background())
	defer ctxCancelCancel()

	tests := []struct {
		name    string
		context context.Context
		want    bool
	}{
		{
			name:    "reached-1",
			context: ctxTimeoutExceeded,
			want:    true,
		},
		{
			name:    "reached-2",
			context: ctxCancelCancelled,
			want:    true,
		},
		{
			name:    "nil",
			context: nil,
			want:    false,
		},
		{
			name:    "not-reached-1",
			context: context.Background(),
			want:    false,
		},
		{
			name:    "not-reached-2",
			context: ctxTimeout,
			want:    false,
		},
		{
			name:    "not-reached-3",
			context: ctxCancel,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContextExpired(tt.context); got != tt.want {
				t.Errorf("ContextExpired() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
