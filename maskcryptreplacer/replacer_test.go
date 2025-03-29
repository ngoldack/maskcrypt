package maskcryptreplacer_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/ngoldack/maskcrypt/maskcryptreplacer"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value slog.Value
		fail  bool
	}{
		{"int value test", "test", slog.IntValue(100), false},
		{"string value test", "test", slog.StringValue("testdata"), false},
		{"duration value test", "test", slog.DurationValue(time.Hour), false},
		{"float64 value test", "test", slog.Float64Value(3.14), false},
		{"bool true value test", "test", slog.BoolValue(true), false},
		{"bool false value test", "test", slog.BoolValue(false), false},
		{"int64 value test", "test", slog.Int64Value(100), false},
		{"single group value test", "test", slog.GroupValue(
			slog.String("test", "test"),
		), false},
		{"multiple group values test", "test", slog.GroupValue(
			slog.String("test", "test"),
			slog.Int("test", 100),
		), false},

		{"int value test", "fail", slog.IntValue(100), true},
		{"string value test", "fail", slog.StringValue("testdata"), true},
		{"duration value test", "fail", slog.DurationValue(time.Hour), true},
		{"float64 value test", "fail", slog.Float64Value(3.14), true},
		{"bool true value test", "fail", slog.BoolValue(true), true},
		{"bool false value test", "fail", slog.BoolValue(false), true},
		{"int64 value test", "fail", slog.Int64Value(100), true},
		{"single group value test", "fail", slog.GroupValue(
			slog.String("fail", "test"),
		), true},
		{"multiple group values test", "fail", slog.GroupValue(
			slog.String("fail", "test"),
			slog.Int("fail", 100),
		), true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_fail_is_%v", tt.name, tt.fail), func(t *testing.T) {
			t.Parallel()
			b := bytes.NewBufferString("")

			key := "test"
			if tt.fail {
				key = "fail"
			}

			p := NewMockParser(key, "testdata")

			var h slog.Handler = slog.NewTextHandler(b, &slog.HandlerOptions{
				Level:       slog.LevelInfo,
				ReplaceAttr: maskcryptreplacer.New(p),
			})
			l := slog.New(h)

			l.Info("test", slog.Attr{Key: tt.key, Value: tt.value})

			// Check if the value is masked
			if tt.fail {
				assert.NotContains(t, b.String(), "test=masked")
			} else {
				assert.Contains(t, b.String(), "test=masked")
			}
		})
	}

}
