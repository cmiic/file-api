package config

import (
	"testing"
	"time"
)

func TestParseDeleteMaxAge(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{raw: "", want: 0},
		{raw: "   ", wantErr: true}, // set but blank is a typo, not "disabled"
		{raw: "30m", want: 30 * time.Minute},
		{raw: "24h", want: 24 * time.Hour},
		{raw: " 1h30m ", want: 90 * time.Minute},
		{raw: "0", wantErr: true},
		{raw: "0s", wantErr: true},
		{raw: "-5m", wantErr: true},
		{raw: "86400", wantErr: true}, // bare seconds are not a Go duration
		{raw: "1d", wantErr: true},    // nor are days
		{raw: "soon", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseDeleteMaxAge(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got %s", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.raw, got, tc.want)
		}
	}
}
