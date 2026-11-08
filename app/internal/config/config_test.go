package config

import (
	"strings"
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
		{raw: "unlimited", want: DeleteAnyAge},
		{raw: " unlimited ", want: DeleteAnyAge},
		{raw: "2562047h", want: 2562047 * time.Hour}, // the largest whole-hour duration
		{raw: "Unlimited", wantErr: true},            // the keyword is exact
		{raw: "unlimit", wantErr: true},
		{raw: "999y", wantErr: true}, // years are not a Go duration
		{raw: "0", wantErr: true},
		{raw: "0s", wantErr: true},
		{raw: "-5m", wantErr: true},
		{raw: "86400", wantErr: true}, // bare seconds are not a Go duration
		{raw: "1d", wantErr: true},    // nor are days
		{raw: "soon", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseDeleteMaxAge("DELETE_MAX_AGE", tc.raw)
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

func TestDeleteWindows(t *testing.T) {
	cases := []struct {
		name            string
		public, private string
		wantPublic      time.Duration
		wantPrivate     time.Duration
	}{
		{name: "both unset is off for all files"},
		{name: "one window covers private files too", public: "24h", wantPublic: 24 * time.Hour, wantPrivate: 24 * time.Hour},
		{name: "unlimited covers private files too", public: "unlimited", wantPublic: DeleteAnyAge, wantPrivate: DeleteAnyAge},
		{name: "private only leaves public files off", private: "unlimited", wantPrivate: DeleteAnyAge},
		{name: "private overrides", public: "24h", private: "unlimited", wantPublic: 24 * time.Hour, wantPrivate: DeleteAnyAge},
		{name: "private may be the shorter", public: "24h", private: "1h", wantPublic: 24 * time.Hour, wantPrivate: time.Hour},
	}
	for _, tc := range cases {
		public, private, err := deleteWindows(tc.public, tc.private)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if public != tc.wantPublic || private != tc.wantPrivate {
			t.Errorf("%s: got %s and %s, want %s and %s", tc.name, public, private, tc.wantPublic, tc.wantPrivate)
		}
	}
}

func TestDeleteWindowsNamesTheInvalidVariable(t *testing.T) {
	cases := []struct {
		public, private string
		want            string
	}{
		{public: "soon", private: "24h", want: `DELETE_MAX_AGE "soon"`},
		{public: "24h", private: "soon", want: `DELETE_MAX_AGE_PRIVATE "soon"`},
		{public: "24h", private: "0s", want: `DELETE_MAX_AGE_PRIVATE "0s"`},
	}
	for _, tc := range cases {
		_, _, err := deleteWindows(tc.public, tc.private)
		if err == nil {
			t.Errorf("%q, %q: expected an error", tc.public, tc.private)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q, %q: error %q does not name %s", tc.public, tc.private, err, tc.want)
		}
	}
}

func TestDescribeDeleteWindow(t *testing.T) {
	cases := map[time.Duration]string{
		0:              "off",
		DeleteAnyAge:   "any age",
		24 * time.Hour: "younger than 24h0m0s",
	}
	for d, want := range cases {
		if got := DescribeDeleteWindow(d); got != want {
			t.Errorf("%s: got %q, want %q", d, got, want)
		}
	}
}
