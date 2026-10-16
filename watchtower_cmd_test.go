package main

import (
	"testing"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"github.com/fatih/color"
)

// pm prints the trend the engine reports, so it matches the app.
func TestTrendTextUsesEngineTrend(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = prev }()

	since := time.Date(2026, 9, 30, 0, 0, 0, 0, time.Local)
	rep := &src.WatchtowerReport{Score: 82, History: []src.HistoryPoint{{T: since.AddDate(0, 0, -20).UnixMilli(), Score: 10}}}
	if got := trendText(rep); got != "" {
		t.Fatalf("no engine trend, no text: %q", got)
	}
	for _, c := range []struct {
		delta int
		want  string
	}{{5, "up 5 since Sep 30"}, {-3, "down 3 since Sep 30"}, {0, "unchanged since Sep 30"}} {
		rep.Trend = &src.ScoreTrend{Delta: c.delta, Since: since.UnixMilli()}
		if got := trendText(rep); got != c.want {
			t.Fatalf("delta %d: %q, want %q", c.delta, got, c.want)
		}
	}
}
