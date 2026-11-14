package media

import (
	"context"
	"strings"

	"go.vicoworks.com/guard-rails-engine/internal/core"
)

// Guard reports the ingest step's findings through the pipeline, so a macro
// or an unsafe image is graded, actioned, audited and counted by the same
// policy machinery as an injection score. The extraction itself happened in
// Prepare, before the stage; this guard only reads its results, which is why
// it fits the stage budget however large the file was.
type Guard struct {
	name  string
	stage core.Stage
}

// NewGuard returns the media guard for the inbound stage or the tool-result
// stage.
func NewGuard(stage core.Stage) *Guard {
	if stage == core.StageToolResult {
		return &Guard{name: GuardResultName, stage: stage}
	}
	return &Guard{name: GuardName, stage: core.StageInbound}
}

func (g *Guard) Name() string      { return g.name }
func (g *Guard) Stage() core.Stage { return g.stage }

func (g *Guard) Check(ctx context.Context, tx *core.Transaction) (core.Result, error) {
	var res core.Result
	parts := tx.Parts()
	if len(parts) == 0 {
		return res, nil
	}
	counts := map[string]float64{}
	for _, ref := range parts {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		isResult := strings.HasPrefix(ref.Field, "tool_results[")
		if (g.stage == core.StageToolResult) != isResult {
			continue
		}
		ext := ref.Part.Extraction
		if ext == nil {
			// Ingest did not run (an engine built without a processor). The
			// part reached a guard unread, which is exactly what must not
			// pass silently.
			f := finding(ref, "not_ingested", "media.unscannable", core.SeverityMedium,
				"attachment "+ref.Part.Label()+" was not processed by the ingest step")
			f.Guard = g.name
			res.Findings = append(res.Findings, f)
			continue
		}
		counts["media.parts."+string(ref.Part.Type)]++
		counts["media.coverage."+string(ext.Coverage)]++
		for _, f := range ext.Findings {
			f.Guard = g.name
			res.Findings = append(res.Findings, f)
		}
	}
	res.Metrics = counts
	return res, nil
}
