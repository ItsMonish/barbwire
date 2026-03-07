package scoring

import (
	"strings"

	"github.com/ItsMonish/barbwire/internal/config"
	"github.com/ItsMonish/barbwire/internal/types"
)

const (
	SeverityLow    string = "LOW"
	SeverityMedium string = "MEDIUM"
	SeverityHigh   string = "HIGH"
)

type Scorer struct {
	conf *config.Config
}

type SeverityResult struct {
	Score    int
	Severity string
	Reasons  []string
}

func NewScorer(cfg *config.Config) *Scorer {
	s := &Scorer{
		conf: cfg,
	}
	return s
}

func (s *Scorer) ScoreEvent(fname string, lineage *types.LineageEntry) SeverityResult {
	result := SeverityResult{}

	for _, pair := range s.conf.SuspiciousFiles {
		for _, pattern := range pair.Patterns {
			if strings.Contains(fname, pattern) {
				result.Score += pair.BaseScore
				result.Reasons = append(result.Reasons, pair.Category)
				goto doneFileMatch
			}
		}
	}
doneFileMatch:
	if result.Score == 0 {
		return result
	}

	if lineage != nil {
		for _, p := range s.conf.SuspiciousParents {
			if lineage.ParentComm == p.Comm || lineage.GparentComm == p.Comm {
				result.Score += p.Modifier
				result.Reasons = append(result.Reasons, "suspicious parent: "+p.Comm)
				break
			}
		}
		for _, p := range s.conf.LegitParents {
			if lineage.ParentComm == p.Comm || lineage.GparentComm == p.Comm {
				result.Score += p.Modifier
				result.Reasons = append(result.Reasons, "legit parent: "+p.Comm)
				break
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	result.Severity = scoreToSeverity(result.Score, s.conf.SeverityThresholds)
	return result
}

func scoreToSeverity(score int, thresholds config.SeverityThreshold) string {
	switch {
	case score >= thresholds.High:
		return SeverityHigh
	case score >= thresholds.Medium:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
