package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vicoaritonang/guardrails-engine/internal/experiment"
)

// Lab runs experiments on behalf of the web page.
//
// Running an experiment spends real API quota, so the lab is switched on
// explicitly (GUARDRAILS_EXPERIMENTS_RUN=true) and runs one job at a time. The
// job's progress is streamed on the event bus and kept in memory, so a page
// that connects mid-run can still show what has happened.
type Lab struct {
	Root string
	// Run executes one named experiment and returns its result and run dir.
	Run func(ctx context.Context, name string, quick bool, log io.Writer) (*experiment.Result, string, error)
	// Fetch downloads the public benchmarks.
	Fetch func(ctx context.Context, log io.Writer) error

	mu  sync.Mutex
	job *labJob
}

type labJob struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Quick    bool                `json:"quick"`
	Status   string              `json:"status"` // running | done | failed
	Started  time.Time           `json:"started"`
	Finished time.Time           `json:"finished,omitzero"`
	Lines    []string            `json:"lines"`
	Dir      string              `json:"dir,omitempty"`
	Error    string              `json:"error,omitempty"`
	Headline []experiment.Metric `json:"headline,omitempty"`
	Findings []string            `json:"findings,omitempty"`
}

// lineWriter turns progress output into bus events, line by line.
type lineWriter struct {
	s   *Server
	job *labJob
	mu  *sync.Mutex // guards job
	wmu sync.Mutex  // guards buf: experiments log from parallel workers
	buf []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:i]), "\r")
		w.buf = w.buf[i+1:]
		if strings.TrimSpace(line) == "" {
			continue
		}
		w.mu.Lock()
		w.job.Lines = append(w.job.Lines, line)
		if len(w.job.Lines) > 400 {
			w.job.Lines = w.job.Lines[len(w.job.Lines)-400:]
		}
		w.mu.Unlock()
		w.s.bus.Publish("lab.log", map[string]any{"job": w.job.ID, "name": w.job.Name, "line": line})
	}
	return len(p), nil
}

type labRun struct {
	ID         string              `json:"run_id"`
	Experiment string              `json:"experiment"`
	Title      string              `json:"title"`
	Started    time.Time           `json:"started_at"`
	Headline   []experiment.Metric `json:"headline"`
	Dir        string              `json:"dir"`
	Usage      experiment.Usage    `json:"usage"`
}

func (s *Server) handleLab(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"enabled": s.opts.Lab != nil && s.opts.Lab.Run != nil, "catalog": experiment.Catalog}
	root := s.opts.ExperimentsDir
	if s.opts.Lab != nil {
		root = s.opts.Lab.Root
	}
	if root != "" {
		latest := map[string]labRun{}
		if f, err := os.Open(filepath.Join(root, "runs", "index.jsonl")); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64<<10), 4<<20)
			for sc.Scan() {
				var r labRun
				if json.Unmarshal(sc.Bytes(), &r) == nil && r.Started.After(latest[r.Experiment].Started) {
					latest[r.Experiment] = r
				}
			}
			f.Close()
		}
		out["latest"] = latest
		_, err := os.Stat(filepath.Join(root, "benchmarks", "manifest.json"))
		out["benchmarks_fetched"] = err == nil
	}
	if l := s.opts.Lab; l != nil {
		l.mu.Lock()
		if l.job != nil {
			j := *l.job
			j.Lines = append([]string(nil), l.job.Lines...)
			out["job"] = j
		}
		l.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLabRun(w http.ResponseWriter, r *http.Request) {
	l := s.opts.Lab
	if l == nil || l.Run == nil {
		writeError(w, http.StatusServiceUnavailable, "lab_disabled",
			"running experiments from the web is off; set GUARDRAILS_EXPERIMENTS_RUN=true and GUARDRAILS_EXPERIMENTS_DIR")
		return
	}
	var req struct {
		Name  string `json:"name"`
		Quick bool   `json:"quick"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, ok := experiment.SpecFor(req.Name); !ok && req.Name != "fetch" {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown experiment "+req.Name)
		return
	}
	l.mu.Lock()
	if l.job != nil && l.job.Status == "running" {
		j := *l.job
		l.mu.Unlock()
		writeErrorDetails(w, http.StatusConflict, "busy", "an experiment is already running: "+j.Name, j)
		return
	}
	job := &labJob{ID: newID(), Name: req.Name, Quick: req.Quick, Status: "running", Started: time.Now().UTC()}
	l.job = job
	l.mu.Unlock()

	s.bus.Publish("lab.start", map[string]any{"job": job.ID, "name": job.Name, "quick": job.Quick})
	s.log.Info("experiment started from the web", "experiment", job.Name, "quick", job.Quick, "request_id", requestID(r.Context()))

	go func() {
		// Detached from the HTTP request: closing the tab must not abort a run
		// that is spending quota, and the hour bound stops a stuck one.
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		lw := &lineWriter{s: s, job: job, mu: &l.mu}
		mode := "full"
		if job.Quick {
			mode = "quick"
		}
		fmt.Fprintf(lw, "starting %s (%s run)\n", job.Name, mode)
		var err error
		var res *experiment.Result
		var dir string
		if job.Name == "fetch" {
			err = l.Fetch(ctx, lw)
		} else {
			res, dir, err = l.Run(ctx, job.Name, job.Quick, lw)
		}
		if err != nil {
			fmt.Fprintf(lw, "failed after %s: %v\n", time.Since(job.Started).Round(time.Second), err)
		} else {
			fmt.Fprintf(lw, "finished in %s\n", time.Since(job.Started).Round(100*time.Millisecond))
		}
		l.mu.Lock()
		job.Finished = time.Now().UTC()
		if err != nil {
			job.Status, job.Error = "failed", err.Error()
		} else {
			job.Status = "done"
			if dir != "" {
				job.Dir = filepath.ToSlash(filepath.Join("runs", filepath.Base(dir)))
			}
			if res != nil {
				job.Headline, job.Findings = res.Headline, res.Findings
			}
		}
		snap := *job
		l.mu.Unlock()
		s.bus.Publish("lab.done", map[string]any{"job": snap.ID, "name": snap.Name, "status": snap.Status,
			"dir": snap.Dir, "error": snap.Error, "headline": snap.Headline, "findings": snap.Findings})
		s.log.Info("experiment finished", "experiment", snap.Name, "status", snap.Status, "error", snap.Error)
	}()
	writeJSON(w, http.StatusAccepted, job)
}
