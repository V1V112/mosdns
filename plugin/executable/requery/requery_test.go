package requery

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeSchedulerTimer struct {
	c       chan time.Time
	stopped chan struct{}
	mu      sync.Mutex
	isStop  bool
	delay   time.Duration
}

func newFakeSchedulerTimer(delay time.Duration) *fakeSchedulerTimer {
	return &fakeSchedulerTimer{
		c:       make(chan time.Time, 1),
		stopped: make(chan struct{}),
		delay:   delay,
	}
}

func (t *fakeSchedulerTimer) Chan() <-chan time.Time {
	return t.c
}

func (t *fakeSchedulerTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isStop {
		return false
	}
	t.isStop = true
	close(t.stopped)
	return true
}

func (t *fakeSchedulerTimer) fire(at time.Time) {
	select {
	case t.c <- at:
	default:
	}
}

type fakeTimerFactory struct {
	created chan *fakeSchedulerTimer
}

func newFakeTimerFactory() *fakeTimerFactory {
	return &fakeTimerFactory{created: make(chan *fakeSchedulerTimer, 8)}
}

func (f *fakeTimerFactory) New(delay time.Duration) schedulerTimer {
	timer := newFakeSchedulerTimer(delay)
	f.created <- timer
	return timer
}

func (f *fakeTimerFactory) next(t *testing.T) *fakeSchedulerTimer {
	t.Helper()
	select {
	case timer := <-f.created:
		return timer
	case <-time.After(time.Second):
		t.Fatal("scheduler did not create a timer")
		return nil
	}
}

func newTestRequery(t *testing.T, scheduler SchedulerConfig) *Requery {
	t.Helper()
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	p := &Requery{
		filePath:        filepath.Join(t.TempDir(), "requery.json"),
		config:          &Config{Scheduler: scheduler, Status: Status{TaskState: "idle"}},
		httpClient:      &http.Client{},
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		scheduleChanged: make(chan struct{}, 1),
		now:             time.Now,
		newTimer: func(delay time.Duration) schedulerTimer {
			return &realSchedulerTimer{Timer: time.NewTimer(delay)}
		},
	}
	p.taskRunner = p.runTask
	return p
}

func TestNextScheduledRun(t *testing.T) {
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)

	if _, enabled, err := nextScheduledRun(now, SchedulerConfig{}); err != nil || enabled {
		t.Fatalf("disabled scheduler returned enabled=%v, err=%v", enabled, err)
	}

	future := now.Add(10 * time.Minute)
	next, enabled, err := nextScheduledRun(now, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   future.Format(time.RFC3339),
		IntervalMinutes: 30,
	})
	if err != nil || !enabled || !next.Equal(future) {
		t.Fatalf("future next run = %v, enabled=%v, err=%v", next, enabled, err)
	}

	start := now.Add(-95 * time.Minute)
	next, enabled, err = nextScheduledRun(now, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   start.Format(time.RFC3339),
		IntervalMinutes: 30,
	})
	want := start.Add(120 * time.Minute)
	if err != nil || !enabled || !next.Equal(want) {
		t.Fatalf("periodic next run = %v, want %v, enabled=%v, err=%v", next, want, enabled, err)
	}

	oversizedInterval := int((maxSchedulerDuration / time.Minute) + 1)
	_, enabled, err = nextScheduledRun(now, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   future.Format(time.RFC3339),
		IntervalMinutes: oversizedInterval,
	})
	if err == nil || enabled {
		t.Fatalf("oversized interval returned enabled=%v, err=%v", enabled, err)
	}

	tooOld := now.Add(-maxSchedulerDuration).Add(-time.Minute)
	_, enabled, err = nextScheduledRun(now, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   tooOld.Format(time.RFC3339),
		IntervalMinutes: 30,
	})
	if err == nil || enabled {
		t.Fatalf("too-old start returned enabled=%v, err=%v", enabled, err)
	}
}

func TestStaleScheduleGenerationCannotStartTask(t *testing.T) {
	p := newTestRequery(t, SchedulerConfig{Enabled: true})
	defer p.Close()
	started := make(chan struct{}, 1)
	p.taskRunner = func(context.Context, requeryTaskConfig) {
		started <- struct{}{}
	}

	staleGeneration := p.scheduleGeneration
	p.mu.Lock()
	p.scheduleGeneration++
	p.mu.Unlock()

	if err := p.startTask(&staleGeneration); !errors.Is(err, errScheduleChanged) {
		t.Fatalf("startTask() error = %v, want %v", err, errScheduleChanged)
	}
	select {
	case <-started:
		t.Fatal("obsolete schedule generation started a task")
	default:
	}
}

func TestSchedulerChangeStopsOldTimer(t *testing.T) {
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	p := newTestRequery(t, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   now.Add(time.Hour).Format(time.RFC3339),
		IntervalMinutes: 60,
	})
	factory := newFakeTimerFactory()
	p.now = func() time.Time { return now }
	p.newTimer = factory.New
	taskStarted := make(chan struct{}, 1)
	p.taskRunner = func(context.Context, requeryTaskConfig) {
		taskStarted <- struct{}{}
	}
	p.startScheduler()

	oldTimer := factory.next(t)
	p.mu.Lock()
	p.config.Scheduler.StartDatetime = now.Add(2 * time.Hour).Format(time.RFC3339)
	p.scheduleGeneration++
	p.mu.Unlock()
	p.notifyScheduleChanged()
	newTimer := factory.next(t)

	select {
	case <-oldTimer.stopped:
	case <-time.After(time.Second):
		t.Fatal("old timer was not stopped after schedule change")
	}
	if oldTimer == newTimer {
		t.Fatal("schedule change reused the old timer")
	}

	// Simulate a stale timer event racing with Stop. The scheduler no longer
	// selects this channel, so the obsolete event must not start a task.
	oldTimer.fire(now.Add(time.Hour))
	select {
	case <-taskStarted:
		t.Fatal("obsolete timer started a task")
	case <-time.After(50 * time.Millisecond):
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-newTimer.stopped:
	default:
		t.Fatal("Close returned without stopping the active timer")
	}
}

func TestDisablingSchedulerStopsTimer(t *testing.T) {
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	p := newTestRequery(t, SchedulerConfig{
		Enabled:         true,
		StartDatetime:   now.Add(time.Hour).Format(time.RFC3339),
		IntervalMinutes: 60,
	})
	factory := newFakeTimerFactory()
	p.now = func() time.Time { return now }
	p.newTimer = factory.New
	p.startScheduler()

	timer := factory.next(t)
	p.mu.Lock()
	p.config.Scheduler.Enabled = false
	p.scheduleGeneration++
	p.mu.Unlock()
	p.notifyScheduleChanged()

	select {
	case <-timer.stopped:
	case <-time.After(time.Second):
		t.Fatal("timer was not stopped after scheduler was disabled")
	}
	select {
	case unexpected := <-factory.created:
		t.Fatalf("disabled scheduler created another timer with delay %v", unexpected.delay)
	case <-time.After(50 * time.Millisecond):
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseCancelsTaskAndWaits(t *testing.T) {
	p := newTestRequery(t, SchedulerConfig{})
	started := make(chan struct{})
	cancelled := make(chan struct{})
	allowExit := make(chan struct{})
	var allowExitOnce sync.Once
	releaseTask := func() {
		allowExitOnce.Do(func() { close(allowExit) })
	}
	t.Cleanup(func() {
		releaseTask()
		_ = p.Close()
	})
	p.taskRunner = func(ctx context.Context, _ requeryTaskConfig) {
		close(started)
		<-ctx.Done()
		p.mu.Lock()
		p.mu.Unlock()
		close(cancelled)
		<-allowExit
	}

	if err := p.startTask(nil); err != nil {
		t.Fatalf("startTask() error = %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task did not start")
	}

	closeReturned := make(chan error, 1)
	go func() { closeReturned <- p.Close() }()

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("task did not observe cancellation")
	}
	select {
	case err := <-closeReturned:
		t.Fatalf("Close returned before task exited: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseTask()
	select {
	case err := <-closeReturned:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for the task to exit")
	}
}

func TestStartTaskClaimsSlotBeforeGoroutineRuns(t *testing.T) {
	p := newTestRequery(t, SchedulerConfig{})
	releaseTask := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseTask) })
	}
	t.Cleanup(func() {
		release()
		_ = p.Close()
	})
	p.taskRunner = func(context.Context, requeryTaskConfig) {
		<-releaseTask
	}

	if err := p.startTask(nil); err != nil {
		t.Fatalf("first startTask() error = %v", err)
	}
	if err := p.startTask(nil); !errors.Is(err, errTaskRunning) {
		t.Fatalf("second startTask() error = %v, want %v", err, errTaskRunning)
	}
	release()
}

func TestCloseIsIdempotent(t *testing.T) {
	p := newTestRequery(t, SchedulerConfig{})
	p.startScheduler()

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- p.Close()
		}()
	}
	allReturned := make(chan struct{})
	go func() {
		wg.Wait()
		close(allReturned)
	}()
	select {
	case <-allReturned:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close calls did not return")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}

	if err := p.startTask(nil); !errors.Is(err, errRequeryClosed) {
		t.Fatalf("startTask() after Close error = %v, want %v", err, errRequeryClosed)
	}
}

func TestTaskErrorStateUsesTaskContext(t *testing.T) {
	p := newTestRequery(t, SchedulerConfig{})
	p.setTaskError(context.Background(), "url call", context.DeadlineExceeded)
	if got := p.config.Status.TaskState; got != "failed" {
		t.Fatalf("independent timeout state = %q, want failed", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.setTaskError(ctx, "url call", context.Canceled)
	if got := p.config.Status.TaskState; got != "cancelled" {
		t.Fatalf("cancelled task state = %q, want cancelled", got)
	}
}
