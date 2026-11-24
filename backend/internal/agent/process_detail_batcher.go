package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"sophon/internal/database"
)

const (
	processDetailBatchSize     = 64
	processDetailMaxPending    = 1024
	processDetailFlushInterval = 200 * time.Millisecond
	processDetailWriteTimeout  = 3 * time.Second
)

type processDetailBatcherContextKey struct{}

type processDetailBatcher struct {
	db            *database.DB
	batchSize     int
	maxPending    int
	flushInterval time.Duration

	mu        sync.Mutex
	flushMu   sync.Mutex
	pending   []database.ProcessDetail
	closed    bool
	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newProcessDetailBatcher(db *database.DB) *processDetailBatcher {
	return newProcessDetailBatcherWithConfig(
		db,
		processDetailBatchSize,
		processDetailMaxPending,
		processDetailFlushInterval,
	)
}

func newProcessDetailBatcherWithConfig(
	db *database.DB,
	batchSize int,
	maxPending int,
	flushInterval time.Duration,
) *processDetailBatcher {
	if db == nil {
		return nil
	}
	if batchSize <= 0 {
		batchSize = processDetailBatchSize
	}
	if maxPending <= 0 {
		maxPending = processDetailMaxPending
	}
	if flushInterval <= 0 {
		flushInterval = processDetailFlushInterval
	}
	batcher := &processDetailBatcher{
		db:            db,
		batchSize:     batchSize,
		maxPending:    maxPending,
		flushInterval: flushInterval,
		wake:          make(chan struct{}, 1),
		done:          make(chan struct{}),
	}
	batcher.wg.Add(1)
	go batcher.run()
	return batcher
}

func withProcessDetailBatcher(ctx context.Context, batcher *processDetailBatcher) context.Context {
	if batcher == nil {
		return ctx
	}
	return context.WithValue(ctx, processDetailBatcherContextKey{}, batcher)
}

func processDetailBatcherFromContext(ctx context.Context) *processDetailBatcher {
	batcher, _ := ctx.Value(processDetailBatcherContextKey{}).(*processDetailBatcher)
	return batcher
}

func (b *processDetailBatcher) Enqueue(ctx context.Context, detail database.ProcessDetail) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		writeCtx, cancel := processDetailWriteContext(ctx)
		defer cancel()
		return b.db.AddProcessDetails(writeCtx, []database.ProcessDetail{detail})
	}
	b.pending = append(b.pending, detail)
	pending := len(b.pending)
	b.mu.Unlock()

	if pending >= b.batchSize {
		b.signal()
	}
	if pending >= b.maxPending {
		writeCtx, cancel := processDetailWriteContext(ctx)
		defer cancel()
		return b.flush(writeCtx)
	}
	return nil
}

func (b *processDetailBatcher) signal() {
	if b == nil {
		return
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *processDetailBatcher) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-b.wake:
			b.flushBackground()
		case <-ticker.C:
			b.flushBackground()
		}
	}
}

func (b *processDetailBatcher) flushBackground() {
	writeCtx, cancel := context.WithTimeout(context.Background(), processDetailWriteTimeout)
	defer cancel()
	if err := b.flush(writeCtx); err != nil {
		log.Printf("agent: 批量保存过程明细失败，已回队重试: %v", err)
	}
}

func (b *processDetailBatcher) flush(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.flushMu.Lock()
	defer b.flushMu.Unlock()
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return nil
	}
	items := append([]database.ProcessDetail(nil), b.pending...)
	b.pending = nil
	b.mu.Unlock()

	if err := b.db.AddProcessDetails(ctx, items); err != nil {
		b.mu.Lock()
		b.pending = append(items, b.pending...)
		b.mu.Unlock()
		b.signal()
		return err
	}
	return nil
}

func (b *processDetailBatcher) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		close(b.done)
	})
	b.wg.Wait()
	writeCtx, cancel := processDetailWriteContext(ctx)
	defer cancel()
	if err := b.flush(writeCtx); err != nil {
		return fmt.Errorf("flush process details: %w", err)
	}
	return nil
}

func processDetailWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(base, processDetailWriteTimeout)
}
