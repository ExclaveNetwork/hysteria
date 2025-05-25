package utils

import (
	"sync/atomic"
	"time"
)

var atomicTimeBase = time.Now()

// AtomicTime stores a time as an offset from atomicTimeBase, so that Set does not allocate.
type AtomicTime struct {
	v atomic.Int64
}

func NewAtomicTime(t time.Time) *AtomicTime {
	a := &AtomicTime{}
	a.Set(t)
	return a
}

func (t *AtomicTime) Set(new time.Time) {
	t.v.Store(int64(new.Sub(atomicTimeBase)))
}

func (t *AtomicTime) Get() time.Time {
	return atomicTimeBase.Add(time.Duration(t.v.Load()))
}
