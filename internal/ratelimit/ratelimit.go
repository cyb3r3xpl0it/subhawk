package ratelimit

import "time"

type Limiter struct {
	ticker *time.Ticker
	done   chan struct{}
}

func New(rps int) *Limiter {
	if rps <= 0 {
		return nil
	}
	l := &Limiter{
		ticker: time.NewTicker(time.Second / time.Duration(rps)),
		done:   make(chan struct{}),
	}
	return l
}

func (l *Limiter) Wait() {
	if l == nil {
		return
	}
	<-l.ticker.C
}

func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	l.ticker.Stop()
}
