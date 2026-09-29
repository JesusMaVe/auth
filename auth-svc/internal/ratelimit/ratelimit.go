// Package ratelimit limita peticiones por clave (IP o usuario) con un token bucket por clave.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sweepEvery es cada cuánto se revisan las claves inactivas (detalle interno, no configuración).
const sweepEvery = time.Minute

type Keyed struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	idle      time.Duration // tras este tiempo sin uso el bucket está lleno: borrarlo no cambia nada
	now       func() time.Time
	entries   map[string]*entry
	lastSweep time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func New(perMinute, burst int, now func() time.Time) *Keyed {
	limit := rate.Limit(float64(perMinute) / 60)
	return &Keyed{
		limit:     limit,
		burst:     burst,
		idle:      time.Duration(float64(burst) / float64(limit) * float64(time.Second)),
		now:       now,
		entries:   map[string]*entry{},
		lastSweep: now(),
	}
}

func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	k.sweep(now)
	e, ok := k.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(k.limit, k.burst)}
		k.entries[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

func (k *Keyed) sweep(now time.Time) {
	if now.Sub(k.lastSweep) < sweepEvery {
		return
	}
	k.lastSweep = now
	for key, e := range k.entries {
		if now.Sub(e.seen) >= k.idle {
			delete(k.entries, key)
		}
	}
}
