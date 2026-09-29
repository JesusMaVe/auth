package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)} }

func TestBurstThenDeny(t *testing.T) {
	c := newClock()
	k := New(60, 3, c.now)
	for i := range 3 {
		if !k.Allow("alice") {
			t.Fatalf("la petición %d debía pasar", i+1)
		}
	}
	if k.Allow("alice") {
		t.Fatal("la cuarta petición debía rechazarse")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	k := New(60, 1, newClock().now)
	if !k.Allow("alice") || !k.Allow("bob") {
		t.Fatal("cada clave tiene su propio cupo")
	}
	if k.Allow("alice") {
		t.Fatal("alice ya agotó su cupo")
	}
}

func TestRefills(t *testing.T) {
	c := newClock()
	k := New(60, 1, c.now) // 1 por segundo
	k.Allow("alice")
	if k.Allow("alice") {
		t.Fatal("sin cupo inmediatamente después")
	}
	c.advance(time.Second)
	if !k.Allow("alice") {
		t.Fatal("tras 1 s debe haber cupo de nuevo")
	}
}

func TestSweepsIdleKeys(t *testing.T) {
	c := newClock()
	k := New(60, 5, c.now)
	for i := range 1000 {
		k.Allow(fmt.Sprintf("user-%d", i))
	}
	c.advance(10 * time.Minute)
	k.Allow("otro")
	if n := len(k.entries); n != 1 {
		t.Fatalf("quedaron %d entradas; las inactivas deben barrerse", n)
	}
}
