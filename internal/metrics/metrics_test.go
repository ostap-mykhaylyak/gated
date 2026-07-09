package metrics

import "testing"

func TestRequestLifecycle(t *testing.T) {
	m := New()

	done := m.RequestStart()
	snap := m.Snapshot()
	if snap.RequestsTotal != 1 || snap.RequestsInFlight != 1 {
		t.Fatalf("in-flight accounting broken: %+v", snap)
	}

	done(512, false)
	done2 := m.RequestStart()
	done2(0, true)

	snap = m.Snapshot()
	if snap.RequestsTotal != 2 || snap.RequestsInFlight != 0 {
		t.Fatalf("completion accounting broken: %+v", snap)
	}
	if snap.ErrorsTotal != 1 || snap.BytesOutTotal != 512 {
		t.Fatalf("error/bytes accounting broken: %+v", snap)
	}
}
