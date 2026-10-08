package lifecycle

import "testing"

func TestValidStates(t *testing.T) {
	for _, s := range AllStates {
		if !s.Valid() {
			t.Fatalf("expected %s to be valid", s)
		}
	}
	if State("BOGUS").Valid() {
		t.Fatal("bogus state should be invalid")
	}
}

func TestLegalTransitions(t *testing.T) {
	legal := [][2]State{
		{StateDraft, StateTesting},
		{StateTesting, StateMonitoring},
		{StateMonitoring, StateActive},
		{StateTesting, StateActive},
		{StateActive, StateDisabled},
		{StateDisabled, StateActive},
	}
	for _, tr := range legal {
		ok, err := CanTransition(tr[0], tr[1])
		if err != nil || !ok {
			t.Fatalf("expected %s -> %s to be legal, got err=%v", tr[0], tr[1], err)
		}
	}
}

func TestIllegalTransitions(t *testing.T) {
	illegal := [][2]State{
		{StateActive, StateDraft},
		{StateRetired, StateActive},
		{StateDraft, StateActive},
	}
	for _, tr := range illegal {
		if ok, _ := CanTransition(tr[0], tr[1]); ok {
			t.Fatalf("expected %s -> %s to be illegal", tr[0], tr[1])
		}
	}
}

func TestEnforcedOnlyActive(t *testing.T) {
	for _, s := range AllStates {
		if s == StateActive && !s.Enforced() {
			t.Fatalf("active should be enforced")
		}
		if s != StateActive && s.Enforced() {
			t.Fatalf("%s should not be enforced", s)
		}
	}
}
