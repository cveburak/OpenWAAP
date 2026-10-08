package lifecycle

import "fmt"

type State string

const (
	StateDraft      State = "DRAFT"
	StateTesting    State = "TESTING"
	StateMonitoring State = "MONITORING"
	StateActive     State = "ACTIVE"
	StateDisabled   State = "DISABLED"
	StateRetired    State = "RETIRED"
)

var AllStates = []State{StateDraft, StateTesting, StateMonitoring, StateActive, StateDisabled, StateRetired}

func (s State) Valid() bool {
	for _, st := range AllStates {
		if s == st {
			return true
		}
	}
	return false
}

var Transitions = map[State][]State{
	StateDraft:      {StateTesting, StateDisabled, StateRetired},
	StateTesting:    {StateMonitoring, StateActive, StateDraft, StateDisabled, StateRetired},
	StateMonitoring: {StateActive, StateTesting, StateDisabled, StateRetired},
	StateActive:     {StateDisabled, StateMonitoring, StateRetired},
	StateDisabled:   {StateActive, StateDraft, StateTesting, StateRetired},
	StateRetired:    {},
}

func CanTransition(from, to State) (bool, error) {
	if !from.Valid() || !to.Valid() {
		return false, fmt.Errorf("invalid state transition: %s -> %s", from, to)
	}
	for _, ok := range Transitions[from] {
		if ok == to {
			return true, nil
		}
	}
	return false, fmt.Errorf("illegal lifecycle transition: %s -> %s", from, to)
}

func (s State) Enforced() bool { return s == StateActive }
