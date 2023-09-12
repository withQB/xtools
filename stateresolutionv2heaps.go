package xtools

import (
	"strings"

	"github.com/withqb/xtools/spec"
)

// A stateResV2ConflictedPowerLevel is used to sort the events by effective
// power level, origin server TS and the lexicographical comparison of event
// IDs. It is a bit of an optimisation to use this - by working out the
// effective power level etc ahead of time, we use less CPU cycles during the
// sort.
type stateResV2ConflictedPowerLevel struct {
	powerLevel     int64
	originServerTS spec.Timestamp
	eventID        string
	event          PDU
}

// A stateResV2ConflictedPowerLevelHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedPowerLevelHeap []*stateResV2ConflictedPowerLevel

// Len implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Len() int {
	return len(s)
}

// Less implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Less(i, j int) bool {
	// Try to tiebreak on the effective power level
	if s[i].powerLevel > s[j].powerLevel {
		return true
	}
	if s[i].powerLevel < s[j].powerLevel {
		return false
	}
	// If we've reached here then s[i].powerLevel == s[j].powerLevel
	// so instead try to tiebreak on origin server TS
	if s[i].originServerTS < s[j].originServerTS {
		return false
	}
	if s[i].originServerTS > s[j].originServerTS {
		return true
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) > 0
}

// Swap implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Push implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Push(x interface{}) {
	*s = append(*s, x.(*stateResV2ConflictedPowerLevel))
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[:n-1]
	return x
}

// A stateResV2ConflictedOther is used to sort the events by power level
// mainline positions, origin server TS and the lexicographical comparison of
// event IDs. It is a bit of an optimisation to use this - by working out the
// effective power level etc ahead of time, we use less CPU cycles during the
// sort.
type stateResV2ConflictedOther struct {
	mainlinePosition int
	mainlineSteps    int
	originServerTS   spec.Timestamp
	eventID          string
	event            PDU
}

// A stateResV2ConflictedOtherHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedOtherHeap []*stateResV2ConflictedOther

// Len implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Len() int {
	return len(s)
}

// Less implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Less(i, j int) bool {
	// Try to tiebreak on the mainline position
	if s[i].mainlinePosition < s[j].mainlinePosition {
		return true
	}
	if s[i].mainlinePosition > s[j].mainlinePosition {
		return false
	}
	// If we've reached here then s[i].mainlinePosition == s[j].mainlinePosition
	// so instead try to tiebreak on step count
	if s[i].mainlineSteps < s[j].mainlineSteps {
		return true
	}
	if s[i].mainlineSteps > s[j].mainlineSteps {
		return false
	}
	// If we've reached here then s[i].mainlineSteps == s[j].mainlineSteps
	// so instead try to tiebreak on origin server TS
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	if s[i].originServerTS > s[j].originServerTS {
		return false
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

// Swap implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Push implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Push(x interface{}) {
	*s = append(*s, x.(*stateResV2ConflictedOther))
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[:n-1]
	return x
}
