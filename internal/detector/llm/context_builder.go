package llm

import (
	"fmt"
	"strings"

	"go-logshield/internal/normalizer"
)

// BehaviorContextBuilder collects normalized events and builds a natural language context string.
type BehaviorContextBuilder struct {
	windowSize int
	events     []normalizer.Event
}

// NewBehaviorContextBuilder creates a new ContextBuilder with a target sliding window size.
func NewBehaviorContextBuilder(windowSize int) *BehaviorContextBuilder {
	if windowSize <= 0 {
		windowSize = 10
	}
	return &BehaviorContextBuilder{
		windowSize: windowSize,
		events:     make([]normalizer.Event, 0, windowSize),
	}
}

// AddEvent pushes an event into the sliding window buffer.
func (b *BehaviorContextBuilder) AddEvent(ev normalizer.Event) {
	b.events = append(b.events, ev)
	if len(b.events) > b.windowSize {
		// Keep sliding window size
		b.events = b.events[1:]
	}
}

// Clear resets the buffer.
func (b *BehaviorContextBuilder) Clear() {
	b.events = b.events[:0]
}

// BuildContext converts the window's events into a natural language behavior context string.
// Modeled after the paper's behavior context format: "(N) At HH:MM:SS, Device/IP performed action..."
func (b *BehaviorContextBuilder) BuildContext() string {
	if len(b.events) == 0 {
		return "No behavior recorded."
	}

	var sb strings.Builder
	for i, ev := range b.events {
		line := fmt.Sprintf("(%d) At %s, IP %s performed service=%s action=%s status=%s user=%s path=%s\n",
			i+1,
			ev.TS.Format("15:04:05.000"),
			ev.IP,
			ev.Service,
			ev.Action,
			ev.Status,
			ev.User,
			ev.Path,
		)
		sb.WriteString(line)
	}
	return sb.String()
}

// IsFull returns true if the sliding window has collected enough events to evaluate.
func (b *BehaviorContextBuilder) IsFull() bool {
	return len(b.events) >= b.windowSize
}
