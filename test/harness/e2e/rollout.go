package e2e

import (
	"fmt"
	"slices"
	"strings"
)

// MIGMember records a managed instance's identity, network address, health, and serving state.
type MIGMember struct {
	Name       string
	BootDiskID string
	NATIP      string
	Health     string
	Serving    bool
}

// ReplacementServing reports whether the fleet has the requested members, each healthy and serving,
// with at least minReplaced members using a different non-empty boot disk than previous.
func ReplacementServing(members []MIGMember, previous map[string]string, want int32, minReplaced int) bool {
	if len(members) != int(want) {
		return false
	}
	replaced := 0
	for _, member := range members {
		if !member.Serving || member.Health != "HEALTHY" {
			return false
		}
		if previousID, found := previous[member.Name]; found && member.BootDiskID != "" && member.BootDiskID != previousID {
			replaced++
		}
	}
	return replaced >= minReplaced
}

// RolloutState records the version target, observed template set, and version-target rollup.
type RolloutState struct {
	Target    string
	Templates []string
	Reached   bool
}

// Matches compares rollout observations, ignoring Reached while both target the old template.
func (s RolloutState) Matches(other RolloutState, oldTemplate string) bool {
	return s.Target == other.Target && slices.Equal(s.Templates, other.Templates) &&
		(s.Target == oldTemplate || s.Reached == other.Reached)
}

// String formats a rollout observation for failure messages.
func (s RolloutState) String() string {
	return fmt.Sprintf("(target %s, templates %v, reached %v)", s.Target, s.Templates, s.Reached)
}

// RolloutStateList renders rollout states for a failure message.
func RolloutStateList(states []RolloutState) string {
	parts := make([]string, 0, len(states))
	for _, state := range states {
		parts = append(parts, state.String())
	}
	return strings.Join(parts, ", ")
}

// RolloutStates orders states from the old template to the new template's completed rollup.
func RolloutStates(oldTemplate, newTemplate string) []RolloutState {
	rolling := []string{oldTemplate, newTemplate}
	slices.Sort(rolling)
	return []RolloutState{
		{Target: oldTemplate, Templates: []string{oldTemplate}},
		{Target: oldTemplate, Templates: rolling},
		{Target: newTemplate, Templates: rolling},
		{Target: newTemplate, Templates: rolling, Reached: true},
		{Target: newTemplate, Templates: []string{newTemplate}, Reached: true},
	}
}
