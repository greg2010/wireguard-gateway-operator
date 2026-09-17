package e2e

import "testing"

func TestReplacementServing(t *testing.T) {
	tests := []struct {
		name        string
		members     []MIGMember
		previous    map[string]string
		want        int32
		minReplaced int
		serving     bool
	}{
		{
			name: "healthy fleet with required replacements",
			members: []MIGMember{
				{Name: "gateway-a", BootDiskID: "new-a", Health: "HEALTHY", Serving: true},
				{Name: "gateway-b", BootDiskID: "new-b", Health: "HEALTHY", Serving: true},
			},
			previous:    map[string]string{"gateway-a": "old-a", "gateway-b": "old-b"},
			want:        2,
			minReplaced: 2,
			serving:     true,
		},
		{
			name: "healthy fleet with too few replacements",
			members: []MIGMember{
				{Name: "gateway-a", BootDiskID: "new-a", Health: "HEALTHY", Serving: true},
				{Name: "gateway-b", BootDiskID: "old-b", Health: "HEALTHY", Serving: true},
			},
			previous:    map[string]string{"gateway-a": "old-a", "gateway-b": "old-b"},
			want:        2,
			minReplaced: 2,
			serving:     false,
		},
		{
			name: "replaced member is not healthy",
			members: []MIGMember{
				{Name: "gateway-a", BootDiskID: "new-a", Health: "VERIFYING", Serving: true},
				{Name: "gateway-b", BootDiskID: "new-b", Health: "HEALTHY", Serving: true},
			},
			previous:    map[string]string{"gateway-a": "old-a", "gateway-b": "old-b"},
			want:        2,
			minReplaced: 1,
			serving:     false,
		},
		{
			name: "fleet has too few members",
			members: []MIGMember{
				{Name: "gateway-a", BootDiskID: "new-a", Health: "HEALTHY", Serving: true},
			},
			previous:    map[string]string{"gateway-a": "old-a"},
			want:        2,
			minReplaced: 1,
			serving:     false,
		},
		{
			name: "missing boot disk is not replaced",
			members: []MIGMember{
				{Name: "gateway-a", Health: "HEALTHY", Serving: true},
			},
			previous:    map[string]string{"gateway-a": "old-a"},
			want:        1,
			minReplaced: 1,
			serving:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ReplacementServing(test.members, test.previous, test.want, test.minReplaced); got != test.serving {
				t.Errorf("replacement serving = %t, want %t", got, test.serving)
			}
		})
	}
}

func TestRolloutStateMatches(t *testing.T) {
	oldTemplate := "old"
	newTemplate := "new"
	for _, test := range []struct {
		name  string
		state RolloutState
		other RolloutState
		want  bool
	}{
		{
			name:  "old target ignores reached",
			state: RolloutState{Target: oldTemplate, Templates: []string{oldTemplate}, Reached: true},
			other: RolloutState{Target: oldTemplate, Templates: []string{oldTemplate}},
			want:  true,
		},
		{
			name:  "new target distinguishes reached",
			state: RolloutState{Target: newTemplate, Templates: []string{newTemplate}, Reached: true},
			other: RolloutState{Target: newTemplate, Templates: []string{newTemplate}},
		},
		{
			name:  "new target matches reached",
			state: RolloutState{Target: newTemplate, Templates: []string{newTemplate}, Reached: true},
			other: RolloutState{Target: newTemplate, Templates: []string{newTemplate}, Reached: true},
			want:  true,
		},
		{
			name:  "different template set",
			state: RolloutState{Target: newTemplate, Templates: []string{newTemplate}},
			other: RolloutState{Target: newTemplate, Templates: []string{oldTemplate}},
		},
		{
			name:  "different target",
			state: RolloutState{Target: newTemplate, Templates: []string{newTemplate}},
			other: RolloutState{Target: oldTemplate, Templates: []string{newTemplate}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.state.Matches(test.other, oldTemplate); got != test.want {
				t.Errorf("matches() = %v, want %v", got, test.want)
			}
		})
	}
}
