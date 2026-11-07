package subscriptions

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestQuarantineAssessInitialAndIdentityChangesLocal(t *testing.T) {
	initial, err := Assess(nil, []Profile{
		{ID: "a", Name: "first", Kind: "vless"},
		{ID: "b", Name: "second", Kind: "ss"},
	}, nil)
	if err != nil {
		t.Fatalf("initial assessment failed: %v", err)
	}
	if !initial.Allowed || initial.Reason != "accepted" || len(initial.Removed) != 0 {
		t.Fatalf("initial assessment = %+v", initial)
	}

	previous := []Profile{
		{ID: "a", Name: "first", Kind: "vless", Outbound: []byte(`{"secret":"old"}`)},
		{ID: "b", Name: "second", Kind: "ss", Outbound: []byte(`{"secret":"old"}`)},
	}
	candidate := []Profile{
		{ID: "b", Name: "renamed", Kind: "trojan", Outbound: []byte(`{"secret":"new"}`)},
		{ID: "a", Name: "also-renamed", Kind: "ssh", Outbound: []byte(`{"secret":"new"}`)},
	}
	changed, err := Assess(previous, candidate, map[string]bool{"a": true, "b": true})
	if err != nil {
		t.Fatalf("identity assessment failed: %v", err)
	}
	if !changed.Allowed || changed.Reason != "accepted" || len(changed.Removed) != 0 {
		t.Fatalf("identity-preserving change = %+v", changed)
	}
}

func TestQuarantineAssessRemovalThresholdLocal(t *testing.T) {
	previous := assessLocalNumberedProfiles(10)
	atTwenty, err := Assess(previous, append([]Profile(nil), previous[:8]...), nil)
	if err != nil {
		t.Fatalf("20 percent assessment failed: %v", err)
	}
	if !atTwenty.Allowed || atTwenty.Reason != "accepted" {
		t.Fatalf("exactly 20 percent removed = %+v", atTwenty)
	}
	if want := []string{"p008", "p009"}; !reflect.DeepEqual(atTwenty.Removed, want) {
		t.Fatalf("20 percent removed = %v, want %v", atTwenty.Removed, want)
	}

	overTwenty, err := Assess(previous, append([]Profile(nil), previous[:7]...), nil)
	if err != nil {
		t.Fatalf("over-20 assessment failed: %v", err)
	}
	if overTwenty.Allowed || overTwenty.Reason != "excessive_removal" {
		t.Fatalf("over 20 percent removed = %+v", overTwenty)
	}
	if want := []string{"p007", "p008", "p009"}; !reflect.DeepEqual(overTwenty.Removed, want) {
		t.Fatalf("over-20 removed = %v, want %v", overTwenty.Removed, want)
	}
}

func TestQuarantineAssessReferencedRemovalWinsLocal(t *testing.T) {
	previous := assessLocalNumberedProfiles(10)

	underThreshold, err := Assess(previous, append([]Profile(nil), previous[:9]...), map[string]bool{"p009": true})
	if err != nil {
		t.Fatalf("referenced assessment failed: %v", err)
	}
	if underThreshold.Allowed || underThreshold.Reason != "referenced_profile_removed" {
		t.Fatalf("referenced removal = %+v", underThreshold)
	}

	overThreshold, err := Assess(previous, append([]Profile(nil), previous[:7]...), map[string]bool{"p008": true})
	if err != nil {
		t.Fatalf("referenced excessive assessment failed: %v", err)
	}
	if overThreshold.Allowed || overThreshold.Reason != "referenced_profile_removed" {
		t.Fatalf("referenced removal should win over excessive removal: %+v", overThreshold)
	}
}

func TestQuarantineAssessEmptyCandidateLocal(t *testing.T) {
	for _, previous := range [][]Profile{nil, assessLocalNumberedProfiles(3)} {
		got, err := Assess(previous, nil, nil)
		if err != nil {
			t.Fatalf("empty candidate assessment failed: %v", err)
		}
		if got.Allowed || got.Reason != "empty_candidate" {
			t.Fatalf("empty candidate = %+v", got)
		}
	}
}

func TestQuarantineAssessRejectsInvalidIdentitiesLocal(t *testing.T) {
	valid := []Profile{{ID: "valid"}}
	tests := []struct {
		name      string
		previous  []Profile
		candidate []Profile
		want      error
	}{
		{name: "empty previous ID", previous: []Profile{{ID: ""}}, candidate: valid, want: ErrInvalid},
		{name: "empty candidate ID", previous: nil, candidate: []Profile{{ID: ""}}, want: ErrInvalid},
		{name: "duplicate previous ID", previous: []Profile{{ID: "same"}, {ID: "same"}}, candidate: valid, want: ErrAmbiguous},
		{name: "duplicate candidate ID", previous: nil, candidate: []Profile{{ID: "same"}, {ID: "same"}}, want: ErrAmbiguous},
		{name: "previous capacity", previous: assessLocalNumberedProfiles(MaxProfiles + 1), candidate: valid, want: ErrInvalid},
		{name: "candidate capacity", previous: valid, candidate: assessLocalNumberedProfiles(MaxProfiles + 1), want: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Assess(test.previous, test.candidate, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestQuarantineAssessSortedRemovalsLocal(t *testing.T) {
	previous := []Profile{{ID: "z"}, {ID: "a"}}
	previous = append(previous, assessLocalNumberedProfiles(8)...)
	candidate := append([]Profile(nil), assessLocalNumberedProfiles(8)...)

	got, err := Assess(previous, candidate, map[string]bool{"p000": true})
	if err != nil {
		t.Fatalf("sorted-removal assessment failed: %v", err)
	}
	if !got.Allowed || got.Reason != "accepted" {
		t.Fatalf("sorted-removal assessment = %+v", got)
	}
	if want := []string{"a", "z"}; !reflect.DeepEqual(got.Removed, want) {
		t.Fatalf("sorted removals = %v, want %v", got.Removed, want)
	}
}

func assessLocalNumberedProfiles(n int) []Profile {
	profiles := make([]Profile, n)
	for i := range profiles {
		profiles[i] = Profile{ID: fmt.Sprintf("p%03d", i), Name: "generated", Kind: "vless"}
	}
	return profiles
}
