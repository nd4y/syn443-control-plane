package catalog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func adaptiveSelectionRefs(count int) []ProfileReference {
	refs := make([]ProfileReference, count)
	for i := range refs {
		refs[i] = ProfileReference{SourceID: "source-a", ProfileID: fmt.Sprintf("profile-%03d", i)}
	}
	return refs
}

func TestAdaptiveSelectionBoundsKeepOrdinary64AndUnion532Distinct(t *testing.T) {
	now := time.Unix(1800000000, 0)
	target := SelectionTarget{Owner: "user-a", Device: "device-a"}
	for _, count := range []int{1, 64} {
		if err := validSelection(target, adaptiveSelectionRefs(count), "wifi", now.Unix()+3600, now); err != nil {
			t.Fatal("ordinary boundary rejected", err)
		}
	}
	if err := validSelection(target, adaptiveSelectionRefs(65), "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("ordinary selection silently widened", err)
	}
	for _, count := range []int{1, 65, 500, 532} {
		if err := validSelectionBound(target, adaptiveSelectionRefs(count), "wifi", now.Unix()+3600, now, 532); err != nil {
			t.Fatal("adaptive union boundary rejected", err)
		}
	}
	for _, count := range []int{0, 533} {
		if err := validSelectionBound(target, adaptiveSelectionRefs(count), "wifi", now.Unix()+3600, now, 532); !errors.Is(err, ErrInvalid) {
			t.Fatal("adaptive reference quota escaped", err)
		}
	}
	for _, limit := range []int{-1, 0, 63, 65, 500, 531, 533, 10000} {
		if err := validSelectionBound(target, adaptiveSelectionRefs(1), "wifi", now.Unix()+3600, now, limit); !errors.Is(err, ErrInvalid) {
			t.Fatal("arbitrary internal limit accepted", err)
		}
	}
}

func TestAdaptiveSelectionRetainsSourceIdentityModeExpiryAndDuplicateFences(t *testing.T) {
	now := time.Unix(1800000000, 0)
	target := SelectionTarget{Owner: "user-a", Device: "device-a"}
	for _, count := range []int{32, 33} {
		refs := adaptiveSelectionRefs(count)
		for i := range refs {
			refs[i].SourceID = fmt.Sprintf("source-%02d", i)
		}
		err := validSelectionBound(target, refs, "wifi", now.Unix()+3600, now, 532)
		if count == 32 && err != nil || count == 33 && !errors.Is(err, ErrQuota) {
			t.Fatal("source32 boundary changed", err)
		}
	}
	for _, mutate := range []func(*SelectionTarget, *[]ProfileReference, *string, *int64){
		func(t *SelectionTarget, _ *[]ProfileReference, _ *string, _ *int64) { t.Owner = "" },
		func(t *SelectionTarget, _ *[]ProfileReference, _ *string, _ *int64) { t.Device = "../device" },
		func(_ *SelectionTarget, r *[]ProfileReference, _ *string, _ *int64) { (*r)[1] = (*r)[0] },
		func(_ *SelectionTarget, r *[]ProfileReference, _ *string, _ *int64) {
			(*r)[0].SourceID = "https://source.example.invalid"
		},
		func(_ *SelectionTarget, r *[]ProfileReference, _ *string, _ *int64) { (*r)[0].ProfileID = "../profile" },
		func(_ *SelectionTarget, _ *[]ProfileReference, m *string, _ *int64) { *m = "unknown" },
		func(_ *SelectionTarget, _ *[]ProfileReference, _ *string, u *int64) { *u = now.Unix() },
		func(_ *SelectionTarget, _ *[]ProfileReference, _ *string, u *int64) { *u = now.Unix() + 604801 },
	} {
		current, refs, mode, until := target, adaptiveSelectionRefs(2), "wifi", now.Unix()+3600
		mutate(&current, &refs, &mode, &until)
		if err := validSelectionBound(current, refs, mode, until, now, 532); err == nil {
			t.Fatal("adaptive selection widened its authority")
		}
	}
	var absent *Store
	if _, err := absent.PrepareAdaptiveSelection(context.Background(), target, adaptiveSelectionRefs(1), "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent selection store accepted", err)
	}
	if _, err := (&Store{}).PrepareAdaptiveSelection(nil, target, adaptiveSelectionRefs(1), "wifi", now.Unix()+3600, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context accepted", err)
	}
}
