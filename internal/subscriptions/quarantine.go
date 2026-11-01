package subscriptions

import (
	"regexp"
	"sort"
)

var profileRef = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// Promotion describes whether a candidate may replace the previous set.
// Removed contains only profile IDs; names, outbounds and other contents are
// never included in errors or returned metadata.
type Promotion struct {
	Allowed bool
	Reason  string
	Removed []string
}

// Assess compares profile identities before a candidate replaces previous.
// It is a pure assessment: caller-side review and revision binding are handled
// by the persistence layer, which must also honor referenced removals.
func Assess(previous, candidate []Profile, referenced map[string]bool) (Promotion, error) {
	if len(referenced) > MaxProfiles {
		return Promotion{}, ErrInvalid
	}
	if err := validateIdentities(previous); err != nil {
		return Promotion{}, err
	}
	if err := validateIdentities(candidate); err != nil {
		return Promotion{}, err
	}
	if len(candidate) == 0 {
		return Promotion{Reason: "empty_candidate"}, nil
	}

	candidateIDs := make(map[string]struct{}, len(candidate))
	for _, profile := range candidate {
		candidateIDs[profile.ID] = struct{}{}
	}

	var removed []string
	for _, profile := range previous {
		if _, ok := candidateIDs[profile.ID]; !ok {
			removed = append(removed, profile.ID)
		}
	}
	sort.Strings(removed)

	for _, id := range removed {
		if referenced[id] {
			return Promotion{Reason: "referenced_profile_removed", Removed: removed}, nil
		}
	}
	if len(previous) > 0 && len(removed)*5 > len(previous) {
		return Promotion{Reason: "excessive_removal", Removed: removed}, nil
	}
	return Promotion{Allowed: true, Reason: "accepted", Removed: removed}, nil
}

func validateIdentities(profiles []Profile) error {
	if len(profiles) > MaxProfiles {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if !profileRef.MatchString(profile.ID) {
			return ErrInvalid
		}
		if _, ok := seen[profile.ID]; ok {
			return ErrAmbiguous
		}
		seen[profile.ID] = struct{}{}
	}
	return nil
}
