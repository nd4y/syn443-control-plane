package configuration

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

type TrafficQuery struct {
	Domain            string `json:"domain,omitempty"`
	Address           string `json:"address,omitempty"`
	DomainUnavailable bool   `json:"domainUnavailable,omitempty"`
	Application       string `json:"application,omitempty"`
	Port              int    `json:"port,omitempty"`
	Network           string `json:"network,omitempty"`
	DNSType           string `json:"dnsType,omitempty"`
}

func (TrafficQuery) String() string   { return "TrafficQuery([redacted])" }
func (TrafficQuery) GoString() string { return "TrafficQuery([redacted])" }

type RuleDecision struct {
	Status string `json:"status"`
	Rule   string `json:"rule,omitempty"`
	Target string `json:"target,omitempty"`
}

type TrafficExplanation struct {
	Route RuleDecision `json:"route"`
	DNS   RuleDecision `json:"dns"`
}

// A missing connection fact cannot promote a lower-priority route over an
// earlier candidate. AND takes the lesser value and OR the greater one.
type ruleMatch int

const (
	noMatch ruleMatch = iota
	missingFact
	confirmedMatch
)

func matched(ok bool) ruleMatch {
	if ok {
		return confirmedMatch
	}
	return noMatch
}

func listed(value string, allowed []string) ruleMatch {
	if len(allowed) == 0 {
		return confirmedMatch
	}
	if value == "" {
		return missingFact
	}
	return matched(slices.Contains(allowed, value))
}

func destinationMatch(q TrafficQuery, address netip.Addr, h HostMatch, prefixes []string) ruleMatch {
	hasDomain := len(h.Domains)+len(h.DomainSuffixes)+len(h.DomainKeywords)+len(h.DomainRegex) > 0
	if !hasDomain && len(prefixes) == 0 {
		return confirmedMatch
	}
	out := noMatch
	if hasDomain && q.Domain == "" && (!address.IsValid() || q.DomainUnavailable) {
		out = missingFact
	}
	if q.Domain != "" {
		if slices.Contains(h.Domains, q.Domain) {
			return confirmedMatch
		}
		for _, suffix := range h.DomainSuffixes {
			root := strings.TrimPrefix(suffix, ".")
			if q.Domain == suffix || strings.HasSuffix(q.Domain, "."+root) {
				return confirmedMatch
			}
		}
		for _, keyword := range h.DomainKeywords {
			if strings.Contains(q.Domain, keyword) {
				return confirmedMatch
			}
		}
		for _, pattern := range h.DomainRegex {
			// routeConditions/dnsConditions already compiled every expression.
			if ok, _ := regexp.MatchString(pattern, q.Domain); ok {
				return confirmedMatch
			}
		}
	}
	if len(prefixes) > 0 && !address.IsValid() {
		return missingFact
	}
	for _, prefix := range prefixes {
		p, _ := netip.ParsePrefix(prefix)
		if p.Contains(address) {
			return confirmedMatch
		}
	}
	return out
}

func portMatch(port int, ranges []PortRange) ruleMatch {
	if len(ranges) == 0 {
		return confirmedMatch
	}
	if port == 0 {
		return missingFact
	}
	for _, r := range ranges {
		if port >= r.First && port <= r.Last {
			return confirmedMatch
		}
	}
	return noMatch
}

func ruleDecision(match ruleMatch, rule, target string) RuleDecision {
	if match == missingFact {
		return RuleDecision{Status: "incomplete", Rule: rule}
	}
	return RuleDecision{Status: "matched", Rule: rule, Target: target}
}

// ExplainTraffic models the portable predicates in their compiled order. It
// accepts a literal IP, a hostname, a hostname with a supplied resolution, or
// an application alone. No resolver or runtime selector runs for this preview.
func ExplainTraffic(s NetworkSettings, final string, q TrafficQuery) (TrafficExplanation, error) {
	var result TrafficExplanation
	if s.SchemaVersion != 1 || !id.MatchString(final) || !id.MatchString(s.DNSFinal) || len(s.Rules) > 128 || len(s.DNSRules) > 64 ||
		q.DomainUnavailable && (q.Address == "" || q.Domain != "") ||
		q.Domain == "" && q.Address == "" && q.Application == "" || q.Port < 0 || q.Port > 65535 ||
		q.Network != "" && q.Network != "tcp" && q.Network != "udp" || q.DNSType != "" && !validDNSQueryType(q.DNSType) ||
		q.Application != "" && (len(q.Application) > 255 || !androidPackage.MatchString(q.Application)) {
		return result, ErrInvalid
	}
	if q.Domain != "" {
		if len(q.Domain) > 254 || strings.IndexFunc(q.Domain, func(r rune) bool { return r > 127 }) >= 0 {
			return result, ErrInvalid
		}
		q.Domain = strings.TrimSuffix(strings.ToLower(q.Domain), ".")
		if !networkHost(q.Domain, false) {
			return result, ErrInvalid
		}
	}
	var address netip.Addr
	if q.Address != "" {
		var err error
		address, err = netip.ParseAddr(q.Address)
		if err != nil || address.Zone() != "" {
			return result, ErrInvalid
		}
	}
	seen := make(map[string]bool)
	for _, rule := range s.Rules {
		_, err := routeConditions(rule)
		if err != nil || seen[rule.ID] || !(rule.Action == "route" && id.MatchString(rule.Outbound) || rule.Action == "reject" && rule.Outbound == "") {
			return TrafficExplanation{}, ErrInvalid
		}
		seen[rule.ID] = true
		if result.Route.Status != "" {
			continue
		}
		m := min(listed(q.Application, rule.Packages), listed(q.Network, rule.Networks), portMatch(q.Port, rule.Ports))
		if m != noMatch {
			m = min(m, destinationMatch(q, address, rule.HostMatch, rule.IPPrefixes))
		}
		if m != noMatch {
			result.Route = ruleDecision(m, rule.ID, rule.Outbound)
		}
	}
	if result.Route.Status == "" {
		result.Route = RuleDecision{Status: "default", Target: final}
	}
	if q.Domain == "" {
		result.DNS = RuleDecision{Status: "incomplete"}
		if address.IsValid() && !q.DomainUnavailable {
			result.DNS = RuleDecision{Status: "not_applicable"}
		}
	}
	clear(seen)
	for _, rule := range s.DNSRules {
		_, err := dnsConditions(rule)
		if err != nil || seen[rule.ID] || !id.MatchString(rule.Server) {
			return TrafficExplanation{}, ErrInvalid
		}
		seen[rule.ID] = true
		if result.DNS.Status != "" {
			continue
		}
		m := min(listed(q.DNSType, rule.QueryTypes), destinationMatch(q, address, rule.HostMatch, nil))
		if m != noMatch {
			result.DNS = ruleDecision(m, rule.ID, rule.Server)
		}
	}
	if result.DNS.Status == "" {
		result.DNS = RuleDecision{Status: "default", Target: s.DNSFinal}
	}
	return result, nil
}
