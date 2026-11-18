package kernel

import (
	"encoding/json"
	"strings"

	"github.com/cedar2025/xboard-node/internal/model"
)

// DecodeCustomRouteRule decodes a structured match/action raw entry into the
// model rule both kernel builders compile. Field names match case-insensitively
// (encoding/json), mirroring the panel's custom_route_rules shape.
func DecodeCustomRouteRule(rule map[string]any) (model.CustomRouteRule, error) {
	var parsed model.CustomRouteRule
	data, err := json.Marshal(rule)
	if err != nil {
		return parsed, err
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return parsed, err
	}
	return parsed, nil
}

func NeedsGeoIPRules(rules []model.CustomRouteRule) bool {
	for _, r := range rules {
		for _, v := range r.Match.IPCIDRs {
			if strings.HasPrefix(v, "geoip:") {
				return true
			}
		}
		for _, v := range r.Match.SourceCIDRs {
			if strings.HasPrefix(v, "geoip:") {
				return true
			}
		}
	}
	return false
}

func NeedsGeoSiteRules(rules []model.CustomRouteRule) bool {
	for _, r := range rules {
		for _, v := range r.Match.Domains {
			if strings.HasPrefix(v, "geosite:") {
				return true
			}
		}
		for _, v := range r.Match.DomainSuffixes {
			if strings.HasPrefix(v, "geosite:") {
				return true
			}
		}
	}
	return false
}
