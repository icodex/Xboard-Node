package kernel

import (
	"strings"

	"github.com/cedar2025/xboard-node/internal/model"
)

// NeedsGeoIP returns true when any panel route rule contains a "geoip:" match entry.
func NeedsGeoIP(routes []model.RouteRule) bool {
	for _, r := range routes {
		for _, m := range r.Match {
			if strings.HasPrefix(m, "geoip:") {
				return true
			}
		}
	}
	return false
}

// NeedsGeoSite returns true when any panel route rule contains a "geosite:" match entry.
func NeedsGeoSite(routes []model.RouteRule) bool {
	for _, r := range routes {
		for _, m := range r.Match {
			if strings.HasPrefix(m, "geosite:") {
				return true
			}
		}
	}
	return false
}

// NeedsGeoIPForNode reports whether any route source in the spec references a
// geoip database: panel routes, structured custom rules, or raw rules (which
// are passed through to xray verbatim). Missing this for custom rules made the
// kernel fail at start while validation had accepted the config.
func NeedsGeoIPForNode(nc *model.NodeSpec) bool {
	if nc == nil {
		return false
	}
	if NeedsGeoIP(nc.Routes) || NeedsGeoIPRules(nc.CustomRouteRules) {
		return true
	}
	return rawRulesReference(nc.CustomRoutes, "geoip:")
}

// NeedsGeoSiteForNode is the geosite counterpart of NeedsGeoIPForNode.
func NeedsGeoSiteForNode(nc *model.NodeSpec) bool {
	if nc == nil {
		return false
	}
	if NeedsGeoSite(nc.Routes) || NeedsGeoSiteRules(nc.CustomRouteRules) {
		return true
	}
	return rawRulesReference(nc.CustomRoutes, "geosite:")
}

func rawRulesReference(rules []map[string]any, prefix string) bool {
	for _, rule := range rules {
		if valueReferences(rule, prefix) {
			return true
		}
	}
	return false
}

func valueReferences(v any, prefix string) bool {
	switch x := v.(type) {
	case string:
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(x)), prefix)
	case []any:
		for _, item := range x {
			if valueReferences(item, prefix) {
				return true
			}
		}
	case []string:
		for _, item := range x {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(item)), prefix) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if valueReferences(item, prefix) {
				return true
			}
		}
	}
	return false
}
