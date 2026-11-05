package route

import (
	"fmt"
	"sort"
	"strings"
)

// SanitizeRules validates raw custom_routes entries per form and returns the
// keepers plus one issue string per dropped rule. It never fails: the node
// must start with legacy or half-broken raw rules, dropping the bad ones with
// a log instead of rejecting the whole config.
//
// Form handling:
//   - structured (match/action): kept verbatim; the model layer validates and
//     the kernels compile it (callers handle it before this function or the
//     kernels re-detect it).
//   - xray: parsed and tag-checked for BOTH kernels (an unknown outboundTag
//     crashes either kernel and starts a reload loop), full shape whitelist.
//   - singbox: kept verbatim on the singbox kernel after a light check (the
//     running kernel is the authority); dropped on the xray kernel, which
//     cannot parse these keys.
//   - unknown: dropped with the offending keys listed.
//
// availableTags maps lowercased tags; a nil map skips the membership check.
func SanitizeRules(rules []map[string]any, kernelType string, availableTags map[string]struct{}, field string) (kept []map[string]any, keptIdx []int, issues []string) {
	kernelType = strings.ToLower(strings.TrimSpace(kernelType))
	kept = make([]map[string]any, 0, len(rules))
	keptIdx = make([]int, 0, len(rules))
	for i, rule := range rules {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		switch DetectForm(rule) {
		case FormStructured:
			// Kept verbatim: the model layer validates the match/action shape
			// (matchers required, action enum, route target tag) and the
			// kernels compile it like custom_route_rules entries.
			kept = append(kept, rule)
			keptIdx = append(keptIdx, i)
		case FormXray:
			if kernelType == "xray" {
				// Xray is the authority for its own rule shape: only the tag
				// reference is checked (balancerTag/protocol/etc. are legal).
				tag, err := outboundTagOf(rule)
				if err != nil {
					issues = append(issues, fmt.Sprintf("%s: %v", prefix, err))
					continue
				}
				if err := checkTag(tag, availableTags); err != nil {
					issues = append(issues, fmt.Sprintf("%s: %v", prefix, err))
					continue
				}
				kept = append(kept, rule)
				keptIdx = append(keptIdx, i)
				continue
			}
			parsed, err := ParseRule(rule)
			if err != nil {
				issues = append(issues, fmt.Sprintf("%s: %v", prefix, err))
				continue
			}
			if err := checkTag(parsed.OutboundTag, availableTags); err != nil {
				issues = append(issues, fmt.Sprintf("%s: %v", prefix, err))
				continue
			}
			kept = append(kept, rule)
			keptIdx = append(keptIdx, i)
		case FormSingbox:
			if kernelType == "xray" {
				issues = append(issues, fmt.Sprintf("%s: sing-box-native rule cannot run on the xray kernel (rule dropped); author it in Xray form or use the singbox kernel", prefix))
				continue
			}
			outbound, hasOutbound := rule["outbound"].(string)
			action, hasAction := rule["action"]
			if !hasOutbound && !hasAction {
				issues = append(issues, fmt.Sprintf("%s: sing-box rule needs outbound or action (rule dropped)", prefix))
				continue
			}
			if hasOutbound {
				tag := strings.TrimSpace(outbound)
				if tag == "" {
					issues = append(issues, fmt.Sprintf("%s: outbound must not be blank (rule dropped)", prefix))
					continue
				}
				if err := checkTag(tag, availableTags); err != nil {
					issues = append(issues, fmt.Sprintf("%s: %v", prefix, err))
					continue
				}
			} else if _, isString := action.(string); !isString {
				issues = append(issues, fmt.Sprintf("%s: action must be a string (rule dropped)", prefix))
				continue
			}
			kept = append(kept, rule)
			keptIdx = append(keptIdx, i)
		default:
			var unknown []string
			for key := range rule {
				unknown = append(unknown, key)
			}
			sort.Strings(unknown)
			issues = append(issues, fmt.Sprintf("%s: unrecognized rule shape, keys [%s] (rule dropped): use Xray-native form (outboundTag), sing-box-native keys, or the structured match/action shape; see docs-custom-routes.md", prefix, strings.Join(unknown, " ")))
		}
	}
	return kept, keptIdx, issues
}

func checkTag(tag string, availableTags map[string]struct{}) error {
	if availableTags == nil {
		return nil
	}
	if _, ok := availableTags[strings.ToLower(strings.TrimSpace(tag))]; !ok {
		return fmt.Errorf("outboundTag references unknown outbound %q", tag)
	}
	return nil
}

// outboundTagOf reads the Xray-form outboundTag for the tag-reference check.
func outboundTagOf(rule map[string]any) (string, error) {
	raw, ok := rule["outboundTag"]
	if !ok {
		return "", fmt.Errorf("outboundTag is required")
	}
	text, err := ruleString(raw, "outboundTag")
	if err != nil {
		return "", err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("outboundTag is required")
	}
	return text, nil
}
