package model

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type outboundTagSource struct {
	Tag    string
	Source string
}

func collectAdditionalOutboundTagSources(path string, rawOutbounds []map[string]any) ([]outboundTagSource, error) {
	sources := collectRawOutboundTagSources(rawOutbounds)
	customSources, err := collectCustomConfigOutboundTagSources(path)
	if err != nil {
		return nil, err
	}
	sources = append(sources, customSources...)
	return sources, nil
}

func collectRawOutboundTagSources(outbounds []map[string]any) []outboundTagSource {
	if len(outbounds) == 0 {
		return nil
	}
	sources := make([]outboundTagSource, 0, len(outbounds))
	for i, outbound := range outbounds {
		tag, _ := outbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sources = append(sources, outboundTagSource{Tag: tag, Source: fmt.Sprintf("kernel.custom_outbound[%d]", i)})
	}
	return sources
}

func collectCustomConfigOutboundTagSources(path string) ([]outboundTagSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom config %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	decoded := make(map[string]any)
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse custom config as JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse custom config as YAML: %w", err)
		}
	}

	items, ok := toSliceOfMaps(decoded["outbounds"])
	if !ok {
		return nil, nil
	}
	sources := make([]outboundTagSource, 0, len(items))
	for i, item := range items {
		tag, _ := item["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sources = append(sources, outboundTagSource{Tag: tag, Source: fmt.Sprintf("kernel.custom_config.outbounds[%d]", i)})
	}
	return sources, nil
}

func toSliceOfMaps(v any) ([]map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	switch items := v.(type) {
	case []any:
		result := make([]map[string]any, 0, len(items))
		for _, item := range items {
			mapped, ok := toMap(item)
			if ok {
				result = append(result, mapped)
			}
		}
		return result, len(result) > 0
	case []map[string]any:
		return items, len(items) > 0
	default:
		return nil, false
	}
}

func toMap(v any) (map[string]any, bool) {
	switch mapped := v.(type) {
	case map[string]any:
		return mapped, true
	case map[any]any:
		result := make(map[string]any, len(mapped))
		for k, val := range mapped {
			result[fmt.Sprint(k)] = val
		}
		return result, true
	default:
		return nil, false
	}
}

// IsReservedOutboundTag reports whether tag names one of the built-in
// outbounds every kernel config references: the private-network block rules
// and the direct final route. A panel-provided outbound must not take these
// names — shadowing "block" silently turns SSRF protection into a proxy hop,
// and a case-only shadow ("Direct") removes the built-in and leaves "direct"
// dangling, which makes the kernel reject the whole config.
func IsReservedOutboundTag(tag string) bool {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "direct", "block":
		return true
	}
	return false
}

func validateOutboundTagCollisions(structured []OutboundConfig, additional []outboundTagSource) error {
	seen := make(map[string]string, len(additional))
	for _, source := range additional {
		key := strings.ToLower(strings.TrimSpace(source.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("%s.tag duplicates %q from %s", source.Source, source.Tag, prev)
		}
		seen[key] = source.Source
	}
	for i, outbound := range structured {
		key := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("custom_outbounds[%d].tag duplicates %q from %s", i, outbound.Tag, prev)
		}
	}
	return nil
}

func additionalTagNames(sources []outboundTagSource) []string {
	if len(sources) == 0 {
		return nil
	}
	tags := make([]string, 0, len(sources))
	for _, source := range sources {
		tags = append(tags, source.Tag)
	}
	return tags
}
