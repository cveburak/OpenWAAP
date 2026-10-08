package apisec

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

type schema struct {
	Type                 string            `json:"type"`
	Properties           map[string]schema `json:"properties"`
	Required             []string          `json:"required"`
	AdditionalProperties *bool             `json:"additionalProperties"`
	Items                *schema           `json:"items"`
	MinItems             *int              `json:"minItems"`
	MaxItems             *int              `json:"maxItems"`
	Pattern              string            `json:"pattern"`
	MinLength            *int              `json:"minLength"`
	MaxLength            *int              `json:"maxLength"`
	Enum                 []json.RawMessage `json:"enum"`
	Minimum              *float64          `json:"minimum"`
	Maximum              *float64          `json:"maximum"`
	nullable             bool
	compiledPattern *regexp.Regexp
}

var schemaTypes = map[string]bool{
	"object": true, "array": true, "string": true, "integer": true,
	"number": true, "boolean": true, "null": true,
}

func compileSchema(raw []byte) (*schema, error) {
	var s schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("invalid request_schema: %w", err)
	}
	if err := s.finalize(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *schema) finalize() error {
	if s.Type == "" {
		s.Type = "object"
	}
	if !schemaTypes[s.Type] {
		return fmt.Errorf("schema: unsupported type %q", s.Type)
	}
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("schema: bad pattern: %w", err)
		}
		s.compiledPattern = re
	}
	if s.Enum != nil && s.Type != "string" && len(s.Enum) > 0 {
		return fmt.Errorf("schema: enum only supported for string type for now")
	}
	if s.Items != nil {
		if err := s.Items.finalize(); err != nil {
			return err
		}
	}
	for k, sub := range s.Properties {
		if err := sub.finalize(); err != nil {
			return err
		}
		s.Properties[k] = sub
	}
	return nil
}

func (s *schema) Validate(doc any, path string) error {
	switch s.Type {
	case "object":
		obj, ok := doc.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected object, got %s", path, typeName(doc))
		}
		for _, k := range s.Required {
			if _, ok := obj[k]; !ok {
				return fmt.Errorf("%s: missing required field %q", path, k)
			}
		}
		for k, v := range obj {
			sub, ok := s.Properties[k]
			if !ok {
				if s.AdditionalProperties != nil && !*s.AdditionalProperties {
					return fmt.Errorf("%s: unexpected field %q", path, k)
				}
				continue
			}
			if err := sub.Validate(v, path+"."+k); err != nil {
				return err
			}
		}
	case "array":
		arr, ok := doc.([]any)
		if !ok {
			return fmt.Errorf("%s: expected array, got %s", path, typeName(doc))
		}
		if s.MinItems != nil && len(arr) < *s.MinItems {
			return fmt.Errorf("%s: array too short (%d < %d)", path, len(arr), *s.MinItems)
		}
		if s.MaxItems != nil && len(arr) > *s.MaxItems {
			return fmt.Errorf("%s: array too long (%d > %d)", path, len(arr), *s.MaxItems)
		}
		if s.Items != nil {
			for i, v := range arr {
				if err := s.Items.Validate(v, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	case "string":
		str, ok := doc.(string)
		if !ok {
			return fmt.Errorf("%s: expected string, got %s", path, typeName(doc))
		}
		if s.MinLength != nil && len(str) < *s.MinLength {
			return fmt.Errorf("%s: string too short", path)
		}
		if s.MaxLength != nil && len(str) > *s.MaxLength {
			return fmt.Errorf("%s: string too long", path)
		}
		if s.Pattern != "" {
			re := s.compiledPattern
			if re == nil {
				var err error
				re, err = regexp.Compile(s.Pattern)
				if err != nil {
					return fmt.Errorf("%s: invalid pattern: %w", path, err)
				}
			}
			if !re.MatchString(str) {
				return fmt.Errorf("%s: string does not match pattern", path)
			}
		}
		if len(s.Enum) > 0 {
			match := false
			for _, want := range s.Enum {
				var wantStr string
				if json.Unmarshal(want, &wantStr) == nil && wantStr == str {
					match = true
					break
				}
			}
			if !match {
				return fmt.Errorf("%s: value not in enum", path)
			}
		}
	case "integer":
		f, ok := asNumber(doc)
		if !ok || f != float64(int64(f)) {
			return fmt.Errorf("%s: expected integer", path)
		}
		if err := s.checkRange(f, path); err != nil {
			return err
		}
	case "number":
		f, ok := asNumber(doc)
		if !ok {
			return fmt.Errorf("%s: expected number", path)
		}
		if err := s.checkRange(f, path); err != nil {
			return err
		}
	case "boolean":
		if _, ok := doc.(bool); !ok {
			return fmt.Errorf("%s: expected boolean", path)
		}
	case "null":
		if doc != nil {
			return fmt.Errorf("%s: expected null", path)
		}
	}
	return nil
}

func (s *schema) checkRange(f float64, path string) error {
	if s.Minimum != nil && f < *s.Minimum {
		return fmt.Errorf("%s: value below minimum %v", path, *s.Minimum)
	}
	if s.Maximum != nil && f > *s.Maximum {
		return fmt.Errorf("%s: value above maximum %v", path, *s.Maximum)
	}
	return nil
}

func asNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

func typeName(v any) string {
	if v == nil {
		return "null"
	}
	return strings.ToLower(reflect.TypeOf(v).String())
}
