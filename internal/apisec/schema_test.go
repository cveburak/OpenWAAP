package apisec

import (
	"encoding/json"
	"strings"
	"testing"
)

func validateDoc(t *testing.T, schemaJSON string, doc any) error {
	t.Helper()
	s, err := compileSchema([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("compileSchema: %v", err)
	}
	return s.Validate(doc, "body")
}

func decode(t *testing.T, raw string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func TestValidateNestedObject(t *testing.T) {
	schemaJSON := `{
		"type": "object",
		"properties": {
			"name": {"type": "string", "minLength": 2},
			"age": {"type": "integer", "minimum": 0, "maximum": 150},
			"tags": {"type": "array", "items": {"type": "string"}, "maxItems": 5}
		},
		"required": ["name"],
		"additionalProperties": false
	}`
	ok := decode(t, `{"name": "ada", "age": 37, "tags": ["a", "b"]}`)
	if err := validateDoc(t, schemaJSON, ok); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}

	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"missing-required", `{"age": 40}`, "missing required field"},
		{"unexpected-field", `{"name": "ada", "extra": 1}`, "unexpected field"},
		{"short-string", `{"name": "a"}`, "string too short"},
		{"wrong-type", `{"name": "ada", "age": "old"}`, "expected integer"},
		{"out-of-range", `{"name": "ada", "age": 200}`, "above maximum"},
		{"too-many-items", `{"name": "ada", "tags": ["1","2","3","4","5","6"]}`, "array too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDoc(t, schemaJSON, decode(t, tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateStringFeatures(t *testing.T) {
	schemaJSON := `{
		"type": "object",
		"properties": {
			"email": {"type": "string", "pattern": "^[^@]+@[^@]+$"},
			"color": {"type": "string", "enum": ["red", "green", "blue"]},
			"score": {"type": "number", "minimum": 0, "maximum": 100}
		}
	}`
	if err := validateDoc(t, schemaJSON, decode(t, `{"email": "a@b.c", "color": "blue", "score": 0.5}`)); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	if err := validateDoc(t, schemaJSON, decode(t, `{"email": "not-an-email"}`)); err == nil {
		t.Fatal("expected pattern failure")
	}
	if err := validateDoc(t, schemaJSON, decode(t, `{"color": "purple"}`)); err == nil {
		t.Fatal("expected enum failure")
	}
	if err := validateDoc(t, schemaJSON, decode(t, `{"score": 101}`)); err == nil {
		t.Fatal("expected max failure")
	}
}

func TestValidateArrayUntyped(t *testing.T) {
	schemaJSON := `{"type": "array", "items": {"type": "string"}, "minItems": 1}`
	if err := validateDoc(t, schemaJSON, decode(t, `[]`)); err == nil {
		t.Fatal("expected minItems failure")
	}
	if err := validateDoc(t, schemaJSON, decode(t, `["ok"]`)); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	if err := validateDoc(t, schemaJSON, decode(t, `[1, 2]`)); err == nil {
		t.Fatal("expected item-type failure")
	}
}

func TestCompileSchemaErrors(t *testing.T) {
	if _, err := compileSchema([]byte(`{"type": "blob"}`)); err == nil {
		t.Fatal("expected unsupported type error")
	}
	if _, err := compileSchema([]byte(`{"type": "string", "pattern": "["}`)); err == nil {
		t.Fatal("expected pattern compile error")
	}
}

func TestNestedArrayPath(t *testing.T) {
	schemaJSON := `{
		"type": "object",
		"properties": {
			"rows": {"type": "array", "items": {
				"type": "object",
				"properties": {"id": {"type": "integer"}},
				"required": ["id"]
			}}
		}
	}`
	err := validateDoc(t, schemaJSON, decode(t, `{"rows": [{"id": 1}, {"name": "x"}]}`))
	if err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("want nested failure, got %v", err)
	}
}
