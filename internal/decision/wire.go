package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const MaxWireBytes = 1 << 20

var wireInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// DecodeRequest rejects duplicate keys, trailing JSON, unknown fields and excessive nesting.
func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) > MaxWireBytes {
		return r, errors.New("request too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return r, err
	}
	if _, err = d.Token(); err != io.EOF {
		return r, errors.New("trailing JSON")
	}
	s, err := requestSchema()
	if err != nil {
		return r, err
	}
	if err = s.Validate(value); err != nil {
		return r, errors.New("invalid decision request")
	}
	clean, err := json.Marshal(value)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(clean, &r); err != nil {
		return r, err
	}
	return r, Validate(r)
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("JSON too deep")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				if _, exists := m[k]; exists {
					return nil, errors.New("duplicate object key")
				}
				if len(m) >= 64 {
					return nil, errors.New("too many object members")
				}
				item, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = item
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid object")
			}
			return m, nil
		}
		if v == '[' {
			a := []any{}
			for d.More() {
				if len(a) >= 4096 {
					return nil, errors.New("too many items")
				}
				item, err := readValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, item)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid array")
			}
			return a, nil
		}
		return nil, errors.New("unexpected delimiter")
	case json.Number:
		if !wireInteger.MatchString(v.String()) {
			return nil, errors.New("integer notation required")
		}
		return v, nil
	case string, bool, nil:
		return t, nil
	default:
		return nil, errors.New("unsupported JSON token")
	}
}
