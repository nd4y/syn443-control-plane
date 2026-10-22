package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"sync"
)

var schemaInit sync.Once
var schemaValue *jsonschema.Schema
var schemaError error

func validateSchema(clean []byte) error {
	schemaInit.Do(func() {
		raw, e := contracts.Files.ReadFile("v1/policy-payload.schema.json")
		if e != nil {
			schemaError = e
			return
		}
		var doc map[string]any
		if e = json.Unmarshal(raw, &doc); e != nil {
			schemaError = e
			return
		}
		compiler := jsonschema.NewCompiler()
		id := doc["$id"].(string)
		if e = compiler.AddResource(id, doc); e != nil {
			schemaError = e
			return
		}
		schemaValue, schemaError = compiler.Compile(id)
	})
	if schemaError != nil {
		return errors.New("policy schema unavailable")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(clean))
	decoder.UseNumber()
	if e := decoder.Decode(&value); e != nil {
		return e
	}
	if e := schemaValue.Validate(value); e != nil {
		return errors.New("policy schema invalid")
	}
	return nil
}
