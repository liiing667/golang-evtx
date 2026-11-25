package evtx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func malformedTemplateInstanceReader() *bytes.Reader {
	var b bytes.Buffer
	le := binary.LittleEndian

	// Template instance header.
	b.WriteByte(TokenTemplateInstance)
	b.WriteByte(0)
	binary.Write(&b, le, int32(0))
	// Offset of the first TemplateDefinitionData byte in this synthetic stream.
	binary.Write(&b, le, int32(10))

	// TemplateDefinitionData prefix.
	binary.Write(&b, le, int32(0))
	b.Write(make([]byte, 16)) // Template ID
	binary.Write(&b, le, int32(0))
	// Fragment header starts immediately after the 24-byte TemplateDefinitionData
	// prefix (Unknown3 + ID + Size).
	b.Write([]byte{FragmentHeaderToken, 1, 1, 0})

	// A simple element followed by an out of range optional substitution.
	b.Write([]byte{TokenOpenStartElementTag1})
	binary.Write(&b, le, int16(0)) // Dependency ID inside a template definition.
	binary.Write(&b, le, int32(0))
	nameOffset := int32(b.Len() + 4)
	binary.Write(&b, le, nameOffset)
	binary.Write(&b, le, int32(0))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint16(0))
	b.WriteByte(TokenCloseEmptyElementTag)
	b.WriteByte(TokenOptionalSubstitution)
	binary.Write(&b, le, int16(1))
	binary.Write(&b, le, int8(UInt8Type))
	b.WriteByte(TokenEndElementTag)
	b.WriteByte(TokenEOF)

	// Template instance data: one value, while the substitution asks for slot 1.
	binary.Write(&b, le, int32(1))
	binary.Write(&b, le, uint16(1))
	b.WriteByte(UInt8Type)
	b.WriteByte(0)
	b.WriteByte(7)

	return bytes.NewReader(b.Bytes())
}

func TestParseRejectsOutOfRangeSubstitutionBeforeConsumerConversion(t *testing.T) {
	elt, err := Parse(malformedTemplateInstanceReader(), nil, false)
	if err != ErrInvalidSubstitution {
		t.Fatalf("got element %#v and error %v, want ErrInvalidSubstitution", elt, err)
	}
	if elt != nil {
		t.Fatalf("malformed template instance must not be returned to consumers")
	}
}

func substitutionTestTemplate() *TemplateInstance {
	return &TemplateInstance{
		Definition: TemplateDefinition{
			Data: TemplateDefinitionData{
				Elements: []Element{
					&ElementStart{
						Name: Name{UTF16String: UTF16String{'E'}},
					},
					&BinXMLCloseStartElementTag{},
					&BinXMLEndElementTag{},
				},
			},
		},
	}
}

func TestValidateSubstitutionsRejectsOutOfRangeSlot(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: StringType}}
	ti.Data.Values = []Element{&ValueString{}}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&OptionalSubstitution{NormalSubstitution{SubID: 1, ValType: StringType}},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != ErrInvalidSubstitution {
		t.Fatalf("got error %v, want ErrInvalidSubstitution", err)
	}
}

func TestValidateSubstitutionsRejectsIncompleteSlot(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: StringType}}
	ti.Data.Values = []Element{nil}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&NormalSubstitution{SubID: 0, ValType: StringType},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != ErrInvalidSubstitution {
		t.Fatalf("got error %v, want ErrInvalidSubstitution", err)
	}
}

func TestValidateSubstitutionsRejectsNegativeSlot(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: StringType}}
	ti.Data.Values = []Element{&ValueString{}}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&NormalSubstitution{SubID: -1, ValType: StringType},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != ErrInvalidSubstitution {
		t.Fatalf("got error %v, want ErrInvalidSubstitution", err)
	}
}

func TestValidateSubstitutionsRejectsTypeMismatch(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: UInt32Type}}
	ti.Data.Values = []Element{&ValueUInt32{}}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&NormalSubstitution{SubID: 0, ValType: StringType},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != ErrInvalidSubstitution {
		t.Fatalf("got error %v, want ErrInvalidSubstitution", err)
	}
}

func TestValidateSubstitutionsChecksAttributes(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: StringType}}
	ti.Data.Values = []Element{&ValueString{}}
	ti.Definition.Data.Elements[0].(*ElementStart).AttributeList.Attributes = []Attribute{
		{AttributeData: &NormalSubstitution{SubID: 1, ValType: StringType}},
	}

	if err := ti.ValidateSubstitutions(); err != ErrInvalidSubstitution {
		t.Fatalf("got error %v, want ErrInvalidSubstitution", err)
	}
}

func TestValidateSubstitutionsPreservesOptionalNullValue(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: NullType}}
	ti.Data.Values = []Element{&ValueNull{}}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&OptionalSubstitution{NormalSubstitution{SubID: 0, ValType: NullType}},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != nil {
		t.Fatalf("optional NullType substitution must remain valid: %v", err)
	}

	// A legal NullType must continue to produce a nil GoEvtx value, rather than
	// being confused with an invalid or incomplete slot.
	if got := ti.ElementToGoEvtx(ti.Definition.Data.Elements[1]); got != nil {
		t.Fatalf("NullType substitution produced non-nil value: %#v", got)
	}
}

func TestValidateSubstitutionsPreservesLegalValue(t *testing.T) {
	ti := substitutionTestTemplate()
	ti.Data.NumValues = 1
	ti.Data.ValDescs = []ValueDescriptor{{ValType: StringType}}
	ti.Data.Values = []Element{&ValueString{value: UTF16String{'o', 'k'}}}
	ti.Definition.Data.Elements = append(ti.Definition.Data.Elements[:1],
		&NormalSubstitution{SubID: 0, ValType: StringType},
		&BinXMLEndElementTag{})

	if err := ti.ValidateSubstitutions(); err != nil {
		t.Fatalf("valid substitution was rejected: %v", err)
	}

	got := ti.GoEvtxMap()
	if value := (*got)["E"].(GoEvtxMap)["Value"]; value != "ok" {
		t.Fatalf("unexpected GoEvtxMap value: %#v", value)
	}
}
