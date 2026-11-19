package server

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

// The gRPC messages and the REST JSON bodies are one schema: a proto field is
// named exactly as the JSON field it mirrors. These two functions lean on that
// to copy between a protobuf message and the Go struct the REST handler
// decodes into, so both transports run the same code with the same types and
// a field added to one cannot quietly go missing from the other. Matching is
// by JSON tag; the contract test checks that every tag has a proto field.
//
// Conversions beyond same-kind scalars:
//
//	Go string kind  <-> proto enum      "tool_result" <-> STAGE_TOOL_RESULT
//	map[string]any  <-> Struct
//	any             <-> Value
//	time.Duration   <-> int64           nanoseconds, as in JSON

// toProto copies a Go struct (or pointer to one) into m.
func toProto(src any, m protoreflect.Message) error {
	v := reflect.ValueOf(src)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	return structToProto(v, m)
}

// fromProto copies m into the Go struct dst points to.
func fromProto(m protoreflect.Message, dst any) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("fromProto: need a non-nil pointer, got %T", dst)
	}
	return protoToStruct(m, v.Elem())
}

// jsonName returns the JSON field name of f, or "" when JSON skips it.
func jsonName(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	tag := f.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}

func structToProto(v reflect.Value, m protoreflect.Message) error {
	fields := m.Descriptor().Fields()
	t := v.Type()
	for i := range t.NumField() {
		name := jsonName(t.Field(i))
		if name == "" {
			continue
		}
		fd := fields.ByName(protoreflect.Name(name))
		if fd == nil {
			// Server-only data with no wire field; the contract test lists
			// the few that are allowed.
			continue
		}
		fv := v.Field(i)
		if fv.IsZero() {
			continue
		}
		if err := setProtoField(m, fd, fv); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func setProtoField(m protoreflect.Message, fd protoreflect.FieldDescriptor, v reflect.Value) error {
	switch {
	case fd.IsMap():
		mp := m.Mutable(fd).Map()
		iter := v.MapRange()
		for iter.Next() {
			key := protoreflect.ValueOfString(iter.Key().String()).MapKey()
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				if err := valueToMessage(iter.Value(), mp.Mutable(key).Message()); err != nil {
					return err
				}
				continue
			}
			pv, err := scalarToProto(fd.MapValue(), iter.Value())
			if err != nil {
				return err
			}
			mp.Set(key, pv)
		}
		return nil
	case fd.IsList():
		list := m.Mutable(fd).List()
		for j := range v.Len() {
			ev := v.Index(j)
			if fd.Kind() == protoreflect.MessageKind {
				if err := valueToMessage(ev, list.AppendMutable().Message()); err != nil {
					return err
				}
				continue
			}
			pv, err := scalarToProto(fd, ev)
			if err != nil {
				return err
			}
			list.Append(pv)
		}
		return nil
	case fd.Kind() == protoreflect.MessageKind:
		return valueToMessage(v, m.Mutable(fd).Message())
	default:
		pv, err := scalarToProto(fd, v)
		if err != nil {
			return err
		}
		m.Set(fd, pv)
		return nil
	}
}

// valueToMessage fills a message from a Go struct, pointer, map or interface.
func valueToMessage(v reflect.Value, m protoreflect.Message) error {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		if v.Kind() == reflect.Interface && m.Descriptor().FullName() == "google.protobuf.Value" {
			break
		}
		v = v.Elem()
	}
	switch m.Descriptor().FullName() {
	case "google.protobuf.Struct":
		obj, ok := v.Interface().(map[string]any)
		if !ok {
			return fmt.Errorf("want map[string]any for Struct, got %s", v.Type())
		}
		s, err := structpb.NewStruct(obj)
		if err != nil {
			return err
		}
		copyMessage(s.ProtoReflect(), m)
		return nil
	case "google.protobuf.Value":
		val, err := structpb.NewValue(v.Interface())
		if err != nil {
			return err
		}
		copyMessage(val.ProtoReflect(), m)
		return nil
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("cannot encode %s as %s", v.Type(), m.Descriptor().FullName())
	}
	return structToProto(v, m)
}

func copyMessage(src, dst protoreflect.Message) {
	proto.Merge(dst.Interface(), src.Interface())
}

func scalarToProto(fd protoreflect.FieldDescriptor, v reflect.Value) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.EnumKind:
		n, err := enumNumber(fd.Enum(), v.String())
		return protoreflect.ValueOfEnum(n), err
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(v.String()), nil
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(v.Bool()), nil
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(v.Bytes()), nil
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(v.Float()), nil
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(v.Float())), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(intOf(v)), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(intOf(v))), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(intOf(v))), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(intOf(v))), nil
	}
	return protoreflect.Value{}, fmt.Errorf("unsupported proto kind %s", fd.Kind())
}

// intOf reads any Go integer kind. Taint hashes are uint64 and must round-trip
// bit for bit, which the conversion through int64 does.
func intOf(v reflect.Value) int64 {
	if v.CanUint() {
		return int64(v.Uint())
	}
	return v.Int()
}

func protoToStruct(m protoreflect.Message, v reflect.Value) error {
	fields := m.Descriptor().Fields()
	t := v.Type()
	for i := range t.NumField() {
		name := jsonName(t.Field(i))
		if name == "" {
			continue
		}
		fd := fields.ByName(protoreflect.Name(name))
		if fd == nil || !m.Has(fd) {
			continue
		}
		if err := getProtoField(m.Get(fd), fd, v.Field(i)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func getProtoField(pv protoreflect.Value, fd protoreflect.FieldDescriptor, dst reflect.Value) error {
	switch {
	case fd.IsMap():
		mp := pv.Map()
		out := reflect.MakeMapWithSize(dst.Type(), mp.Len())
		var err error
		mp.Range(func(k protoreflect.MapKey, val protoreflect.Value) bool {
			ev := reflect.New(dst.Type().Elem()).Elem()
			if err = getProtoValue(val, fd.MapValue(), ev); err != nil {
				return false
			}
			out.SetMapIndex(reflect.ValueOf(k.String()).Convert(dst.Type().Key()), ev)
			return true
		})
		if err != nil {
			return err
		}
		dst.Set(out)
		return nil
	case fd.IsList():
		list := pv.List()
		out := reflect.MakeSlice(dst.Type(), list.Len(), list.Len())
		for j := range list.Len() {
			if err := getProtoValue(list.Get(j), fd, out.Index(j)); err != nil {
				return err
			}
		}
		dst.Set(out)
		return nil
	default:
		return getProtoValue(pv, fd, dst)
	}
}

// getProtoValue reads one singular value (a field, a list element or a map
// value) into dst.
func getProtoValue(pv protoreflect.Value, fd protoreflect.FieldDescriptor, dst reflect.Value) error {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		return messageToValue(pv.Message(), dst)
	case protoreflect.EnumKind:
		dst.SetString(enumString(fd.Enum(), pv.Enum()))
	case protoreflect.StringKind:
		dst.SetString(pv.String())
	case protoreflect.BoolKind:
		dst.SetBool(pv.Bool())
	case protoreflect.BytesKind:
		dst.SetBytes(append([]byte(nil), pv.Bytes()...))
	case protoreflect.DoubleKind, protoreflect.FloatKind:
		dst.SetFloat(pv.Float())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind, protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		setInt(dst, int64(pv.Uint()))
	default:
		setInt(dst, pv.Int())
	}
	return nil
}

func setInt(dst reflect.Value, n int64) {
	if dst.CanUint() {
		dst.SetUint(uint64(n))
		return
	}
	dst.SetInt(n)
}

func messageToValue(m protoreflect.Message, dst reflect.Value) error {
	switch m.Descriptor().FullName() {
	case "google.protobuf.Struct":
		s := &structpb.Struct{}
		copyMessage(m, s.ProtoReflect())
		dst.Set(reflect.ValueOf(s.AsMap()))
		return nil
	case "google.protobuf.Value":
		val := &structpb.Value{}
		copyMessage(m, val.ProtoReflect())
		if x := val.AsInterface(); x != nil {
			dst.Set(reflect.ValueOf(x))
		}
		return nil
	}
	if dst.Kind() == reflect.Pointer {
		dst.Set(reflect.New(dst.Type().Elem()))
		dst = dst.Elem()
	}
	if dst.Kind() != reflect.Struct {
		return fmt.Errorf("cannot decode %s into %s", m.Descriptor().FullName(), dst.Type())
	}
	return protoToStruct(m, dst)
}

// enumPrefix is the value prefix the style guide gives an enum: Stage ->
// "STAGE_", ToolKind -> "TOOL_KIND_".
func enumPrefix(ed protoreflect.EnumDescriptor) string {
	var b strings.Builder
	for i, r := range string(ed.Name()) {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String() + "_"
}

// enumNumber maps a JSON enum string ("tool_result") to its proto value.
func enumNumber(ed protoreflect.EnumDescriptor, s string) (protoreflect.EnumNumber, error) {
	if s == "" {
		return 0, nil
	}
	ev := ed.Values().ByName(protoreflect.Name(enumPrefix(ed) + strings.ToUpper(s)))
	if ev == nil {
		return 0, fmt.Errorf("%q is not a %s", s, ed.Name())
	}
	return ev.Number(), nil
}

// enumString maps a proto enum value back to its JSON string. UNSPECIFIED and
// numbers this build does not know become "", which the engine treats as the
// field's default.
func enumString(ed protoreflect.EnumDescriptor, n protoreflect.EnumNumber) string {
	ev := ed.Values().ByNumber(n)
	if ev == nil || n == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(string(ev.Name()), enumPrefix(ed)))
}
