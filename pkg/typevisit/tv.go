package typevisit

import (
	"errors"
	"reflect"
)

var (
	ErrInvalidType  = errors.New("invalid-type")
	ErrInvalidValue = errors.New("invalid-value")
)

type FieldOpts string
type TargetVisitorFunc func(v reflect.Value, opts FieldOpts)
type visitorFunc func(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc)
type TypeVisitorTree struct {
	root     reflect.Type
	target   reflect.Type
	tagName  string
	rootNode visitorFunc
}

func (tvt TypeVisitorTree) newTypeVisitor(t reflect.Type, tag string) visitorFunc {
	// handle hashblob struct type directly
	if t == tvt.target {
		return func(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
			targetVisitor(v, FieldOpts(tag))
		}
	}

	switch t.Kind() {
	case reflect.Struct:
		return tvt.newStructVisitor(t)

	case reflect.Map:
		return tvt.newMapVisitor(t, tag)

	case reflect.Slice:
		fallthrough

	case reflect.Array:
		return tvt.newArrayVisitor(t, tag)

	case reflect.Pointer:
		return tvt.newPointerVisitor(t, tag)

	default:
		// don't handle unknown fields
		return nil
	}
}

type arrayVisitor struct {
	ev visitorFunc
}

func (av arrayVisitor) visit(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
	n := v.Len()
	for i := 0; i < n; i++ {
		av.ev(v.Index(i), opts, targetVisitor)
	}
}

func (tvt TypeVisitorTree) newArrayVisitor(t reflect.Type, tag string) visitorFunc {
	if t.Kind() != reflect.Array || t.Kind() != reflect.Slice {
		return nil
	}

	if r := tvt.newTypeVisitor(t.Elem(), tag); r != nil {
		av := arrayVisitor{ev: r}
		return av.visit
	}
	return nil
}

type mapVisitor struct {
	ev visitorFunc
}

func (mv mapVisitor) visit(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
	mi := v.MapRange()
	for mi.Next() {
		mv.ev(mi.Value(), opts, targetVisitor)
	}
}

func (tvt TypeVisitorTree) newMapVisitor(t reflect.Type, tag string) visitorFunc {
	if t.Kind() != reflect.Map {
		return nil
	}

	// we need a speical treatment for maps of target type because it is not possible to get pointers to map elements
	// and that would prevent any lasting modifications to the elements
	if t.Elem() == tvt.target {
		return func(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
			targetVisitor(v, FieldOpts(tag))
		}
	}

	if r := tvt.newTypeVisitor(t.Elem(), tag); r != nil {
		mv := mapVisitor{ev: r}
		return mv.visit
	}
	return nil
}

type pointerVisitor struct {
	ev visitorFunc
}

func (pv pointerVisitor) visit(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
	if v.IsNil() {
		return
	}
	pv.ev(v.Elem(), opts, targetVisitor)
}

func (tvt TypeVisitorTree) newPointerVisitor(t reflect.Type, tag string) visitorFunc {
	if t.Kind() != reflect.Pointer {
		return nil
	}

	if r := tvt.newTypeVisitor(t.Elem(), tag); r != nil {
		pv := pointerVisitor{ev: r}
		return pv.visit
	}
	return nil
}

type structVisitor struct {
	fields map[int]visitorFunc
}

func (sv structVisitor) visit(v reflect.Value, opts FieldOpts, targetVisitor TargetVisitorFunc) {
	for k, vf := range sv.fields {
		vf(v.Field(k), opts, targetVisitor)
	}
}

// newStructVisitor does not support non-exported or anonymous struct members
func (tvt TypeVisitorTree) newStructVisitor(t reflect.Type) visitorFunc {
	// we only work on structs
	if t.Kind() != reflect.Struct {
		return nil
	}

	fields := make(map[int]visitorFunc)
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)

		// ignore unexported or anonymous fields
		if !sf.IsExported() || sf.Anonymous {
			continue
		}

		// handle other types
		if r := tvt.newTypeVisitor(sf.Type, sf.Tag.Get(tvt.tagName)); r != nil {
			fields[i] = r
		}
	}

	if len(fields) > 0 {
		sv := structVisitor{fields: fields}
		return sv.visit
	}
	return nil
}

// Visit must be called with the root type the tree was constructed for and will call the user callback on all target type instances
func (tvt TypeVisitorTree) Visit(value any, targetVisitor TargetVisitorFunc) error {
	if reflect.TypeOf(value) != tvt.root {
		return ErrInvalidValue
	}

	tvt.rootNode(reflect.ValueOf(value), "", targetVisitor)

	return nil
}

// New constructs a tree that is tailored to visit all instances of the target type that are found below the root type
// the root type must be a pointer to a struct, the target type can be any type and tagName specifies a tag that will be searched for
// the tag string content on a struct field will be passed to the callback, if the field is a map of slice of array of pointer of map of target type, then the tag will still be passed along
// this will not work on non-exported or anonymous struct fields and pointer loops are not detected
func New(rootType, targetType any, tagName string) (*TypeVisitorTree, error) {
	rt := reflect.TypeOf(rootType)

	// only work on structs, though we could theoretically also work on any container
	if rt.Kind() != reflect.Pointer && rt.Elem().Kind() != reflect.Struct {
		return nil, ErrInvalidType
	}

	tvt := TypeVisitorTree{root: rt, target: reflect.TypeOf(targetType), tagName: tagName}
	tvt.rootNode = tvt.newTypeVisitor(rt, "")

	// when the target is not found we don't have a tree
	if tvt.rootNode == nil {
		return nil, ErrInvalidType
	}

	return &tvt, nil
}
