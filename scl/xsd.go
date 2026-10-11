package scl

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/xsd"
)

// Schema validation against the official SCL schema, the IEC 61850-6 code
// component (SCL.2007C5 when this was written). The schema is IEC's,
// under IEC's own licence, and this module does not carry it:
// an application loads it at run time with LoadSchema (the unpacked SCL
// zip from IEC's download site) or LoadSchemaFiles, and the generic
// validator (github.com/cB-Sigma/xsd) interprets it: content models,
// simple types with their facets, unions and lists, and unique, key and
// keyref with the XPath subset of XSD identity constraints. Without a
// schema, Validate applies the clause rules only and says so in one
// warning.
//
// Clause 8.2.1 is kept on top of the XSD through the validator's hooks: an
// SCL element the schema does not know is ignored with a warning unless it
// is marked mustUnderstand, an unknown attribute is ignored with a warning.
// Elements of other namespaces come before the SCL elements of their
// parent (8.3.5) and are not validated. A document that declares another
// SCL version than the schema's (2007C5) is checked too, with the
// departures as warnings: its own schema release is the reference
// (Annex I).

// schemaIndex is the loaded SCL schema.
type schemaIndex struct {
	x       *xsd.Schema
	version string
	simple  map[string]bool // global simple types
}

var (
	schemaMu  sync.RWMutex
	schemaIdx *schemaIndex
)

// ErrNoSchema is returned by functions that need the SCL schema before it
// is loaded.
var ErrNoSchema = errors.New("scl: the SCL schema is not loaded (call scl.LoadSchema with IEC's SCL schema files; this module does not include them)")

// schema returns the loaded schema, or nil.
func schema() *schemaIndex {
	schemaMu.RLock()
	defer schemaMu.RUnlock()
	return schemaIdx
}

// LoadSchema loads the SCL schema from fsys, which holds SCL.xsd and the
// documents it includes at its root (the directory of IEC's unpacked
// IEC_61850-6 SCL zip), and makes it the schema Validate
// checks documents against. The schema version is read from SCL.xsd.
func LoadSchema(fsys fs.FS) error {
	b, err := fs.ReadFile(fsys, "SCL.xsd")
	if err != nil {
		return fmt.Errorf("scl: %w", err)
	}
	version, err := schemaVersionOf(b)
	if err != nil {
		return err
	}
	x, err := xsd.Load(fsys, "SCL.xsd")
	if err != nil {
		return fmt.Errorf("scl: the SCL schema does not load: %w", err)
	}
	s := &schemaIndex{x: x, version: version, simple: map[string]bool{}}
	for _, n := range x.SimpleTypes(NS) {
		s.simple[n] = true
	}
	schemaMu.Lock()
	schemaIdx = s
	schemaMu.Unlock()
	return nil
}

// LoadSchemaFiles is LoadSchema for schema documents held in memory, by
// file name ("SCL.xsd", "SCL_BaseTypes.xsd" …).
func LoadSchemaFiles(files map[string]string) error {
	return LoadSchema(mapFS(files))
}

// schemaVersionOf reads the version attribute of the schema element.
func schemaVersionOf(b []byte) (string, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := d.Token()
		if err != nil {
			return "", fmt.Errorf("scl: SCL.xsd: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			for _, a := range se.Attr {
				if a.Name.Local == "version" && a.Name.Space == "" && a.Value != "" {
					return a.Value, nil
				}
			}
			return "", errors.New("scl: SCL.xsd has no version")
		}
	}
}

// SchemaVersion is the version of the loaded SCL schema ("2007C5"), or ""
// before LoadSchema.
func SchemaVersion() string {
	if s := schema(); s != nil {
		return s.version
	}
	return ""
}

// xsdRun is one validation pass over a document.
type xsdRun struct {
	v      *validator
	s      *schemaIndex
	strict bool // the document declares the schema's own version
	sawSCL map[*Node]bool
}

func (r *xsdRun) isSCL(n *Node) bool {
	return n.Kind == KindElement && (n.Space == NS || n.Space == "" && r.v.d.Tree.NoNamespace)
}

// report adds a schema departure: an error for a document of the schema's
// version, a warning otherwise.
func (r *xsdRun) report(n *Node, format string, args ...any) {
	if r.strict {
		r.v.err(n, "XSD", format, args...)
	} else {
		r.v.warn(n, "XSD", format+" (checked against SCL schema "+r.s.version+")", args...)
	}
}

// checkSchema validates the tree against the SCL schema.
func (v *validator) checkSchema() {
	root := v.d.Tree.Root
	r := &xsdRun{v: v, s: schema(), sawSCL: map[*Node]bool{}}
	if r.s == nil {
		v.warn(root, "XSD", "the SCL schema is not loaded (scl.LoadSchema): schema checks were skipped")
		return
	}
	ver := v.d.SCL.SchemaVersion()
	r.strict = fmt.Sprintf("%d%s%d", ver.Year, ver.Revision, ver.Release) == r.s.version
	if root.Local != "SCL" {
		r.report(root, "the root element is %s, not %s", root.Local, "SCL")
		return
	}
	issues := r.s.x.ValidateTree(r.element(root), xsd.Options{
		Child:      r.child,
		Undeclared: r.undeclared,
		Check:      r.check,
		Opaque:     r.opaque,
		NoFixed: func(e *xsd.Element, _ string) bool {
			// The SCL version attributes are fixed to the schema's own;
			// other versions are the subject of 8.2.2 and Annex I
			// (checkVersion).
			return e.Ref.(*Node).Parent == nil
		},
	})
	for _, is := range issues {
		n := root
		if is.Elem != nil {
			n = is.Elem.Ref.(*Node)
		}
		switch {
		case is.Kind == xsd.IssueValue && is.Attr != "":
			// A value outside its type is an error whatever the version:
			// the attribute is known and its type has not changed.
			r.v.err(n, "9", "%s=%q %s", is.Attr, is.Value, is.Why)
		case is.Kind == xsd.IssueValue:
			r.report(n, "%s content %q %s", n.Local, strings.TrimSpace(is.Value), is.Why)
		case is.Kind == xsd.IssueCharacters:
			r.report(n, "%s has character content", n.Local)
		default:
			r.report(n, "%s", is.Msg)
		}
	}
}

// element converts the SCL tree for the validator: SCL elements take the
// SCL namespace (also in a document that omitted it) and are named without
// prefix, as the messages name them.
func (r *xsdRun) element(n *Node) *xsd.Element {
	e := &xsd.Element{Space: n.Space, Local: n.Local, Prefix: n.Prefix, Line: n.Line, Ref: n}
	if r.isSCL(n) {
		e.Space, e.Prefix = NS, ""
	}
	for _, a := range n.Attrs {
		if a.Prefix == "xmlns" || a.Local == "xmlns" && a.Prefix == "" {
			continue
		}
		e.Attrs = append(e.Attrs, xsd.Attr{Space: a.Space, Local: a.Local, Prefix: a.Prefix, Value: a.Value})
	}
	var text strings.Builder
	for _, c := range n.Children {
		switch c.Kind {
		case KindElement:
			e.Children = append(e.Children, r.element(c))
		case KindText:
			text.WriteString(c.Text)
		}
	}
	e.Text = text.String()
	return e
}

// child sorts the children of an element before its content is matched:
// elements of other namespaces first and not validated (tBaseElement),
// unknown SCL elements ignored (8.2.1), the rest matched.
func (r *xsdRun) child(c xsd.Child) bool {
	ch, parent := c.Elem.Ref.(*Node), c.Parent.Ref.(*Node)
	if !r.isSCL(ch) {
		if r.sawSCL[parent] && c.Wildcard {
			r.v.err(ch, "8.3.5", "element %s:%s of another namespace follows SCL elements (they come first)", ch.Prefix, ch.Local)
			return false
		}
		if !c.Wildcard {
			r.report(ch, "element %s:%s of another namespace is not allowed in %s", ch.Prefix, ch.Local, parent.Local)
		}
		return false
	}
	r.sawSCL[parent] = true
	if !c.Declared {
		if mu, _ := ch.Attr("mustUnderstand"); parseBool(mu, false) {
			r.v.errS(ch, "8.2.1", "element %s marked mustUnderstand is not known: %s cannot be used", ch.Local, parent.Local)
		} else {
			r.v.warn(ch, "8.2.1", "element %s is not known in %s and is ignored", ch.Local, parent.Local)
		}
		return false
	}
	return true
}

// undeclared handles an attribute the element's type does not declare.
func (r *xsdRun) undeclared(e *xsd.Element, a xsd.Attr, allowed bool) bool {
	n := e.Ref.(*Node)
	if a.Prefix != "" || a.Space != "" {
		if !allowed && a.Space != "http://www.w3.org/2001/XMLSchema-instance" {
			r.report(n, "attribute %s of another namespace is not allowed on %s", a.Prefix+":"+a.Local, n.Local)
		}
		return true
	}
	r.v.warn(n, "8.2.1", "attribute %s is not defined for %s and is ignored", a.Local, n.Local)
	return true
}

// check adds the package's own reading of an attribute type (types.go):
// its explanation is the more specific one, and a value the XSD accepts
// but the clause text restricts further is reported too.
func (r *xsdRun) check(typ, v string) string {
	if chk := types[typ]; chk != nil && typ != "" {
		return chk(v)
	}
	return ""
}

// opaque: Private and Text hold mixed content of other namespaces,
// processed lax; a Private is checked by 8.3.6 instead.
func (r *xsdRun) opaque(e *xsd.Element) bool {
	n := e.Ref.(*Node)
	if !r.isSCL(n) || n.Local != "Private" && n.Local != "Text" {
		return false
	}
	if n.Local == "Private" {
		r.v.checkPrivate(n)
	}
	return true
}

// simpleValue checks a value against a simple type of the SCL schema (or a
// built-in one, "xs:" prefixed) and returns why it is not valid.
func (r *xsdRun) simpleValue(typ, v string) string {
	if local, ok := strings.CutPrefix(typ, "xs:"); ok {
		why, _ := r.s.x.CheckValue(xsd.Namespace, local, v)
		return why
	}
	why, _ := r.s.x.CheckValue(NS, typ, v)
	return why
}

// mapFS serves the generated schema documents as a file system.
type mapFS map[string]string

func (m mapFS) Open(name string) (fs.File, error) {
	s, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{name: name, r: strings.NewReader(s), size: int64(len(s))}, nil
}

type memFile struct {
	name string
	r    *strings.Reader
	size int64
}

func (f *memFile) Stat() (fs.FileInfo, error) { return memInfo{f.name, f.size}, nil }
func (f *memFile) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *memFile) Close() error               { return nil }

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return 0o444 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

var (
	_ fs.FS     = mapFS(nil)
	_ io.Reader = (*memFile)(nil)
)
