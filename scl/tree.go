// Package scl reads, checks and writes IEC 61850-6 System Configuration
// description Language files (ICD, IID, CID, SCD, SSD, SED and the ISD
// name some tools use), edition 2.2 (namespace version 2007, revision C,
// release 5) and every earlier version a tool has to accept.
//
// A document is kept twice: as a lossless XML tree (Node) that writes back
// every element, attribute, namespace declaration, comment and processing
// instruction in its original order, including Private sections and
// elements of other namespaces that this package does not interpret
// (IEC 61850-6 8.3.6, 8.3.8), and as a typed model (SCL) of the parts the
// IEC 61850 client, a GOOSE subscriber and a server role use.
//
// Validate checks a document against the syntax and the restrictions the
// standard states in text (element structure, attribute value types,
// key/keyref uniqueness and references, versions, the mustUnderstand rule,
// file type rules and the per-clause restrictions of Clause 9); each issue
// carries the clause it comes from. Nothing of the standard's prose or of
// its XML schema machine-readable file is reproduced here: the rules are written
// from the facts (element and attribute names, types, ranges, keys).
package scl

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/ianaindex"
)

// NS is the SCL namespace (IEC 61850-6 Table 53); it has not changed
// since the 2003 version.
const NS = "http://www.iec.ch/61850/2003/SCL"

// XSINS is the XML Schema instance namespace (xsi:type on P elements).
const XSINS = "http://www.w3.org/2001/XMLSchema-instance"

// Kind of a tree item.
type Kind int

const (
	KindElement Kind = iota
	KindText
	KindComment
	KindProcInst
	KindDirective
)

// Attr is an attribute as written: Prefix and Local are the qualified name
// in the file, Space the namespace URI it resolves to ("" for unprefixed
// attributes, which belong to no namespace).
type Attr struct {
	Prefix, Local, Space string
	Value                string
}

// QName is the attribute's name as written.
func (a Attr) QName() string {
	if a.Prefix == "" {
		return a.Local
	}
	return a.Prefix + ":" + a.Local
}

// Node is an element, or a piece of character data, a comment, a
// processing instruction or a directive between elements.
type Node struct {
	Kind Kind
	// Element: qualified name as written and the resolved namespace.
	Prefix, Local, Space string
	Attrs                []Attr
	Children             []*Node
	// Text, comment, processing instruction (Target + Text) or directive.
	Text   string
	Target string
	// Line is the line of the element's start tag in the source (1-based).
	Line int
	// Open marks an empty element written as start and end tag (<a></a>)
	// rather than self-closed.
	Open   bool
	offset int64
	Parent *Node
}

// Attr returns the value of the unprefixed attribute name and whether it
// is present.
func (n *Node) Attr(name string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Prefix == "" && a.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// A returns the value of the unprefixed attribute name, "" when absent.
func (n *Node) A(name string) string {
	v, _ := n.Attr(name)
	return v
}

// SetAttr sets (or adds) an unprefixed attribute.
func (n *Node) SetAttr(name, value string) {
	for i, a := range n.Attrs {
		if a.Prefix == "" && a.Local == name {
			n.Attrs[i].Value = value
			return
		}
	}
	n.Attrs = append(n.Attrs, Attr{Local: name, Value: value})
}

// IsSCL reports whether the node is an element of the SCL namespace.
func (n *Node) IsSCL() bool { return n.Kind == KindElement && n.Space == NS }

// Elements returns the child elements of the SCL namespace with the local
// name (all SCL child elements for "").
func (n *Node) Elements(local string) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.IsSCL() && (local == "" || c.Local == local) {
			out = append(out, c)
		}
	}
	return out
}

// Element returns the first SCL child element with the local name.
func (n *Node) Element(local string) *Node {
	for _, c := range n.Children {
		if c.IsSCL() && c.Local == local {
			return c
		}
	}
	return nil
}

// Content returns the concatenated character data of the element.
func (n *Node) Content() string {
	var b strings.Builder
	for _, c := range n.Children {
		if c.Kind == KindText {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// Path is a readable location of the element: SCL/IED[name=X]/… .
func (n *Node) Path() string {
	var parts []string
	for e := n; e != nil && e.Kind == KindElement; e = e.Parent {
		s := e.Local
		for _, k := range []string{"name", "id", "inst", "iedName", "cbName", "type"} {
			if v, ok := e.Attr(k); ok && v != "" {
				s += "[" + k + "=" + v + "]"
				break
			}
		}
		parts = append(parts, s)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}

// Tree is a parsed document: the items before and after the root (XML
// declaration, comments) and the root element.
type Tree struct {
	Prolog []*Node
	Root   *Node
	Epilog []*Node
	// NoNamespace is set when the root declared no default namespace and
	// the SCL namespace was assumed for unprefixed elements.
	NoNamespace bool
	// Encoding is the declared encoding when it is not UTF-8 or ASCII;
	// the document was converted to UTF-8 when it was read.
	Encoding string
}

// ErrNotSCL is returned for a well-formed document whose root is not SCL.
var ErrNotSCL = errors.New("scl: the root element is not SCL")

// ParseTree reads an XML document into a lossless tree. Namespaces are
// resolved from the declarations in the file; a document without any
// default namespace on an SCL root is read as if the SCL namespace were
// declared (NoNamespace is then set, and Validate reports it).
func ParseTree(raw []byte) (*Tree, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	// Encoding declarations other than UTF-8 (8.4 makes UTF-8 the one to
	// support) are accepted when they are ASCII-compatible names of UTF-8.
	t := &Tree{}
	// Other encodings (ISO-8859-1 and Windows-1252 from older engineering
	// tools, among others) are converted to UTF-8 and recorded in
	// Tree.Encoding, which Validate reports as a warning.
	d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		switch strings.ToUpper(label) {
		case "UTF-8", "UTF8", "US-ASCII", "ASCII":
			return r, nil
		}
		enc, err := ianaindex.IANA.Encoding(label)
		if err != nil || enc == nil {
			enc, err = htmlindex.Get(label)
		}
		if err != nil || enc == nil {
			return nil, fmt.Errorf("scl: encoding %q is not known (UTF-8 is the SCL encoding)", label)
		}
		t.Encoding = label
		return enc.NewDecoder().Reader(r), nil
	}
	type scope map[string]string
	var stack []*Node
	var scopes []scope
	lookup := func(prefix string) (string, bool) {
		if prefix == "xml" {
			return "http://www.w3.org/XML/1998/namespace", true
		}
		for i := len(scopes) - 1; i >= 0; i-- {
			if v, ok := scopes[i][prefix]; ok {
				return v, true
			}
		}
		if prefix == "" {
			return "", true
		}
		return "", false
	}
	add := func(n *Node) {
		if len(stack) == 0 {
			if t.Root == nil {
				if n.Kind == KindText && strings.TrimSpace(n.Text) != "" {
					return
				}
				t.Prolog = append(t.Prolog, n)
			} else {
				t.Epilog = append(t.Epilog, n)
			}
			return
		}
		p := stack[len(stack)-1]
		n.Parent = p
		p.Children = append(p.Children, n)
	}
	for {
		line, _ := d.InputPos()
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("scl: the document is not well-formed XML: %w", err)
		}
		switch tk := tok.(type) {
		case xml.StartElement:
			sc := scope{}
			for _, a := range tk.Attr {
				switch {
				case a.Name.Space == "" && a.Name.Local == "xmlns":
					sc[""] = a.Value
				case a.Name.Space == "xmlns":
					sc[a.Name.Local] = a.Value
				}
			}
			if len(stack) == 0 && t.Root == nil {
				if _, ok := sc[""]; !ok && tk.Name.Space == "" && tk.Name.Local == "SCL" {
					sc[""] = NS
					t.NoNamespace = true
				}
			}
			scopes = append(scopes, sc)
			n := &Node{Kind: KindElement, Prefix: tk.Name.Space, Local: tk.Name.Local, Line: line, offset: d.InputOffset()}
			uri, ok := lookup(n.Prefix)
			if !ok {
				return nil, fmt.Errorf("scl: line %d: namespace prefix %q is not declared", line, n.Prefix)
			}
			n.Space = uri
			for _, a := range tk.Attr {
				at := Attr{Prefix: a.Name.Space, Local: a.Name.Local, Value: a.Value}
				switch {
				case at.Prefix == "" && at.Local == "xmlns", at.Prefix == "xmlns":
					at.Space = "xmlns"
				case at.Prefix != "":
					u, ok := lookup(at.Prefix)
					if !ok {
						return nil, fmt.Errorf("scl: line %d: namespace prefix %q is not declared", line, at.Prefix)
					}
					at.Space = u
				}
				n.Attrs = append(n.Attrs, at)
			}
			if len(stack) == 0 {
				if t.Root != nil {
					return nil, errors.New("scl: the document has more than one root element")
				}
				t.Root = n
			} else {
				add(n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("scl: unbalanced end tag")
			}
			top := stack[len(stack)-1]
			if top.Prefix != tk.Name.Space || top.Local != tk.Name.Local {
				return nil, fmt.Errorf("scl: line %d: end tag %s does not close %s", line, tk.Name.Local, top.Local)
			}
			if len(top.Children) == 0 && d.InputOffset() != top.offset {
				top.Open = true
			}
			stack = stack[:len(stack)-1]
			scopes = scopes[:len(scopes)-1]
		case xml.CharData:
			if len(stack) > 0 {
				if p := stack[len(stack)-1]; len(p.Children) > 0 && p.Children[len(p.Children)-1].Kind == KindText {
					p.Children[len(p.Children)-1].Text += string(tk)
					continue
				}
			}
			add(&Node{Kind: KindText, Text: string(tk)})
		case xml.Comment:
			add(&Node{Kind: KindComment, Text: string(tk)})
		case xml.ProcInst:
			add(&Node{Kind: KindProcInst, Target: tk.Target, Text: string(tk.Inst)})
		case xml.Directive:
			add(&Node{Kind: KindDirective, Text: string(tk)})
		}
	}
	if len(stack) != 0 {
		return nil, errors.New("scl: the document ends inside an element")
	}
	if t.Root == nil {
		return nil, errors.New("scl: the document has no root element")
	}
	if t.Root.Local != "SCL" || t.Root.Space != NS {
		return t, ErrNotSCL
	}
	return t, nil
}

// Bytes writes the tree back. Everything read is written in its original
// order with the original qualified names; character data and attribute
// values are escaped minimally, so a document that used the same escapes
// comes back byte for byte.
func (t *Tree) Bytes() []byte {
	var b bytes.Buffer
	for _, n := range t.Prolog {
		writeNode(&b, n)
	}
	writeNode(&b, t.Root)
	for _, n := range t.Epilog {
		writeNode(&b, n)
	}
	return b.Bytes()
}

func writeNode(b *bytes.Buffer, n *Node) {
	switch n.Kind {
	case KindText:
		escText(b, n.Text)
	case KindComment:
		b.WriteString("<!--")
		b.WriteString(n.Text)
		b.WriteString("-->")
	case KindProcInst:
		b.WriteString("<?")
		b.WriteString(n.Target)
		if n.Text != "" {
			b.WriteByte(' ')
			b.WriteString(n.Text)
		}
		b.WriteString("?>")
	case KindDirective:
		b.WriteString("<!")
		b.WriteString(n.Text)
		b.WriteString(">")
	case KindElement:
		name := n.Local
		if n.Prefix != "" {
			name = n.Prefix + ":" + n.Local
		}
		b.WriteByte('<')
		b.WriteString(name)
		for _, a := range n.Attrs {
			b.WriteByte(' ')
			b.WriteString(a.QName())
			b.WriteString(`="`)
			escAttr(b, a.Value)
			b.WriteByte('"')
		}
		if len(n.Children) == 0 && !n.Open {
			b.WriteString("/>")
			return
		}
		b.WriteByte('>')
		for _, c := range n.Children {
			writeNode(b, c)
		}
		b.WriteString("</")
		b.WriteString(name)
		b.WriteByte('>')
	}
}

func escText(b *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
}

func escAttr(b *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteRune(r)
		}
	}
}

// Equal reports whether two trees carry the same information: the same
// elements (by namespace and local name), attributes (by namespace and
// name, in order), character data, comments and processing instructions.
func Equal(a, b *Tree) bool {
	if a == nil || b == nil {
		return a == b
	}
	return nodesEqual(a.Prolog, b.Prolog) && nodeEqual(a.Root, b.Root) && nodesEqual(a.Epilog, b.Epilog)
}

func nodesEqual(a, b []*Node) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !nodeEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func nodeEqual(a, b *Node) bool {
	if a.Kind != b.Kind || a.Text != b.Text || a.Target != b.Target || a.Space != b.Space || a.Local != b.Local || len(a.Attrs) != len(b.Attrs) {
		return false
	}
	for i := range a.Attrs {
		x, y := a.Attrs[i], b.Attrs[i]
		if x.Space != y.Space || x.Local != y.Local || x.Value != y.Value {
			return false
		}
	}
	return nodesEqual(a.Children, b.Children)
}

// normalized writes the SCL-namespace part of the tree without prefixes,
// Private and Text contents, foreign elements and foreign attributes, so
// encoding/xml can fill the typed model from it.
func (t *Tree) normalized() []byte {
	var b bytes.Buffer
	var w func(n *Node, root bool)
	w = func(n *Node, root bool) {
		b.WriteByte('<')
		b.WriteString(n.Local)
		if root {
			b.WriteString(` xmlns="` + NS + `"`)
		}
		for _, a := range n.Attrs {
			if a.Prefix != "" || a.Local == "xmlns" {
				continue
			}
			b.WriteByte(' ')
			b.WriteString(a.Local)
			b.WriteString(`="`)
			escAttr(&b, a.Value)
			b.WriteByte('"')
		}
		b.WriteByte('>')
		skipBody := n.Local == "Private" || n.Local == "Text"
		if !skipBody {
			for _, c := range n.Children {
				switch {
				case c.Kind == KindText:
					escText(&b, c.Text)
				case c.IsSCL():
					w(c, false)
				}
			}
		}
		b.WriteString("</")
		b.WriteString(n.Local)
		b.WriteByte('>')
	}
	w(t.Root, true)
	return b.Bytes()
}
