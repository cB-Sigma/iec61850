package scl

import "fmt"

// Schema-level checks are IEC's SCL schema, loaded at run time and
// interpreted by xsd.go; the hand-written element table that stood here
// before is gone. What remains are clause rules the XSD cannot express.

// checkPrivate applies 8.3.6: a Private names its owner in type, and its
// content is of another namespace.
func (v *validator) checkPrivate(n *Node) {
	if t, ok := n.Attr("type"); !ok || t == "" {
		v.err(n, "8.3.6", "Private needs a type naming its owner")
	}
	for _, ch := range n.Children {
		if ch.IsSCL() {
			v.err(ch, "8.3.6", "Private content uses the SCL namespace (%s)", ch.Local)
		}
	}
}

func (v *validator) fmtPath(n *Node) string { return fmt.Sprintf("%s (line %d)", n.Path(), n.Line) }
