package model

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
)

// SCL representation of a BAP (IEC TR 61850-7-6 Ed. 2.0 Clause 6.1): the
// Application element of the IEC 61850-6-100 SCL extension. We read the
// structure (roles, variants, references) by element and attribute name in
// any namespace. The references are tPathName paths into the rest of the
// SCL file (Function, SubFunction, LNode, SourceRef, ControlRef of IEC
// 61850-6 Ed. 2.1 AMD2 and IEC TR 61850-90-30); resolving them needs those
// schemas and is left to the SCL import (see the hook notes), so paths are
// kept as strings here.

// VariantRef ties an element to a functional variant: update "add" puts
// the element in when the variant is chosen, "remove" takes it out.
type VariantRef struct {
	Variant string
	Update  string
}

// Application is a BAP template or instance.
type Application struct {
	Name, Desc, Type               string
	UUID, TemplateUUID, OriginUUID string
	FunctionRoles                  []FunctionRole
	Variants                       []FunctionalVariant
	VariantGroups                  []FunctionalVariantGroup
	AllocationRoles                []AllocationRoleRef
}

// FunctionalVariant is a variant (or sub variant) with the variables it
// sets.
type FunctionalVariant struct {
	Name, Desc  string
	IsBaseline  bool
	SubVariants []FunctionalVariant
	Variables   []VariableRef
}

// FunctionalVariantGroup holds mutually exclusive variants.
type FunctionalVariantGroup struct {
	Name     string
	Variants []FunctionalVariant
}

// VariableRef overwrites a variable's value.
type VariableRef struct {
	Variable, Value string
}

// AllocationRoleRef refers to an allocation role (IEC TR 61850-90-30).
type AllocationRoleRef struct {
	AllocationRole string
	VariantRefs    []VariantRef
}

// FunctionRole is a role of the application; Cardinality (0..1, 1..1,
// 0..n, 1..n; default 1..1) and Max say how often it may be instantiated.
type FunctionRole struct {
	Name, Type, Cardinality, Selector string
	Max                               int
	Contents                          []FunctionRoleContent
	VariantRefs                       []VariantRef
}

// FunctionRoleContent is the content of one role instance.
type FunctionRoleContent struct {
	RoleInst     string
	FunctionRefs []FunctionRef
	Variables    []VariableRef
	VariantRefs  []VariantRef
}

// FunctionRef refers to a function of the SCL file with its signals.
type FunctionRef struct {
	Function    string
	Signals     []SignalRole
	VariantRefs []VariantRef
}

// SignalRole names a signal of the role and the LNode data it maps to.
type SignalRole struct {
	Name string
	// Inputs are LNodeInputRef sourceRef paths, Outputs LNodeOutputRef
	// controlRef paths, Data LNodeDataRef data paths.
	Inputs, Outputs, Data []string
	VariantRefs           []VariantRef
}

type xnode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []xnode    `xml:",any"`
}

func (n *xnode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n *xnode) children(local string) []*xnode {
	var out []*xnode
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == local {
			out = append(out, &n.Nodes[i])
		}
	}
	return out
}

func variantRefs(n *xnode) []VariantRef {
	var out []VariantRef
	var walk func(x *xnode)
	walk = func(x *xnode) {
		for _, c := range x.children("FunctionalVariantRef") {
			u := c.attr("update")
			if u == "" {
				u = "add"
			}
			out = append(out, VariantRef{Variant: c.attr("functionalVariant"), Update: u})
		}
		// some schemas wrap the refs in a container element
		for _, c := range x.children("FunctionalVariantRefContainer") {
			walk(c)
		}
	}
	walk(n)
	return out
}

func variables(n *xnode) []VariableRef {
	var out []VariableRef
	for _, c := range n.children("VariableRef") {
		out = append(out, VariableRef{Variable: c.attr("variable"), Value: c.attr("value")})
	}
	return out
}

func parseVariant(n *xnode) FunctionalVariant {
	v := FunctionalVariant{Name: n.attr("name"), Desc: n.attr("desc"), IsBaseline: n.attr("isBaseline") == "true", Variables: variables(n)}
	for _, s := range n.children("FunctionalSubVariant") {
		v.SubVariants = append(v.SubVariants, parseVariant(s))
	}
	return v
}

// ParseApplications reads every Application element of an SCL document.
func ParseApplications(r io.Reader) ([]Application, error) {
	var root xnode
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("iec61850 model: SCL: %w", err)
	}
	var out []Application
	var walk func(n *xnode)
	walk = func(n *xnode) {
		if n.XMLName.Local == "Application" {
			out = append(out, parseApplication(n))
			return
		}
		for i := range n.Nodes {
			walk(&n.Nodes[i])
		}
	}
	walk(&root)
	for _, a := range out {
		if a.Name == "" {
			return nil, fmt.Errorf("iec61850 model: SCL: Application without name")
		}
	}
	return out, nil
}

func parseApplication(n *xnode) Application {
	a := Application{Name: n.attr("name"), Desc: n.attr("desc"), Type: n.attr("type"), UUID: n.attr("uuid"), TemplateUUID: n.attr("templateUuid"), OriginUUID: n.attr("originUuid")}
	for _, v := range n.children("FunctionalVariant") {
		a.Variants = append(a.Variants, parseVariant(v))
	}
	for _, g := range n.children("FunctionalVariantGroup") {
		fg := FunctionalVariantGroup{Name: g.attr("name")}
		for _, v := range g.children("FunctionalVariant") {
			fg.Variants = append(fg.Variants, parseVariant(v))
		}
		a.VariantGroups = append(a.VariantGroups, fg)
	}
	for _, r := range n.children("AllocationRoleRef") {
		a.AllocationRoles = append(a.AllocationRoles, AllocationRoleRef{AllocationRole: r.attr("allocationRole"), VariantRefs: variantRefs(r)})
	}
	for _, fr := range n.children("FunctionRole") {
		role := FunctionRole{Name: fr.attr("name"), Type: fr.attr("type"), Cardinality: fr.attr("cardinality"), Selector: fr.attr("selector"), VariantRefs: variantRefs(fr)}
		if role.Cardinality == "" {
			role.Cardinality = "1..1"
		}
		role.Max, _ = strconv.Atoi(fr.attr("max"))
		for _, c := range fr.children("FunctionRoleContent") {
			rc := FunctionRoleContent{RoleInst: c.attr("roleInst"), Variables: variables(c), VariantRefs: variantRefs(c)}
			for _, f := range c.children("FunctionRef") {
				ref := FunctionRef{Function: f.attr("function"), VariantRefs: variantRefs(f)}
				for _, s := range f.children("SignalRole") {
					sr := SignalRole{Name: s.attr("name"), VariantRefs: variantRefs(s)}
					for _, x := range s.children("LNodeInputRef") {
						sr.Inputs = append(sr.Inputs, x.attr("sourceRef"))
					}
					for _, x := range s.children("LNodeOutputRef") {
						sr.Outputs = append(sr.Outputs, x.attr("controlRef"))
					}
					for _, x := range s.children("LNodeDataRef") {
						sr.Data = append(sr.Data, x.attr("data"))
					}
					ref.Signals = append(ref.Signals, sr)
				}
				rc.FunctionRefs = append(rc.FunctionRefs, ref)
			}
			role.Contents = append(role.Contents, rc)
		}
		a.FunctionRoles = append(a.FunctionRoles, role)
	}
	return a
}

// Selected returns the chosen variants completed with the baseline variant
// of every group in which none was chosen; an unknown variant is an error.
func (a *Application) Selected(chosen []string) (map[string]bool, error) {
	all := map[string]bool{}
	var add func(v FunctionalVariant)
	add = func(v FunctionalVariant) {
		all[v.Name] = true
		for _, s := range v.SubVariants {
			add(s)
		}
	}
	for _, v := range a.Variants {
		add(v)
	}
	for _, g := range a.VariantGroups {
		for _, v := range g.Variants {
			add(v)
		}
	}
	sel := map[string]bool{}
	for _, c := range chosen {
		if !all[c] {
			return nil, fmt.Errorf("iec61850 model: application %s has no variant %s", a.Name, c)
		}
		sel[c] = true
	}
	for _, g := range a.VariantGroups {
		any := false
		for _, v := range g.Variants {
			any = any || sel[v.Name]
		}
		if !any {
			for _, v := range g.Variants {
				if v.IsBaseline {
					sel[v.Name] = true
				}
			}
		}
	}
	return sel, nil
}

// active reports whether an element with these variant references is
// part of the application under the selection: an element without
// references always is; one with "add" references needs one of them
// chosen; a chosen "remove" reference takes it out.
func active(refs []VariantRef, sel map[string]bool) bool {
	hasAdd, added := false, false
	for _, r := range refs {
		switch r.Update {
		case "remove":
			if sel[r.Variant] {
				return false
			}
		default:
			hasAdd = true
			if sel[r.Variant] {
				added = true
			}
		}
	}
	return !hasAdd || added
}

// SignalUse is a signal of an active role with the LNode data it maps to.
type SignalUse struct {
	Role, RoleInst, Function, Signal string
	Inputs, Outputs, Data            []string
}

// Signals lists the signals the application uses under the chosen
// variants, in document order.
func (a *Application) Signals(chosen []string) ([]SignalUse, error) {
	sel, err := a.Selected(chosen)
	if err != nil {
		return nil, err
	}
	var out []SignalUse
	for _, r := range a.FunctionRoles {
		if !active(r.VariantRefs, sel) {
			continue
		}
		for _, c := range r.Contents {
			if !active(c.VariantRefs, sel) {
				continue
			}
			for _, f := range c.FunctionRefs {
				if !active(f.VariantRefs, sel) {
					continue
				}
				for _, s := range f.Signals {
					if !active(s.VariantRefs, sel) {
						continue
					}
					out = append(out, SignalUse{Role: r.Name, RoleInst: c.RoleInst, Function: f.Function, Signal: s.Name, Inputs: s.Inputs, Outputs: s.Outputs, Data: s.Data})
				}
			}
		}
	}
	return out, nil
}
