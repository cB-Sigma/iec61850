// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The name space definitions (NSD) of IEC 61850-7-2, -7-3, -7-4 and the
// IEC 61850-8-1 service name space are published by IEC as code
// components under IEC's own licence. This module does not carry them: an
// application loads them at run time, either from IEC's files (LoadNSD,
// the unpacked "Light" or "full" zips from IEC's download site) or
// from a JSON rendering it keeps itself (SetNSDJSON). Until one of them is
// called, Default and Load return ErrNoNSD.

// ErrNoNSD is returned by Default and Load before the name space
// definitions are loaded.
var ErrNoNSD = errors.New("model: no IEC 61850 name space definitions loaded (call model.LoadNSD with IEC's NSD files; this module does not include them)")

var (
	nsdMu   sync.RWMutex
	nsdData *nsdTables
)

// nsdNamespaces are the name spaces the model is built from, in the order
// their tables are read.
var nsdNamespaces = []string{"IEC 61850-7-2", "IEC 61850-7-3", "IEC 61850-7-4", "IEC 61850-8-1"}

// nsdTablesOf returns the loaded tables (empty ones before loading).
func nsdTablesOf() *nsdTables {
	nsdMu.RLock()
	defer nsdMu.RUnlock()
	if nsdData == nil {
		return &nsdTables{}
	}
	return nsdData
}

func nsdLoaded() bool {
	nsdMu.RLock()
	defer nsdMu.RUnlock()
	return nsdData != nil
}

// installNSD makes t the tables of every model built afterwards and drops
// the cached default model.
func installNSD(t *nsdTables) error {
	if len(t.LNs) == 0 || len(t.CDCs) == 0 || len(t.FCs) == 0 {
		return errors.New("model: the name space definitions have no LN classes, CDCs or functional constraints")
	}
	nsdMu.Lock()
	nsdData = t
	nsdMu.Unlock()
	defMu.Lock()
	defM = nil
	defMu.Unlock()
	return nil
}

// LoadNSD reads IEC's name space definition files from fsys and makes
// them the source of the model: the NSD files of IEC 61850-7-2, -7-3 and
// -7-4 (*.nsd), the IEC 61850-8-1 service name space (*.snsd) with its
// ApplicableServiceNS.AppNS, and optionally the IEC TR 61850-7-6
// application templates (*.asd) that the Basic Application Profiles of
// data/bap.yaml refer to. The files may be anywhere in fsys (the
// directories of IEC's unpacked zips side by side, for example). NSD files
// of other name spaces are ignored. It returns an error naming any of the
// four name spaces that is missing.
func LoadNSD(fsys fs.FS) error {
	t, err := ReadNSD(fsys)
	if err != nil {
		return err
	}
	return installNSD(t.t)
}

// SetNSDJSON makes tables in the JSON form NSDTables.JSON writes the
// source of the model, for an application that converts IEC's files once
// and keeps the result.
func SetNSDJSON(b []byte) error {
	var t nsdTables
	if err := json.Unmarshal(b, &t); err != nil {
		return fmt.Errorf("model: name space definitions: %w", err)
	}
	return installNSD(&t)
}

// NSDTables are name space definitions read by ReadNSD.
type NSDTables struct{ t *nsdTables }

// JSON renders the tables as SetNSDJSON reads them: zero fields omitted,
// one element of a list of records per line.
func (n *NSDTables) JSON() []byte {
	var b bytes.Buffer
	writeNSDJSON(&b, n.t)
	return b.Bytes()
}

// ReadNSD reads IEC's name space definition files from fsys as LoadNSD
// does, without making them the source of the model.
func ReadNSD(fsys fs.FS) (*NSDTables, error) {
	type doc struct {
		file string
		root *nsdNode
	}
	var docs []doc
	var appNS []*nsdNode
	var asds []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".nsd", ".snsd":
			n, err := readXMLFile(fsys, p)
			if err != nil {
				return err
			}
			if rank(n.a("id")) >= 0 {
				docs = append(docs, doc{p, n})
			}
		case ".appns":
			n, err := readXMLFile(fsys, p)
			if err != nil {
				return err
			}
			appNS = append(appNS, n)
		case ".asd":
			asds = append(asds, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("model: reading NSD files: %w", err)
	}
	sort.SliceStable(docs, func(i, j int) bool { return rank(docs[i].root.a("id")) < rank(docs[j].root.a("id")) })
	seen := map[string]string{}
	for _, d := range docs {
		id := d.root.a("id")
		if prev, dup := seen[id]; dup {
			return nil, fmt.Errorf("model: %s is defined twice (%s and %s)", id, prev, d.file)
		}
		seen[id] = d.file
	}
	var missing []string
	for _, ns := range nsdNamespaces {
		if _, ok := seen[ns]; !ok {
			missing = append(missing, ns)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("model: no NSD file for %s", strings.Join(missing, ", "))
	}
	t := &nsdTables{}
	for _, d := range docs {
		if err := readNSDDoc(t, d.root, d.file); err != nil {
			return nil, err
		}
	}
	for _, app := range appNS {
		for _, u := range app.all("ServiceNsUsage") {
			for _, at := range u.all("AppliesTo") {
				rel, _ := strconv.Atoi(at.a("release"))
				t.ServiceAppNS = append(t.ServiceAppNS, nsdAppliesTo{Service: u.a("id") + ":" + u.a("version"), ID: at.a("id"), Version: at.a("version"), Revision: at.a("revision"), Release: rel})
			}
		}
	}
	sort.Strings(asds)
	for _, p := range asds {
		a, err := readASD(fsys, p)
		if err != nil {
			return nil, err
		}
		t.ASDs = append(t.ASDs, *a)
	}
	return &NSDTables{t}, nil
}

func rank(id string) int {
	for i, ns := range nsdNamespaces {
		if ns == id {
			return i
		}
	}
	return -1
}

// nsdNode is a generic XML element.
type nsdNode struct {
	Name     string
	Attrs    map[string]string
	Children []*nsdNode
}

func (n *nsdNode) a(k string) string { return n.Attrs[k] }

func (n *nsdNode) all(name string) []*nsdNode {
	var out []*nsdNode
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func (n *nsdNode) first(name string) *nsdNode {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (n *nsdNode) walk(f func(*nsdNode) bool) {
	if !f(n) {
		return
	}
	for _, c := range n.Children {
		c.walk(f)
	}
}

func readXMLFile(fsys fs.FS, p string) (*nsdNode, error) {
	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	var stack []*nsdNode
	var root *nsdNode
	for {
		tok, err := d.Token()
		if err == io.EOF && root != nil {
			return root, nil
		}
		if err != nil {
			return nil, fmt.Errorf("model: %s: %w", p, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &nsdNode{Name: t.Name.Local, Attrs: map[string]string{}}
			for _, at := range t.Attr {
				if at.Name.Space == "xmlns" || at.Name.Local == "xmlns" {
					continue
				}
				k := at.Name.Local
				if at.Name.Space != "" && at.Name.Space != "http://www.w3.org/2001/XMLSchema-instance" {
					k = at.Name.Space + " " + at.Name.Local
				}
				n.Attrs[k] = at.Value
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, n)
			} else {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
}

func bool1(s string) bool { return s == "true" }

func attrOf(n *nsdNode) nsdAttr {
	return nsdAttr{Kind: n.Name, Name: n.a("name"), Type: n.a("type"), TypeKind: n.a("typeKind"),
		UnderlyingType: n.a("underlyingType"), UnderlyingKind: n.a("underlyingTypeKind"), FC: n.a("fc"),
		Dchg: bool1(n.a("dchg")), Qchg: bool1(n.a("qchg")), Dupd: bool1(n.a("dupd")),
		PresCond: n.a("presCond"), PresCondArgs: n.a("presCondArgs"), DefaultValue: n.a("defaultValue"),
		MinValue: n.a("minValue"), MaxValue: n.a("maxValue"), IsArray: bool1(n.a("isArray")),
		SizeAttribute: n.a("sizeAttribute"), MaxIndexAttr: n.a("maxIndexAttribute"), Deprecated: bool1(n.a("deprecated"))}
}

func attrsOf(n *nsdNode) []nsdAttr {
	var out []nsdAttr
	for _, c := range n.Children {
		switch c.Name {
		case "DataAttribute", "SubDataObject", "ServiceParameter", "SubDataAttribute", "ServiceDataAttribute":
			out = append(out, attrOf(c))
		}
	}
	return out
}

func casOf(n *nsdNode, container, elem, src string) []nsdCA {
	var out []nsdCA
	if cs := n.first(container); cs != nil {
		for _, c := range cs.all(elem) {
			out = append(out, nsdCA{Name: c.a("name"), Source: src, TypeKindParameterized: bool1(c.a("typeKindParameterized")), Attrs: attrsOf(c)})
		}
	}
	return out
}

// readNSDDoc adds one NSD or SNSD document to t.
func readNSDDoc(t *nsdTables, n *nsdNode, file string) error {
	src := strings.TrimPrefix(n.a("id"), "IEC 61850-")
	t.Docs = append(t.Docs, nsdDoc{ID: n.a("id"), Version: n.a("version"), Revision: n.a("revision"), Release: n.a("release"), File: file})
	if bs := n.first("BasicTypes"); bs != nil {
		for _, b := range bs.all("BasicType") {
			t.BasicTypes = append(t.BasicTypes, b.a("name"))
		}
	}
	if fcs := n.first("FunctionalConstraints"); fcs != nil {
		for _, f := range fcs.all("FunctionalConstraint") {
			fc := nsdFC{Name: f.a("abbreviation"), Source: src}
			if as := f.first("ApplicableServices"); as != nil {
				for _, s := range as.all("Service") {
					fc.Services = append(fc.Services, s.a("name"))
				}
				for _, s := range as.all("DataSetMemberOf") {
					fc.DataSetMembers = append(fc.DataSetMembers, s.a("cb"))
				}
			}
			t.FCs = append(t.FCs, fc)
		}
	}
	if ps := n.first("PresenceConditions"); ps != nil {
		for _, p := range ps.all("PresenceCondition") {
			t.PresConds = append(t.PresConds, nsdPresCond{Name: p.a("name"), Argument: p.a("argument"), Source: src})
		}
	}
	if es := n.first("Enumerations"); es != nil {
		for _, e := range es.all("Enumeration") {
			en := nsdEnum{Name: e.a("name"), Source: src}
			for _, l := range e.all("Literal") {
				v, err := strconv.Atoi(l.a("literalVal"))
				if err != nil {
					return fmt.Errorf("model: %s: %s literal %s: %w", file, en.Name, l.a("name"), err)
				}
				en.Items = append(en.Items, nsdLiteral{Name: l.a("name"), Value: v, Deprecated: bool1(l.a("deprecated"))})
			}
			t.Enums = append(t.Enums, en)
		}
	}
	t.CAs = append(t.CAs, casOf(n, "ConstructedAttributes", "ConstructedAttribute", src)...)
	t.ServiceCAs = append(t.ServiceCAs, casOf(n, "ServiceConstructedAttributes", "ServiceConstructedAttribute", src)...)
	if cs := n.first("CDCs"); cs != nil {
		for _, c := range cs.all("CDC") {
			t.CDCs = append(t.CDCs, nsdCDC{Name: c.a("name"), Variant: c.a("variant"), Statistics: bool1(c.a("statistics")),
				EnumParameterized: bool1(c.a("enumParameterized")), TypeKindParameterized: bool1(c.a("typeKindParameterized")), Attrs: attrsOf(c)})
		}
	}
	if as := n.first("Abbreviations"); as != nil {
		for _, a := range as.all("Abbreviation") {
			t.Abbreviations = append(t.Abbreviations, a.a("name"))
		}
	}
	if ls := n.first("LNClasses"); ls != nil {
		for _, l := range ls.Children {
			if l.Name != "LNClass" && l.Name != "AbstractLNClass" {
				continue
			}
			ln := nsdLN{Name: l.a("name"), Base: l.a("base"), Abstract: l.Name == "AbstractLNClass", CanHaveLOG: bool1(l.a("canHaveLOG"))}
			for _, d := range l.all("DataObject") {
				ln.DOs = append(ln.DOs, nsdDO{Name: d.a("name"), Type: d.a("type"), UnderlyingType: d.a("underlyingType"),
					UnderlyingKind: d.a("underlyingTypeKind"), Transient: bool1(d.a("transient")),
					PresCond: d.a("presCond"), PresCondArgs: d.a("presCondArgs"), DsPresCond: d.a("dsPresCond"),
					DsPresCondArgs: d.a("dsPresCondArgs"), Deprecated: bool1(d.a("deprecated"))})
			}
			t.LNs = append(t.LNs, ln)
		}
	}
	if sc := n.first("ServiceCDCs"); sc != nil {
		for _, c := range sc.all("ServiceCDC") {
			t.ServiceCDCs = append(t.ServiceCDCs, nsdServiceCDC{CDC: c.a("cdc"), Attrs: attrsOf(c)})
		}
	}
	if rs := n.first("ServiceTypeRealizations"); rs != nil {
		for _, r := range rs.all("ServiceTypeRealization") {
			t.Realizations = append(t.Realizations, nsdRealization{Name: r.a("name"), Realize: r.a("realize"), Attrs: attrsOf(r)})
		}
	}
	return nil
}

// readASD reads an IEC TR 61850-7-6 application template file.
func readASD(fsys fs.FS, p string) (*asdFile, error) {
	n, err := readXMLFile(fsys, p)
	if err != nil {
		return nil, err
	}
	a := &asdFile{File: path.Base(p)}
	if h := n.first("Header"); h != nil {
		a.HeaderID, a.UUID = h.a("id"), h.a("uuid")
	}
	var fn func(x *nsdNode, where []string)
	fn = func(x *nsdNode, where []string) {
		for _, c := range x.Children {
			switch c.Name {
			case "Substation", "VoltageLevel", "Bay":
				fn(c, append(append([]string(nil), where...), c.a("name")))
			case "Function":
				f := asdFunction{Path: strings.Join(append(append([]string(nil), where...), c.a("name")), "/")}
				for _, ln := range c.all("LNode") {
					l := asdLNode{Prefix: ln.a("prefix"), LNClass: ln.a("lnClass"), LNInst: ln.a("lnInst"), LNType: ln.a("lnType")}
					ln.walk(func(y *nsdNode) bool {
						if y.Name == "SourceRef" {
							l.Inputs = append(l.Inputs, asdInput{Service: y.a("service"), Input: y.a("input"), InputInst: y.a("inputInst"),
								PLN: y.a("pLN"), PDO: y.a("pDO"), PDA: y.a("pDA"), Source: y.a("source"), Resource: y.a("resourceName")})
						}
						return true
					})
					f.LNodes = append(f.LNodes, l)
				}
				a.Functions = append(a.Functions, f)
			}
		}
	}
	fn(n, nil)
	n.walk(func(x *nsdNode) bool {
		if x.Name != "Application" {
			return true
		}
		app := asdApp{Name: x.a("name")}
		for _, r := range x.all("FunctionRole") {
			role := asdRole{Name: r.a("name")}
			for _, c := range r.all("FunctionRoleContent") {
				for _, f := range c.all("FunctionRef") {
					role.Functions = append(role.Functions, f.a("function"))
					for _, s := range f.all("SignalRole") {
						sig := asdSignal{Function: f.a("function"), Name: s.a("name")}
						for _, in := range s.all("LNodeInputRef") {
							sig.Inputs = append(sig.Inputs, in.a("sourceRef"))
						}
						role.Signals = append(role.Signals, sig)
					}
				}
			}
			app.Roles = append(app.Roles, role)
		}
		a.Applications = append(a.Applications, app)
		return false
	})
	if dt := n.first("DataTypeTemplates"); dt != nil {
		for _, lt := range dt.all("LNodeType") {
			t := asdLNodeType{ID: lt.a("id"), LNClass: lt.a("lnClass")}
			for _, d := range lt.all("DO") {
				t.DOs = append(t.DOs, asdDO{Name: d.a("name"), Type: d.a("type")})
			}
			a.LNodeTypes = append(a.LNodeTypes, t)
		}
		for _, dot := range dt.all("DOType") {
			t := asdDOType{ID: dot.a("id"), CDC: dot.a("cdc")}
			for _, d := range dot.all("DA") {
				t.DAs = append(t.DAs, asdDA{Name: d.a("name"), FC: d.a("fc"), BType: d.a("bType"), Type: d.a("type")})
			}
			a.DOTypes = append(a.DOTypes, t)
		}
	}
	if len(a.Applications) == 0 {
		return nil, fmt.Errorf("model: %s: no Application", a.File)
	}
	return a, nil
}

// writeNSDJSON writes t as JSON with zero fields omitted and one record
// of a list per line.
func writeNSDJSON(b *bytes.Buffer, t *nsdTables) {
	raw, _ := json.Marshal(t)
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&v)
	writeJSONValue(b, prune(v))
}

// prune drops zero values (false, 0, "", empty lists and objects).
func prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			e = prune(e)
			if isZero(e) {
				delete(x, k)
				continue
			}
			x[k] = e
		}
		return x
	case []any:
		for i := range x {
			x[i] = prune(x[i])
		}
		return x
	}
	return v
}

func isZero(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	case json.Number:
		return x.String() == "0"
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func writeJSONValue(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(":")
			writeJSONValue(b, x[k])
		}
		b.WriteString("}")
	case []any:
		multi := len(x) > 0
		if multi {
			_, multi = x[0].(map[string]any)
		}
		b.WriteString("[")
		for i, e := range x {
			if i > 0 {
				b.WriteString(",")
			}
			if multi {
				b.WriteString("\n")
			}
			writeJSONValue(b, e)
		}
		if multi {
			b.WriteString("\n")
		}
		b.WriteString("]")
	default:
		eb, _ := json.Marshal(x)
		b.Write(eb)
	}
}
