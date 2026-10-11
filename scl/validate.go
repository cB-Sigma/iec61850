package scl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Severity of an issue.
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Issue is one finding of Validate.
type Issue struct {
	Severity Severity
	// Clause is the IEC 61850-6 clause (or table) the rule comes from.
	Clause string
	Path   string
	Line   int
	Msg    string
	// Structural marks an error that leaves the model unusable where it
	// occurs (a dangling or ambiguous type or data set reference, an
	// unknown mustUnderstand element); Options.Lenient keeps it an error.
	Structural bool
	// Accepted marks a departure from IEC 61850-6 or the XSD that
	// Options.Lenient reported as a warning instead of an error.
	Accepted bool
}

// String names the value.
func (i Issue) String() string {
	return fmt.Sprintf("%s: %s (line %d): %s [IEC 61850-6 %s]", i.Severity, i.Path, i.Line, i.Msg, i.Clause)
}

// Issues is a validation result.
type Issues []Issue

// Errors returns the errors only.
func (is Issues) Errors() Issues {
	var out Issues
	for _, i := range is {
		if i.Severity == Error {
			out = append(out, i)
		}
	}
	return out
}

// Has reports whether an issue's message contains s.
func (is Issues) Has(s string) bool {
	for _, i := range is {
		if strings.Contains(i.Msg, s) {
			return true
		}
	}
	return false
}

// Options tune Validate.
type Options struct {
	// FileType is the kind of file (ICD, IID, CID, SCD, SSD, SED, ISD);
	// "" takes Header fileType, else no file type rules apply.
	FileType string
	// RefuseNewer makes a document of a newer SCL version than Supported
	// an error (IEC 61850-6 Table G.2 S14 for system tools); otherwise a
	// warning.
	RefuseNewer bool
	// Lenient reports the departures vendor tools commonly make as
	// warnings (Issue.Accepted) instead of errors: schema departures of
	// any version (element order, missing or extra attributes, values
	// outside an XSD enumeration or pattern, other-namespace elements
	// after SCL elements), a missing namespace declaration or version
	// attribute, and the clause 9 rules on names, counts and values. Only
	// structural errors (Issue.Structural) stay errors.
	Lenient bool
}

type validator struct {
	d      *Document
	opt    Options
	issues Issues
	// nodes indexes tree elements by typed-model identity for positions.
	iedNode map[string]*Node
}

func (v *validator) add(sev Severity, n *Node, clause, format string, args ...any) *Issue {
	i := Issue{Severity: sev, Clause: clause, Msg: fmt.Sprintf(format, args...)}
	if n != nil {
		i.Path, i.Line = n.Path(), n.Line
	}
	v.issues = append(v.issues, i)
	return &v.issues[len(v.issues)-1]
}

// err reports a departure from IEC 61850-6 or the schema: an error, or
// with Options.Lenient an accepted warning.
func (v *validator) err(n *Node, clause, format string, args ...any) {
	i := v.add(Error, n, clause, format, args...)
	if v.opt.Lenient {
		i.Severity, i.Accepted = Warning, true
	}
}

// errS reports a structural error: the model cannot be used where it
// occurs, so it stays an error in every mode.
func (v *validator) errS(n *Node, clause, format string, args ...any) {
	v.add(Error, n, clause, format, args...).Structural = true
}

func (v *validator) warn(n *Node, clause, format string, args ...any) {
	v.add(Warning, n, clause, format, args...)
}

// Validate checks the document. Errors are departures from what IEC
// 61850-6 requires; warnings are what a receiver ignores or tolerates
// (unknown elements without mustUnderstand, deprecated values, newer
// versions).
func Validate(d *Document, opt Options) Issues {
	v := &validator{d: d, opt: opt, iedNode: map[string]*Node{}}
	root := d.Tree.Root
	if d.Tree.NoNamespace {
		v.err(root, "8.3.5", "the SCL namespace %s is not declared as default namespace", NS)
	}
	if e := d.Tree.Encoding; e != "" {
		v.warn(root, "8.4", "the document is encoded in %s, not UTF-8; it was converted", e)
	}
	v.checkSchema()
	v.checkVersion(opt)
	v.checkRoot()
	for _, n := range root.Elements("IED") {
		v.iedNode[n.A("name")] = n
	}
	v.checkProcess()
	v.checkIEDs()
	v.checkCommunication()
	v.checkTemplates()
	ft := opt.FileType
	if ft == "" && d.SCL.Header != nil {
		ft = d.SCL.Header.FileType
	}
	if ft != "" {
		v.checkFileType(strings.ToUpper(ft))
	}
	sort.SliceStable(v.issues, func(i, j int) bool { return v.issues[i].Line < v.issues[j].Line })
	return v.issues
}

func (v *validator) checkVersion(opt Options) {
	s := v.d.SCL
	root := v.d.Tree.Root
	ver := s.SchemaVersion()
	if Supported.Less(ver) {
		if opt.RefuseNewer {
			v.err(root, "Table G.2", "SCL version %s is newer than the supported %s", ver, Supported)
		} else {
			v.warn(root, "8.2.2", "SCL version %s is newer than the supported %s: unknown elements are ignored unless marked mustUnderstand", ver, Supported)
		}
	}
	if s.Version == "" {
		// 8.2.2: the version attribute is required for any instance using
		// what came after 2003; the Ed. 2 additions are a sure sign.
		for _, marker := range []string{"ServerAt", "ClientServices", "Line", "Process", "LogSettings", "ConfLdName"} {
			if findLocal(root, marker) != nil {
				v.err(root, "8.2.2", "the SCL version attribute is missing but the document uses %s (introduced after 2003)", marker)
				break
			}
		}
	}
	if s.Version != "" && ver.Year >= 2007 && s.Revision == "" {
		v.warn(root, "8.2.2", "the revision attribute is missing (default A)")
	}
	for i := range s.IEDs {
		ied := &s.IEDs[i]
		if ied.OriginalSclVersion != "" && ied.OriginalSclRev == "" && ied.OriginalSclVersion != "2003" {
			v.warn(v.iedNode[ied.Name], "I.4.3.3", "originalSclRevision is missing for original version %s", ied.OriginalSclVersion)
		}
	}
}

func findLocal(n *Node, local string) *Node {
	for _, c := range n.Children {
		if c.IsSCL() {
			if c.Local == local {
				return c
			}
			if f := findLocal(c, local); f != nil {
				return f
			}
		}
	}
	return nil
}

func (v *validator) checkRoot() {
	root := v.d.Tree.Root
	s := v.d.SCL
	if len(s.Substations)+len(s.Lines)+len(s.Processes)+len(s.IEDs) == 0 && s.Communication == nil && s.DataTypeTemplates == nil {
		v.err(root, "8.4", "an SCL document needs a Header and at least one of Substation/Process/Line, Communication, IED, DataTypeTemplates")
	}
	// SubstationKey: Substation, Process and Line names unique at top level.
	seen := map[string]bool{}
	for _, n := range root.Children {
		if n.IsSCL() && (n.Local == "Substation" || n.Local == "Line" || n.Local == "Process") {
			nm := n.A("name")
			if seen[nm] {
				v.err(n, "9.2.1", "process element name %q is used twice at the top level", nm)
			}
			seen[nm] = true
		}
	}
	// IEDKey.
	seen = map[string]bool{}
	for _, n := range root.Elements("IED") {
		nm := n.A("name")
		if seen[nm] {
			v.errS(n, "9.3.2", "IED name %q is used twice", nm)
		}
		seen[nm] = true
	}
	if h := s.Header; h != nil {
		hs := map[string]bool{}
		hn := root.Element("Header")
		for _, it := range h.History {
			k := it.Version + "/" + it.Revision
			if hs[k] {
				v.err(hn, "9.1", "history item version %s revision %s is listed twice", it.Version, it.Revision)
			}
			hs[k] = true
		}
		for _, r := range append(append([]SclFileReference{}, h.SourceFiles...), allHistorySources(h)...) {
			if r.FileUUID == "" && r.FileName == "" {
				v.err(hn, "9.1", "an SclFileReference needs fileUuid or fileName")
			}
		}
		if h.NameStructure != "" && h.NameStructure != "IEDName" {
			v.warn(hn, "8.2.3", "nameStructure %q is no longer supported and is ignored", h.NameStructure)
		}
	}
}

func allHistorySources(h *Header) []SclFileReference {
	var out []SclFileReference
	for _, it := range h.History {
		out = append(out, it.SourceFiles...)
	}
	return out
}

// checkProcess applies 9.2: unique names per level, LNode keys and links,
// connectivity node keys and terminal references.
func (v *validator) checkProcess() {
	root := v.d.Tree.Root
	cnodes := map[string]*Node{}
	var terminals []*Node
	lnodeGlobal := map[string]*Node{}
	var walk func(n *Node, inLine bool)
	walk = func(n *Node, inLine bool) {
		names := map[string]bool{}
		lnodes := map[string]bool{}
		for _, ch := range n.Children {
			if !ch.IsSCL() {
				continue
			}
			switch ch.Local {
			case "LNode":
				k := strings.Join([]string{ch.A("lnInst"), ch.A("lnClass"), orDefault(ch.A("iedName"), "None"), ch.A("ldInst"), ch.A("prefix")}, "|")
				if lnodes[k] {
					v.err(ch, "9.2.1", "two LNode elements with the same lnInst, lnClass, iedName, ldInst and prefix at one level")
				}
				lnodes[k] = true
				ied := orDefault(ch.A("iedName"), "None")
				if ied != "None" {
					if prev := lnodeGlobal[k]; prev != nil {
						v.err(ch, "9.2.6", "logical node %s is linked from two process elements", lnodeRef(ch))
					}
					lnodeGlobal[k] = ch
					v.checkLNodeTarget(ch)
				}
				if ch.A("lnClass") != "LLN0" && ch.A("lnInst") == "" {
					v.err(ch, "9.2.6", "lnInst is required unless lnClass is LLN0")
				}
				continue
			case "Terminal", "NeutralPoint":
				terminals = append(terminals, ch)
				if !inLine && ch.A("lineName") != "" {
					v.err(ch, "9.2.4", "a terminal outside a Line references a Line connectivity node")
				}
				continue
			case "ConnectivityNode":
				p := ch.A("pathName")
				if cnodes[p] != nil {
					v.err(ch, "9.2.1", "connectivity node pathName %q is used twice", p)
				}
				cnodes[p] = ch
			case "Text", "Private", "Labels", "Voltage":
				continue
			}
			if nm, ok := ch.Attr("name"); ok {
				if names[nm] {
					v.err(ch, "9.2.1", "name %q is used twice below %s", nm, n.Local)
				}
				names[nm] = true
			}
			walk(ch, inLine || ch.Local == "Line")
		}
	}
	for _, n := range root.Children {
		if n.IsSCL() && (n.Local == "Substation" || n.Local == "Line" || n.Local == "Process") {
			walk(n, n.Local == "Line")
		}
	}
	for _, t := range terminals {
		cn := t.A("connectivityNode")
		target := cnodes[cn]
		if target == nil {
			if cn != "" && !strings.HasSuffix(cn, "/grounded") {
				v.err(t, "9.2.1", "terminal references connectivity node %q which is not defined", cn)
			}
			continue
		}
		inLine := func(n *Node) bool {
			for e := n; e != nil; e = e.Parent {
				if e.Local == "Line" {
					return true
				}
			}
			return false
		}
		if !inLine(t) && inLine(target) {
			v.err(t, "9.2.1", "a substation terminal may not reference a connectivity node inside a Line")
		}
		if want := t.A("cNodeName"); want != "" && target.A("name") != want {
			v.err(t, "9.2.4", "cNodeName %q differs from the referenced node's name %q", want, target.A("name"))
		}
		if sub := t.A("substationName"); sub != "" && !strings.HasPrefix(cn, sub+"/") {
			v.err(t, "9.2.4", "substationName %q does not match the connectivity node path", sub)
		}
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func lnodeRef(n *Node) string {
	return n.A("iedName") + n.A("ldInst") + "/" + n.A("prefix") + n.A("lnClass") + n.A("lnInst")
}

func (v *validator) checkLNodeTarget(n *Node) {
	ied, err := v.d.IED(n.A("iedName"))
	if err != nil {
		v.err(n, "9.2.6", "LNode references IED %q which is not in the file", n.A("iedName"))
		return
	}
	ld, _ := ied.LDevice(n.A("ldInst"))
	if ld == nil {
		v.err(n, "9.2.6", "LNode references logical device %s of IED %s which does not exist", n.A("ldInst"), ied.Name)
		return
	}
	if ld.LN(n.A("prefix"), n.A("lnClass"), n.A("lnInst")) == nil {
		v.err(n, "9.2.6", "LNode references %s which does not exist", lnodeRef(n))
	}
}

// ldNode finds the tree node of a logical device for positions.
func (v *validator) ldNode(ied, inst string) *Node {
	n := v.iedNode[ied]
	if n == nil {
		return nil
	}
	for _, ap := range n.Elements("AccessPoint") {
		if s := ap.Element("Server"); s != nil {
			for _, ld := range s.Elements("LDevice") {
				if ld.A("inst") == inst {
					return ld
				}
			}
		}
	}
	return n
}

func (v *validator) lnNode(ldn *Node, ln *LN) *Node {
	if ldn == nil {
		return nil
	}
	if ln.LNClass == "LLN0" {
		if n := ldn.Element("LN0"); n != nil {
			return n
		}
		return ldn
	}
	for _, n := range ldn.Elements("LN") {
		if n.A("lnClass") == ln.LNClass && n.A("inst") == ln.Inst && n.A("prefix") == ln.Prefix {
			return n
		}
	}
	return ldn
}

func childNamed(n *Node, local, attr, value string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Elements(local) {
		if c.A(attr) == value {
			return c
		}
	}
	return n
}

// checkIEDs applies 9.3.
func (v *validator) checkIEDs() {
	s := v.d.SCL
	ldNames := map[string]string{}
	appIDs := map[string]string{}
	for i := range s.IEDs {
		ied := &s.IEDs[i]
		in := v.iedNode[ied.Name]
		aps := map[string]bool{}
		for _, ap := range ied.AccessPoints {
			if aps[ap.Name] {
				v.err(in, "9.3.2", "access point name %q is used twice", ap.Name)
			}
			aps[ap.Name] = true
		}
		mr := map[string]bool{}
		for _, f := range ied.MinRequestedSCDFiles {
			if f.FileUUID != "" && mr[f.FileUUID] {
				v.err(in, "9.3.2", "two MinRequestedSCDFile entries have fileUuid %s", f.FileUUID)
			}
			mr[f.FileUUID] = true
			if f.FileType != "" && f.FileType != "SCD" {
				v.err(in, "9.3.2", "MinRequestedSCDFile fileType must be SCD")
			}
		}
		lds := map[string]bool{}
		for j := range ied.AccessPoints {
			ap := &ied.AccessPoints[j]
			apn := childNamed(in, "AccessPoint", "name", ap.Name)
			if ap.ServerAt != nil {
				t := ied.AccessPoint(ap.ServerAt.APName)
				if t == nil || t.Server == nil {
					v.err(apn, "9.3.2", "ServerAt references access point %q which has no server", ap.ServerAt.APName)
				}
			}
			if len(ap.GOOSESecurity)+len(ap.SMVSecurity) > 0 {
				srv := ap.Server
				if srv == nil && ap.ServerAt != nil {
					if t := ied.AccessPoint(ap.ServerAt.APName); t != nil {
						srv = t.Server
					}
				}
				if srv == nil || srv.Authentication == nil || !parseBool(srv.Authentication.Certificate, false) {
					v.err(apn, "9.3.3", "GOOSESecurity and SMVSecurity need Authentication certificate=\"true\"")
				}
			}
			for _, c := range []string{"ConfLNs", "ConfLdName", "ValueHandling"} {
				if ap.Services.Get(c) != nil {
					v.err(apn, "9.3.2", "service capability %s belongs at IED level only", c)
				}
			}
			v.checkClientLNs(ied, ap, apn)
			if ap.Server == nil {
				continue
			}
			assoc := map[string]bool{}
			for _, as := range ap.Server.Associations {
				if as.AssociationID != "" {
					if assoc[as.AssociationID] {
						v.err(apn, "9.3.14", "association ID %q is used twice in the server", as.AssociationID)
					}
					assoc[as.AssociationID] = true
				}
				if as.APRef == "" {
					v.warn(apn, "I.5.3.3", "Association without apRef (required since edition 2.2)")
				}
			}
			for k := range ap.Server.LDevices {
				ld := &ap.Server.LDevices[k]
				ldn := v.ldNode(ied.Name, ld.Inst)
				if lds[ld.Inst] {
					v.errS(ldn, "9.3.2", "logical device inst %q is used twice in the IED", ld.Inst)
				}
				lds[ld.Inst] = true
				name := ld.Name(ied.Name)
				if len(name) > 64 || !reLDName.MatchString(name) {
					v.err(ldn, "9.3.4", "logical device name %q is not 1 to 64 letters, digits and underscore starting with a letter", name)
				}
				if prev, ok := ldNames[name]; ok && ied.Name != "TEMPLATE" {
					v.err(ldn, "9.3.4", "logical device name %q is also used by %s", name, prev)
				}
				ldNames[name] = ied.Name + "/" + ld.Inst
				v.checkLDevice(ied, ap, ld, ldn, appIDs)
			}
		}
	}
}

func (v *validator) checkClientLNs(ied *IED, ap *AccessPoint, apn *Node) {
	seen := map[string]bool{}
	for _, ln := range ap.LNs {
		k := ln.Prefix + ln.LNClass + ln.Inst
		if seen[k] {
			v.errS(apn, "9.3.5", "LN %s is defined twice in the access point", k)
		}
		seen[k] = true
		v.checkLNType(&ln, apn)
	}
}

func (v *validator) checkLNType(ln *LN, n *Node) {
	lt, ok := v.d.Types.LNodeTypes[ln.LNType]
	if !ok {
		v.errS(n, "9.3.5", "lnType %q of %s is not defined in DataTypeTemplates", ln.LNType, ln.Name())
		return
	}
	if lt.LNClass != ln.LNClass {
		v.err(n, "9.3.5", "lnType %q is of class %s, not %s", ln.LNType, lt.LNClass, ln.LNClass)
	}
	if ln.LNClass != "LLN0" && len(ln.Inst) > 7 {
		v.warn(n, "9.3.5", "LN instance %q has more than 7 digits", ln.Inst)
	}
	if len(ln.Inst) > 1 && ln.Inst[0] == '0' {
		v.warn(n, "9.3.5", "LN instance %q has a leading zero", ln.Inst)
	}
}

func (v *validator) checkLDevice(ied *IED, ap *AccessPoint, ld *LDevice, ldn *Node, appIDs map[string]string) {
	if ld.LN0 == nil {
		return // reported by the structure check
	}
	names := map[string]bool{}
	for _, ln := range ld.AllLNs() {
		lnn := v.lnNode(ldn, ln)
		k := ln.Name()
		if names[k] {
			v.errS(lnn, "9.3.5", "LN %s is defined twice in the logical device", k)
		}
		names[k] = true
		v.checkLNType(ln, lnn)
		if ln.LNClass != "LLN0" {
			if len(ln.Logs) > 0 {
				v.warn(lnn, "9.3.5", "Log elements are only allowed in LLN0 and a few special LN classes")
			}
			if len(ln.GSEControls)+len(ln.SampledValueControls) > 0 || ln.SettingControl != nil {
				v.err(lnn, "9.3.10", "GSE, sampled value and setting control blocks are only allowed in LLN0")
			}
		}
		logs := map[string]bool{}
		for _, l := range ln.Logs {
			nm := orDefault(l.Name, ld.Inst)
			if logs[nm] {
				v.err(lnn, "9.3.5", "log name %q is used twice in the LN", nm)
			}
			logs[nm] = true
		}
		v.checkDOIs(ied, ld, ln, lnn)
		dsNames := map[string]bool{}
		for _, ds := range ln.DataSets {
			dsn := childNamed(lnn, "DataSet", "name", ds.Name)
			if dsNames[ds.Name] {
				v.err(dsn, "9.3.7", "data set name %q is used twice in the LN", ds.Name)
			}
			dsNames[ds.Name] = true
			v.checkDataSet(ied, ap, ld, &ds, dsn)
		}
		cbNames := map[string]bool{}
		cb := func(kind, name string, n *Node) {
			if cbNames[kind+name] {
				v.err(n, "9.3.8", "%s name %q is used twice in the LN", kind, name)
			}
			cbNames[kind+name] = true
		}
		for _, rc := range ln.ReportControls {
			rcn := childNamed(lnn, "ReportControl", "name", rc.Name)
			cb("report control block", rc.Name, rcn)
			v.checkDatSetRef(ln, rc.DatSet, rc.ConfRev, true, rcn, "9.3.8")
			if rc.RptID != nil && *rc.RptID == "" {
				v.warn(rcn, "9.3.8", "rptID is the empty string (accepted for backward compatibility; leave it out for NULL)")
			}
			if rc.RptEnabled != nil && strings.TrimSpace(rc.RptEnabled.Max) == "0" {
				v.err(rcn, "I.4.3.5", "RptEnabled max is 0")
			}
			if !rc.IsIndexed() && rc.IsBuffered() && rc.Max() > 1 {
				v.err(rcn, "9.3.8", "a buffered block with indexed=false allows only max=1")
			}
			if !rc.IsIndexed() && !rc.IsBuffered() && rc.Max() != 1 {
				dyn := ied.Service(ap, "DynAssociation")
				m, _ := dyn.Attr("max")
				if m != strconv.Itoa(rc.Max()) {
					v.err(rcn, "9.3.8", "an unbuffered block with indexed=false needs max 1 or DynAssociation max")
				}
			}
			if rc.OptFields != nil && rc.OptFields.Segmentation != "" {
				v.warn(rcn, "9.3.8", "OptFields segmentation is deprecated and ignored")
			}
			if rc.RptEnabled != nil {
				if len(rc.RptEnabled.ClientLNs) > rc.Max() {
					v.err(rcn, "9.3.8", "RptEnabled lists %d clients for max %d", len(rc.RptEnabled.ClientLNs), rc.Max())
				}
				for _, c := range rc.RptEnabled.ClientLNs {
					if c.APRef == "" {
						v.warn(rcn, "I.5.3.2", "ClientLN without apRef (required since edition 2.2)")
					}
					if c.Prefix != "" && strings.TrimSpace(c.Prefix) == "" {
						v.err(rcn, "9.3.8", "ClientLN prefix is blank")
					}
					cied, err := v.d.IED(c.IEDName)
					if err != nil {
						if ied.Name != "TEMPLATE" {
							v.warn(rcn, "9.3.8", "client IED %s is not in the file", c.IEDName)
						}
						continue
					}
					if cap := cied.AccessPoint(c.APRef); cap != nil && cap.Server == nil && cap.ServerAt == nil && c.LDInst != "LD0" {
						v.warn(rcn, "9.3.8", "ClientLN of a pure client access point should use ldInst LD0, not %q", c.LDInst)
					}
				}
			}
		}
		for _, lc := range ln.LogControls {
			lcn := childNamed(lnn, "LogControl", "name", lc.Name)
			cb("log control block", lc.Name, lcn)
			v.checkDatSetRef(ln, lc.DatSet, "", false, lcn, "9.3.9")
			tld := ld
			if lc.LDInst != "" && lc.LDInst != ld.Inst {
				tld, _ = ied.LDevice(lc.LDInst)
			}
			if tld == nil {
				v.err(lcn, "9.3.9", "log control block references logical device %s which does not exist", lc.LDInst)
				continue
			}
			tln := tld.LN(lc.Prefix, orDefault(lc.LNClass, "LLN0"), lc.LNInst)
			found := false
			if tln != nil {
				for _, l := range tln.Logs {
					if orDefault(l.Name, tld.Inst) == lc.LogName {
						found = true
					}
				}
			}
			if !found {
				v.err(lcn, "9.3.9", "log %q referenced by the log control block does not exist", lc.LogName)
			}
		}
		for _, gc := range ln.GSEControls {
			gcn := childNamed(lnn, "GSEControl", "name", gc.Name)
			cb("GSE control block", gc.Name, gcn)
			goose := gc.Type == "" || gc.Type == "GOOSE"
			if goose && gc.ConfRev == "" {
				v.err(gcn, "9.3.10", "confRev is required for a GOOSE control block")
			}
			if gc.Type == "GSSE" {
				v.warn(gcn, "9.3.10", "GSSE is deprecated")
			}
			v.checkDatSetRef(ln, gc.DatSet, gc.ConfRev, goose, gcn, "9.3.10")
			if gc.AppID != "" && ied.Name != "TEMPLATE" {
				if prev, ok := appIDs[gc.AppID]; ok {
					v.warn(gcn, "9.3.10", "appID %q is also used by %s", gc.AppID, prev)
				}
				appIDs[gc.AppID] = ied.Name + "/" + ld.Inst + "/" + gc.Name
			}
			v.checkSecurity(ied, ap, "GSESettings", gc.SecurityEnable, gcn)
			v.checkProtocol(gc.Protocol, "R-GOOSE", gcn)
			v.checkIEDNames(gc.IEDNames, gcn)
		}
		for _, sv := range ln.SampledValueControls {
			svn := childNamed(lnn, "SampledValueControl", "name", sv.Name)
			cb("sampled value control block", sv.Name, svn)
			if sv.ConfRev == "" {
				v.err(svn, "9.3.11", "confRev is required for a sampled value control block")
			}
			v.checkDatSetRef(ln, sv.DatSet, sv.ConfRev, true, svn, "9.3.11")
			if !parseBool(sv.Multicast, true) && len(sv.IEDNames) > 1 {
				v.err(svn, "9.3.11", "a unicast sampled value control block has at most one subscriber")
			}
			if sv.SmvOpts != nil {
				if sv.SmvOpts.SampleSynchronized != "" && !parseBool(sv.SmvOpts.SampleSynchronized, true) {
					v.err(svn, "8.2.3", "SmvOpts sampleSynchronized may not be false")
				}
				if parseBool(sv.SmvOpts.DataRef, false) {
					v.err(svn, "9.3.11", "SmvOpts dataRef is deprecated and only false is accepted")
				}
			}
			v.checkSecurity(ied, ap, "SMVSettings", sv.SecurityEnable, svn)
			v.checkProtocol(sv.Protocol, "R-SV", svn)
			v.checkIEDNames(sv.IEDNames, svn)
		}
		if sc := ln.SettingControl; sc != nil {
			n, _ := strconv.Atoi(sc.NumOfSGs)
			if a, err := strconv.Atoi(orDefault(sc.ActSG, "1")); err == nil && n > 0 && a > n {
				v.err(lnn, "9.3.12", "actSG %d is above numOfSGs %d", a, n)
			}
		}
		if ln.Inputs != nil {
			for _, er := range ln.Inputs.ExtRefs {
				v.checkExtRef(er, lnn)
			}
		}
	}
}

func (v *validator) checkSecurity(ied *IED, ap *AccessPoint, settings, enable string, n *Node) {
	if enable == "" || enable == "None" {
		return
	}
	mc := ied.Service(ap, settings).Get("McSecurity")
	if mc == nil {
		v.err(n, "9.3.10", "securityEnable %s needs McSecurity in %s", enable, settings)
		return
	}
	if !mc.Bool("signature", false) || (enable == "SignatureAndEncryption" && !mc.Bool("encryption", false)) {
		v.err(n, "9.3.10", "securityEnable %s is not offered by %s McSecurity", enable, settings)
	}
}

func (v *validator) checkProtocol(p *Protocol, want string, n *Node) {
	if p == nil {
		return
	}
	if strings.TrimSpace(p.Value) != want {
		v.err(n, "9.3.10", "Protocol is %q, expected %s", p.Value, want)
	}
	if !parseBool(p.MustUnderstand, false) {
		v.err(n, "8.2.1", "Protocol must carry mustUnderstand=\"true\"")
	}
}

func (v *validator) checkIEDNames(list []IEDName, n *Node) {
	for _, in := range list {
		name := strings.TrimSpace(in.Name)
		if why := types["tIEDName"](name); why != "" {
			v.err(n, "9.3.10", "IEDName %q %s", name, why)
		}
		if in.APRef == "" {
			v.warn(n, "I.5.3.1", "IEDName %s without apRef (required since edition 2.2)", name)
		}
	}
}

func (v *validator) checkDatSetRef(ln *LN, datSet, confRev string, hasConfRev bool, n *Node, clause string) {
	if datSet != "" && ln.DataSet(datSet) == nil {
		v.errS(n, clause, "data set %q is not defined in the same LN", datSet)
	}
	if hasConfRev && datSet != "" && strings.TrimSpace(confRev) == "0" {
		v.err(n, clause, "confRev 0 is only allowed without a data set")
	}
}

func (v *validator) checkExtRef(er ExtRef, n *Node) {
	if er.SrcCBName == "" && (er.SrcLDInst != "" || er.SrcPrefix != "" || er.SrcLNClass != "" || er.SrcLNInst != "") {
		v.err(n, "9.3.13", "ExtRef has source control block attributes without srcCBName")
	}
	if er.ServiceType == "Poll" && er.SrcCBName != "" {
		v.err(n, "9.3.13", "ExtRef with serviceType Poll names a source control block")
	}
	if er.PServT != "" && er.ServiceType != "" && er.PServT != er.ServiceType {
		v.err(n, "9.3.13", "ExtRef serviceType %s does not match pServT %s", er.ServiceType, er.PServT)
	}
	if er.IEDName != "" && er.IEDName != "@" && er.LDInst != "" {
		ied, err := v.d.IED(er.IEDName)
		if err != nil {
			return // source may be outside this file (IID, ICD)
		}
		ld, _ := ied.LDevice(er.LDInst)
		if ld == nil || ld.LN(er.Prefix, er.LNClass, er.LNInst) == nil {
			v.err(n, "9.3.13", "ExtRef source %s%s/%s%s%s does not exist", er.IEDName, er.LDInst, er.Prefix, er.LNClass, er.LNInst)
		}
	}
}

// checkDOIs applies 9.3.6: instance values only for what the LN type has.
func (v *validator) checkDOIs(ied *IED, ld *LDevice, ln *LN, n *Node) {
	lt, ok := v.d.Types.LNodeTypes[ln.LNType]
	if !ok {
		return
	}
	seen := map[string]bool{}
	numSG := 0
	if ld.LN0 != nil && ld.LN0.SettingControl != nil {
		numSG, _ = strconv.Atoi(ld.LN0.SettingControl.NumOfSGs)
	}
	for _, doi := range ln.DOIs {
		k := doi.Name + "|" + doi.Ix
		if seen[k] {
			v.err(n, "9.3.6", "DOI %s is defined twice", doi.Name)
		}
		seen[k] = true
		var typ string
		for _, do := range lt.DOs {
			if do.Name == doi.Name {
				typ = do.Type
			}
		}
		if typ == "" {
			v.err(n, "9.3.6", "DOI %s is not a data object of lnType %s", doi.Name, lt.ID)
			continue
		}
		v.checkInst(doi.Name, typ, "", doi.SDIs, doi.DAIs, numSG, n)
	}
}

// checkInst walks SDI/DAI against a DOType (or DAType when da is set).
func (v *validator) checkInst(path, doType, daType string, sdis []SDI, dais []DAI, numSG int, n *Node) {
	var items []TypeItem
	if daType != "" {
		t, ok := v.d.Types.DATypes[daType]
		if !ok {
			return
		}
		items = t.Members()
	} else {
		t, ok := v.d.Types.DOTypes[doType]
		if !ok {
			return
		}
		items = t.Members()
	}
	find := func(name string) *TypeItem {
		for i := range items {
			if items[i].Name == name {
				return &items[i]
			}
		}
		return nil
	}
	seen := map[string]bool{}
	for _, s := range sdis {
		k := s.Name + "|" + s.Ix
		if seen[k] {
			v.err(n, "9.3.6", "%s.%s is given twice", path, s.Name)
		}
		seen[k] = true
		it := find(s.Name)
		switch {
		case it == nil:
			v.err(n, "9.3.6", "%s.%s is not in the type", path, s.Name)
		case it.Kind() == "SDO":
			v.checkInst(path+"."+s.Name, it.Type, "", s.SDIs, s.DAIs, numSG, n)
		case it.BType == "Struct":
			v.checkInst(path+"."+s.Name, "", it.Type, s.SDIs, s.DAIs, numSG, n)
		default:
			v.err(n, "9.3.6", "%s.%s is not a structure", path, s.Name)
		}
	}
	for _, dai := range dais {
		k := dai.Name + "|" + dai.Ix
		if seen[k] {
			v.err(n, "9.3.6", "%s.%s is given twice", path, dai.Name)
		}
		seen[k] = true
		it := find(dai.Name)
		if it == nil || it.Kind() == "SDO" {
			v.err(n, "9.3.6", "%s.%s is not an attribute of the type", path, dai.Name)
			continue
		}
		if it.BType == "Struct" {
			v.err(n, "9.3.6", "%s.%s is a structure: give its members with SDI", path, dai.Name)
			continue
		}
		v.checkVals(path+"."+dai.Name, *it, dai.Vals, numSG, n)
	}
}

func (v *validator) checkVals(path string, it TypeItem, vals []Val, numSG int, n *Node) {
	var lits map[string]bool
	if it.BType == "Enum" {
		if et, ok := v.d.Types.EnumTypes[it.Type]; ok {
			lits = map[string]bool{}
			for _, e := range et.EnumVals {
				lits[strings.TrimSpace(e.Value)] = true
			}
		}
	}
	for _, val := range vals {
		if why := CheckValue(it.BType, val.Value, lits); why != "" {
			v.err(n, "9.5.4.1", "value %q of %s (%s) %s", strings.TrimSpace(val.Value), path, it.BType, why)
		}
		if val.SGroup != "" {
			g, _ := strconv.Atoi(val.SGroup)
			if it.FC != "" && it.FC != "SG" && it.FC != "SE" {
				v.err(n, "9.5.4.4", "sGroup on %s whose fc is %s", path, it.FC)
			}
			if numSG > 0 && (g < 1 || g > numSG) {
				v.err(n, "9.5.4.4", "sGroup %d of %s is outside 1..numOfSGs %d", g, path, numSG)
			}
		}
	}
}

// checkDataSet applies 9.3.7 to each FCDA.
func (v *validator) checkDataSet(ied *IED, ap *AccessPoint, ld *LDevice, ds *DataSet, n *Node) {
	for _, f := range ds.FCDAs {
		if f.LDInst == "" && f.LNClass == "" && f.DOName == "" {
			v.warn(n, "9.3.7", "empty FCDA (only meaningful as a GSSE DataLabel)")
			continue
		}
		if f.LDInst == "" || f.LNClass == "" || f.DOName == "" {
			v.err(n, "9.3.7", "FCDA %s needs ldInst, lnClass and doName", f.Ref())
			continue
		}
		if f.LNClass != "LLN0" && f.LNInst == "" {
			v.err(n, "9.3.7", "FCDA %s needs lnInst", f.Ref())
		}
		tld, tap := ied.LDevice(f.LDInst)
		if tld == nil {
			v.err(n, "9.3.7", "FCDA logical device %s does not exist", f.LDInst)
			continue
		}
		if tap != ap && (tap == nil || ap == nil || tap.Server != ap.Server) {
			v.err(n, "9.3.7", "FCDA %s/%s is on another server of the IED", f.LDInst, f.Ref())
		}
		tln := tld.LN(f.Prefix, f.LNClass, f.LNInst)
		if tln == nil {
			v.err(n, "9.3.7", "FCDA LN %s/%s does not exist", f.LDInst, f.LNName())
			continue
		}
		if err := v.resolveFCDA(tln, f); err != "" {
			v.err(n, "9.3.7", "FCDA %s/%s [%s]: %s", f.LDInst, f.Ref(), f.FC, err)
		}
		if f.Ix != "" {
			if !strings.Contains(f.DOName+f.DAName, "("+f.Ix+")") {
				v.err(n, "9.3.7", "FCDA ix %s does not match the array element in the name", f.Ix)
			}
		}
	}
}

// resolveFCDA checks that the member exists with the functional
// constraint; it returns "" when it does.
func (v *validator) resolveFCDA(ln *LN, f FCDA) string {
	lt, ok := v.d.Types.LNodeTypes[ln.LNType]
	if !ok {
		return "" // reported elsewhere
	}
	parts := strings.Split(stripArrays(f.DOName), ".")
	typ := ""
	for _, do := range lt.DOs {
		if do.Name == parts[0] {
			typ = do.Type
		}
	}
	if typ == "" {
		return "data object " + parts[0] + " is not in the LN type"
	}
	for _, p := range parts[1:] {
		t, ok := v.d.Types.DOTypes[typ]
		if !ok {
			return ""
		}
		next := ""
		for _, m := range t.Members() {
			if m.Kind() == "SDO" && m.Name == p {
				next = m.Type
			}
		}
		if next == "" {
			return "sub data object " + p + " is not in the type"
		}
		typ = next
	}
	t, ok := v.d.Types.DOTypes[typ]
	if !ok {
		return ""
	}
	if f.DAName == "" {
		// The FC must exist in the DOType (at any depth of its SDOs).
		if !v.doHasFC(t, f.FC, 0) {
			return "no attribute of the data object has this functional constraint"
		}
		return ""
	}
	das := strings.Split(stripArrays(f.DAName), ".")
	var it *TypeItem
	for _, m := range t.Members() {
		if m.Kind() == "DA" && m.Name == das[0] {
			mm := m
			it = &mm
		}
	}
	if it == nil {
		return "attribute " + das[0] + " is not in the data object type"
	}
	if it.FC != f.FC {
		return "the attribute's fc is " + it.FC
	}
	for _, p := range das[1:] {
		dt, ok := v.d.Types.DATypes[it.Type]
		if !ok || it.BType != "Struct" {
			return "attribute " + it.Name + " has no member " + p
		}
		var next *TypeItem
		for _, m := range dt.Members() {
			if m.Name == p {
				mm := m
				next = &mm
			}
		}
		if next == nil {
			return "attribute member " + p + " does not exist"
		}
		it = next
	}
	return ""
}

func (v *validator) doHasFC(t *DOType, fc string, depth int) bool {
	if depth > maxDepth {
		return false
	}
	for _, m := range t.Members() {
		if m.Kind() == "DA" && m.FC == fc {
			return true
		}
		if m.Kind() == "SDO" {
			if st, ok := v.d.Types.DOTypes[m.Type]; ok && v.doHasFC(st, fc, depth+1) {
				return true
			}
		}
	}
	return false
}

func stripArrays(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkCommunication applies 9.4.
func (v *validator) checkCommunication() {
	root := v.d.Tree.Root
	cn := root.Element("Communication")
	c := v.d.SCL.Communication
	if c == nil || cn == nil {
		return
	}
	sns := map[string]bool{}
	for i := range c.SubNetworks {
		sn := &c.SubNetworks[i]
		snn := childNamed(cn, "SubNetwork", "name", sn.Name)
		if sns[sn.Name] {
			v.err(snn, "9.4.1", "subnetwork name %q is used twice", sn.Name)
		}
		sns[sn.Name] = true
		caps := map[string]bool{}
		for j := range sn.ConnectedAPs {
			ca := &sn.ConnectedAPs[j]
			can := childNamed(snn, "ConnectedAP", "iedName", ca.IEDName)
			k := ca.IEDName + "/" + ca.APName
			if caps[k] {
				v.err(can, "9.4.2", "access point %s is connected twice to the subnetwork", k)
			}
			caps[k] = true
			ied, err := v.d.IED(ca.IEDName)
			if err != nil {
				v.err(can, "9.4.2", "ConnectedAP references IED %q which is not in the file", ca.IEDName)
				continue
			}
			if ied.AccessPoint(ca.APName) == nil {
				v.err(can, "9.4.2", "ConnectedAP references access point %s which IED %s does not have", ca.APName, ca.IEDName)
			}
			if ca.RedProt != "" && ca.RedProt != "none" {
				rp := ied.Services.Get("RedProt")
				if rp != nil && !rp.Bool(ca.RedProt, false) {
					v.err(can, "9.4.2", "redProt %s is not among the IED's RedProt capabilities", ca.RedProt)
				}
			}
			if ca.Address != nil {
				v.checkPs(ca.Address.Ps, can)
			}
			for _, list := range []struct {
				gses []GSE
				sv   bool
			}{{ca.GSEs, false}, {ca.SMVs, true}} {
				seen := map[string]bool{}
				for _, g := range list.gses {
					kk := g.LDInst + "/" + g.CBName
					if seen[kk] {
						v.err(can, "9.4.4", "control block address %s is given twice", kk)
					}
					seen[kk] = true
					ld, _ := ied.LDevice(g.LDInst)
					ok := false
					if ld != nil && ld.LN0 != nil {
						if list.sv {
							for _, s := range ld.LN0.SampledValueControls {
								ok = ok || s.Name == g.CBName
							}
						} else {
							for _, s := range ld.LN0.GSEControls {
								ok = ok || s.Name == g.CBName
							}
						}
					}
					if !ok {
						v.err(can, "8.1", "address for control block %s/%s which does not exist in IED %s", g.LDInst, g.CBName, ied.Name)
					}
					if g.Address != nil {
						v.checkPs(g.Address.Ps, can)
					}
				}
			}
			red, conn := 0, 0
			for _, pc := range ca.PhysConns {
				types := map[string]bool{}
				for _, p := range pc.Ps {
					if types[p.Type] {
						v.err(can, "9.4.6", "PhysConn P type %s is given twice", p.Type)
					}
					types[p.Type] = true
				}
				switch pc.Type {
				case "RedConn":
					red++
				case "Connection":
					conn++
				}
			}
			if red > 1 || (red == 1 && conn > 1) {
				v.err(can, "9.4.6", "only one RedConn, with only one Connection, is allowed per access point")
			}
		}
	}
}

func (v *validator) checkPs(ps []P, n *Node) {
	seen := map[string]bool{}
	for _, p := range ps {
		if seen[p.Type] {
			v.err(n, "9.4.3", "address parameter %s is given twice", p.Type)
		}
		seen[p.Type] = true
		if predefinedP[p.Type] {
			if why := CheckP(p.Type, p.Value); why != "" {
				v.err(n, "9.4.3", "address %s %q %s", p.Type, strings.TrimSpace(p.Value), why)
			}
		} else if strings.TrimSpace(p.Value) == "" {
			v.err(n, "9.4.3", "address %s is empty", p.Type)
		}
	}
}

// checkTemplates applies 9.5 (keys and references of DataTypeTemplates).
func (v *validator) checkTemplates() {
	dt := v.d.SCL.DataTypeTemplates
	dtn := v.d.Tree.Root.Element("DataTypeTemplates")
	if dt == nil || dtn == nil {
		return
	}
	ids := map[string]string{}
	for _, n := range dtn.Children {
		if !n.IsSCL() {
			continue
		}
		id, ok := n.Attr("id")
		if !ok {
			continue
		}
		if prev, dup := ids[id]; dup {
			v.errS(n, "9.5.1", "id %q is used by %s and %s", id, prev, n.Local)
		}
		ids[id] = n.Local
	}
	for _, lt := range dt.LNodeTypes {
		n := childNamed(dtn, "LNodeType", "id", lt.ID)
		dos := map[string]bool{}
		for _, do := range lt.DOs {
			if dos[do.Name] {
				v.errS(n, "9.5.2", "DO %s is defined twice", do.Name)
			}
			dos[do.Name] = true
			if _, ok := v.d.Types.DOTypes[do.Type]; !ok {
				v.errS(n, "9.5.2", "DO %s references DOType %q which is not defined", do.Name, do.Type)
			}
		}
		if lt.IEDType != "" {
			v.warn(n, "9.5.2", "iedType on LNodeType is deprecated")
		}
	}
	for _, t := range dt.DOTypes {
		n := childNamed(dtn, "DOType", "id", t.ID)
		names := map[string]bool{}
		ms := t.Members()
		if len(ms) == 0 {
			v.warn(n, "9.5.3", "DOType %s is empty (allowed in SSD and SED files only)", t.ID)
		}
		for _, m := range ms {
			if names[m.Name] {
				v.errS(n, "9.5.3", "%s is defined twice in DOType %s", m.Name, t.ID)
			}
			names[m.Name] = true
			switch m.Kind() {
			case "SDO":
				if _, ok := v.d.Types.DOTypes[m.Type]; !ok {
					v.errS(n, "9.5.3", "SDO %s references DOType %q which is not defined", m.Name, m.Type)
				}
				v.checkCount(m, names, ms, n)
			case "DA":
				v.checkDAItem(t.ID, m, ms, n)
			}
		}
		if v.recursive(t.ID, map[string]bool{}) {
			v.errS(n, "9.5.3", "DOType %s references itself through SDO", t.ID)
		}
	}
	for _, t := range dt.DATypes {
		n := childNamed(dtn, "DAType", "id", t.ID)
		names := map[string]bool{}
		ms := t.Members()
		for _, m := range ms {
			if names[m.Name] {
				v.errS(n, "9.5.5", "BDA %s is defined twice in DAType %s", m.Name, t.ID)
			}
			names[m.Name] = true
			v.checkDAItem(t.ID, m, ms, n)
		}
		if v.daRecursive(t.ID, map[string]bool{}) {
			v.errS(n, "9.5.5", "DAType %s references itself", t.ID)
		}
	}
	for _, t := range dt.EnumTypes {
		n := childNamed(dtn, "EnumType", "id", t.ID)
		ords := map[string]bool{}
		vals := map[string]bool{}
		for _, e := range t.EnumVals {
			if ords[e.Ord] {
				v.err(n, "9.5.6", "ord %s is used twice in EnumType %s", e.Ord, t.ID)
			}
			ords[e.Ord] = true
			val := e.Value
			if vals[val] {
				v.err(n, "9.5.6", "value %q is used twice in EnumType %s", val, t.ID)
			}
			vals[val] = true
			if utf8.RuneCountInString(val) > 127 {
				v.err(n, "9.5.6", "enumeration value %q is longer than 127 characters", val)
			}
			for _, r := range val {
				if r > 0xFF {
					v.err(n, "9.5.6", "enumeration value %q has characters outside Basic Latin and Latin-1 Supplement", val)
					break
				}
			}
		}
	}
}

func (v *validator) checkCount(m TypeItem, names map[string]bool, ms []TypeItem, n *Node) {
	if m.Count == "" {
		return
	}
	if _, err := strconv.ParseUint(m.Count, 10, 32); err == nil {
		return
	}
	for _, o := range ms {
		if o.Name == m.Count {
			return
		}
	}
	v.err(n, "9.5.4.1", "count of %s references attribute %q which is not in the same type", m.Name, m.Count)
}

func (v *validator) checkDAItem(typeID string, m TypeItem, ms []TypeItem, n *Node) {
	switch m.BType {
	case "Struct":
		if _, ok := v.d.Types.DATypes[m.Type]; !ok {
			v.errS(n, "9.5.4.1", "%s.%s is Struct but type %q is not a DAType", typeID, m.Name, m.Type)
		}
	case "Enum":
		if _, ok := v.d.Types.EnumTypes[m.Type]; !ok {
			v.errS(n, "9.5.4.1", "%s.%s is Enum but type %q is not an EnumType", typeID, m.Name, m.Type)
		}
	default:
		if m.Type != "" {
			v.warn(n, "9.5.4.1", "%s.%s has a type attribute but bType %s", typeID, m.Name, m.BType)
		}
		if m.BType == "INT128" || m.BType == "INT24U" {
			v.warn(n, "9.5.4.2", "%s.%s uses deprecated bType %s", typeID, m.Name, m.BType)
		}
	}
	v.checkCount(m, nil, ms, n)
	v.checkVals(typeID+"."+m.Name, m, m.Vals, 0, n)
	if m.SAddr != "" && utf8.RuneCountInString(m.SAddr) > 255 {
		v.err(n, "I.5.3.5", "sAddr of %s.%s is longer than 255 characters", typeID, m.Name)
	}
}

func (v *validator) recursive(id string, path map[string]bool) bool {
	if path[id] {
		return true
	}
	t, ok := v.d.Types.DOTypes[id]
	if !ok {
		return false
	}
	path[id] = true
	defer delete(path, id)
	for _, m := range t.Members() {
		if m.Kind() == "SDO" && v.recursive(m.Type, path) {
			return true
		}
	}
	return false
}

func (v *validator) daRecursive(id string, path map[string]bool) bool {
	if path[id] {
		return true
	}
	t, ok := v.d.Types.DATypes[id]
	if !ok {
		return false
	}
	path[id] = true
	defer delete(path, id)
	for _, m := range t.Members() {
		if m.BType == "Struct" && v.daRecursive(m.Type, path) {
			return true
		}
	}
	return false
}

// checkFileType applies Clause 7 and Annex F.
func (v *validator) checkFileType(ft string) {
	s := v.d.SCL
	root := v.d.Tree.Root
	need := func(ok bool, clause, what string) {
		if !ok {
			v.err(root, clause, "a %s file %s", ft, what)
		}
	}
	switch ft {
	case "ICD":
		need(len(s.IEDs) == 1, "7", "contains exactly one IED")
		if len(s.IEDs) == 1 {
			need(s.IEDs[0].Name == "TEMPLATE", "7", "names its IED TEMPLATE")
		}
		need(s.DataTypeTemplates != nil, "7", "contains the DataTypeTemplates")
		for _, p := range append(append(append([]PSR{}, s.Substations...), s.Lines...), s.Processes...) {
			need(p.Name == "TEMPLATE", "7", "names its process template TEMPLATE")
		}
	case "IID":
		need(len(s.IEDs) >= 1, "7", "contains the IED")
		need(s.DataTypeTemplates != nil, "7", "contains the DataTypeTemplates")
		for _, ied := range s.IEDs {
			if ied.Name == "TEMPLATE" {
				v.err(root, "7", "an IID file names its IED project-specifically, not TEMPLATE")
			}
		}
	case "SSD":
		need(len(s.Substations)+len(s.Processes)+len(s.Lines) > 0, "7", "contains a Substation, Process or Line section")
	case "SCD", "SED":
		need(len(s.IEDs) > 0, "Annex F", "contains the IEDs")
		need(s.Communication != nil, "Annex F", "contains a Communication section")
		need(s.DataTypeTemplates != nil, "Annex F", "contains the DataTypeTemplates")
		for _, ied := range s.IEDs {
			if ied.Name == "TEMPLATE" {
				v.err(v.iedNode[ied.Name], "7", "an %s file contains the IED template TEMPLATE", ft)
			}
		}
		if s.Communication != nil {
			for _, sn := range s.Communication.SubNetworks {
				if strings.TrimSpace(sn.Type) == "" {
					v.err(root, "9.4.2", "subnetwork %s needs a type in an %s file", sn.Name, ft)
				}
			}
		}
		if ft == "SED" {
			for _, ied := range s.IEDs {
				if ied.EngRight == "" || ied.EngRight == "full" {
					v.warn(v.iedNode[ied.Name], "5.5", "IED %s in a SED file carries no transferred engineering right (fix or dataflow)", ied.Name)
				}
			}
		}
	case "CID":
		need(len(s.IEDs) > 0, "Annex F", "contains the IED")
		need(s.Communication != nil, "Annex F", "contains a Communication section")
		need(s.DataTypeTemplates != nil, "Annex F", "contains the DataTypeTemplates")
	}
	if ft != "SSD" {
		for _, n := range root.Elements("IED") {
			if n.A("name") == "None" {
				v.err(n, "8.2.3", "None is not allowed as IED name")
			}
		}
	}
}
