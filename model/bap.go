package model

import (
	"fmt"
	"sort"
	"strings"
)

// BAP is a Basic Application Profile (IEC TR 61850-7-6 Ed. 2.0 Clause 4.3):
// the variants of an application and, per actor, the data the application
// needs from a device.
type BAP struct {
	Name          string         `yaml:"name"`
	Title         string         `yaml:"title"`
	Source        string         `yaml:"source"`
	VariantGroups []VariantGroup `yaml:"variantGroups"`
	Actors        []Actor        `yaml:"actors"`
	// ASD names the IEC TR 61850-7-6 ASD example file (machine-readable file
	// 2024A2) that carries the profile's application template.
	ASD string `yaml:"asd"`
	// Template is the application template read from that file.
	Template *Template `yaml:"-"`
	// TemplateDepartures lists where the TR's tables ask for more than
	// the ASD template's data model gives (the example templates are
	// minimal; the tables stay authoritative for the requirements).
	TemplateDepartures []string `yaml:"-"`
}

// Template is the application template of an ASD file: the IEC 61850-6-100
// Application with its function roles, the LNodes of its functions with
// the signals they subscribe to, and the data type templates that define
// what each LN of the application exposes.
type Template struct {
	File, Application string
	Roles             []TemplateRole
	LNs               []TemplateLN
	Inputs            []TemplateInput
}

// TemplateRole is a function role of the application.
type TemplateRole struct {
	Name      string
	Functions []string
	// Signals maps a signal role to the LNode inputs it binds (LN.input).
	Signals map[string][]string
}

// TemplateLN is a logical node class the application uses, with the data
// objects (and their attributes) its LNodeType gives it.
type TemplateLN struct {
	Class     string
	Instances []string // prefix+class+inst of the LNodes using it
	DOs       []TemplateDO
}

// TemplateDO is a data object of a template LN.
type TemplateDO struct {
	Name, CDC string
	DAs       []string
}

// TemplateInput is a signal an LNode of the application subscribes to:
// service (GOOSE, SMV, Internal, Wired) and the source data (pLN.pDO.pDA).
type TemplateInput struct {
	LN, Input, Service string
	LNClass, DO, DA    string
}

// String names the value.
func (in TemplateInput) String() string {
	if in.LNClass == "" {
		return in.LN + " <- " + in.Input + " (" + in.Service + ")"
	}
	return in.LN + " <- " + in.LNClass + "." + in.DO + "." + in.DA + " (" + in.Service + ")"
}

// templateFromASD builds the template of one generated ASD file.
func templateFromASD(a *asdFile) (*Template, error) {
	if len(a.Applications) != 1 {
		return nil, fmt.Errorf("%s: %d applications", a.File, len(a.Applications))
	}
	t := &Template{File: a.File, Application: a.Applications[0].Name}
	for _, r := range a.Applications[0].Roles {
		tr := TemplateRole{Name: r.Name, Functions: r.Functions, Signals: map[string][]string{}}
		for _, s := range r.Signals {
			tr.Signals[s.Name] = append(tr.Signals[s.Name], s.Inputs...)
		}
		t.Roles = append(t.Roles, tr)
	}
	doTypes := map[string]asdDOType{}
	for _, d := range a.DOTypes {
		doTypes[d.ID] = d
	}
	lnTypes := map[string]asdLNodeType{}
	for _, l := range a.LNodeTypes {
		lnTypes[l.ID] = l
	}
	byClass := map[string]*TemplateLN{}
	for _, f := range a.Functions {
		for _, ln := range f.LNodes {
			inst := ln.Prefix + ln.LNClass + ln.LNInst
			for _, in := range ln.Inputs {
				t.Inputs = append(t.Inputs, TemplateInput{LN: inst, Input: in.Input, Service: in.Service, LNClass: in.PLN, DO: in.PDO, DA: in.PDA})
			}
			lt, ok := lnTypes[ln.LNType]
			if !ok {
				return nil, fmt.Errorf("%s: LNode %s: no LNodeType %s", a.File, inst, ln.LNType)
			}
			if lt.LNClass != ln.LNClass {
				return nil, fmt.Errorf("%s: LNode %s uses LNodeType %s of class %s", a.File, inst, lt.ID, lt.LNClass)
			}
			tl, ok := byClass[ln.LNClass]
			if !ok {
				tl = &TemplateLN{Class: ln.LNClass}
				for _, d := range lt.DOs {
					dt, ok := doTypes[d.Type]
					if !ok {
						return nil, fmt.Errorf("%s: %s.%s: no DOType %s", a.File, lt.ID, d.Name, d.Type)
					}
					td := TemplateDO{Name: d.Name, CDC: dt.CDC}
					for _, da := range dt.DAs {
						td.DAs = append(td.DAs, da.Name)
					}
					tl.DOs = append(tl.DOs, td)
				}
				byClass[ln.LNClass] = tl
				t.LNs = append(t.LNs, TemplateLN{})
			}
			tl.Instances = append(tl.Instances, inst)
		}
	}
	// keep first-use order
	t.LNs = t.LNs[:0]
	seen := map[string]bool{}
	for _, f := range a.Functions {
		for _, ln := range f.LNodes {
			if !seen[ln.LNClass] {
				seen[ln.LNClass] = true
				t.LNs = append(t.LNs, *byClass[ln.LNClass])
			}
		}
	}
	return t, nil
}

// LN returns the template LN of a class.
func (t *Template) LN(class string) (*TemplateLN, bool) {
	for i := range t.LNs {
		if t.LNs[i].Class == class {
			return &t.LNs[i], true
		}
	}
	return nil, false
}

// DO returns a data object of a template LN; a multi-instance name
// (BlkRef) matches its numbered instances (BlkRef1).
func (l *TemplateLN) DO(name string, multi bool) (*TemplateDO, bool) {
	for i := range l.DOs {
		n := l.DOs[i].Name
		if n == name || multi && strings.TrimRight(n, "0123456789") == name && n != name {
			return &l.DOs[i], true
		}
	}
	return nil, false
}

// attachTemplates reads the ASD template of every profile that names one.
func (m *Model) attachTemplates() error {
	for _, b := range m.BAPs {
		if b.ASD == "" {
			continue
		}
		for i := range nsdTablesOf().ASDs {
			if nsdTablesOf().ASDs[i].File == b.ASD {
				t, err := templateFromASD(&nsdTablesOf().ASDs[i])
				if err != nil {
					return fmt.Errorf("iec61850 model: bap %s: %w", b.Name, err)
				}
				b.Template = t
			}
		}
		// Without IEC's ASD files the profile has no template (the ASD
		// files are optional to LoadNSD); with them, the named one must
		// be there.
		if b.Template == nil && len(nsdTablesOf().ASDs) > 0 {
			return fmt.Errorf("iec61850 model: bap %s: no ASD file %s", b.Name, b.ASD)
		}
	}
	return nil
}

// Templates lists the ASD application templates of the embedded model by
// file name, including those no profile names.
func Templates() (map[string]*Template, error) {
	out := map[string]*Template{}
	for i := range nsdTablesOf().ASDs {
		t, err := templateFromASD(&nsdTablesOf().ASDs[i])
		if err != nil {
			return nil, err
		}
		out[t.File] = t
	}
	return out, nil
}

// VariantGroup groups mutually exclusive variants (one is chosen).
type VariantGroup struct {
	Name     string    `yaml:"name"`
	Kind     string    `yaml:"kind"` // core or noncore
	Variants []Variant `yaml:"variants"`
}

// Variant is a functional variant.
type Variant struct {
	Name    string `yaml:"name"`
	Meaning string `yaml:"meaning"`
}

// Actor is a role of the application with the data it needs.
type Actor struct {
	Name    string        `yaml:"name"`
	Meaning string        `yaml:"meaning"`
	Table   string        `yaml:"table"`
	Items   []Requirement `yaml:"items"`
}

// Requirement is one data object of an actor's data model table.
type Requirement struct {
	LN string `yaml:"ln"`
	// Inst restricts the requirement to one LN instance number (PDIS1).
	Inst  string   `yaml:"inst"`
	DO    string   `yaml:"do"`
	CDC   string   `yaml:"cdc"`
	Attrs []string `yaml:"attrs"`
	// Multi marks a multi-instance data object used as DO1 … DOn.
	Multi  bool   `yaml:"multi"`
	Values string `yaml:"values"`
	// R lists the variants in which the device must expose the data
	// (server capability); Rc those in which a client must use it.
	R  []string `yaml:"r"`
	Rc []string `yaml:"rc"`
}

// String names the value.
func (r Requirement) String() string {
	s := r.LN + r.Inst + "." + r.DO
	if r.Multi {
		s += "n"
	}
	return s
}

// Variants lists all variant names of the profile.
func (b *BAP) Variants() []string {
	var out []string
	for _, g := range b.VariantGroups {
		for _, v := range g.Variants {
			out = append(out, v.Name)
		}
	}
	return out
}

// Actor returns the named actor.
func (b *BAP) Actor(name string) (*Actor, bool) {
	for i := range b.Actors {
		if b.Actors[i].Name == name {
			return &b.Actors[i], true
		}
	}
	return nil, false
}

// check verifies the profile against the 7-3/7-4 model: every LN class,
// data object, CDC and attribute must exist and every variant be declared.
func (b *BAP) check(m *Model) []error {
	var errs []error
	known := map[string]bool{}
	for _, v := range b.Variants() {
		known[v] = true
	}
	for _, a := range b.Actors {
		for _, it := range a.Items {
			where := fmt.Sprintf("bap %s/%s %s", b.Name, a.Name, it)
			l, ok := m.LNs[it.LN]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: unknown LN class", where))
				continue
			}
			d, ok := l.DataObject(it.DO)
			if !ok {
				errs = append(errs, fmt.Errorf("%s: data object not in %s", where, it.LN))
				continue
			}
			if d.CDC != it.CDC {
				errs = append(errs, fmt.Errorf("%s: CDC %s, 7-4 says %s", where, it.CDC, d.CDC))
			}
			if it.Multi && !d.Multi() {
				errs = append(errs, fmt.Errorf("%s: not a multi-instance data object", where))
			}
			for _, at := range it.Attrs {
				if _, ok := m.FindAttr(d.CDC, at); !ok {
					errs = append(errs, fmt.Errorf("%s: attribute %s not in %s", where, at, d.CDC))
				}
			}
			for _, v := range append(append([]string(nil), it.R...), it.Rc...) {
				if !known[v] {
					errs = append(errs, fmt.Errorf("%s: unknown variant %s", where, v))
				}
			}
			for _, e := range b.checkTemplate(it, where) {
				b.TemplateDepartures = append(b.TemplateDepartures, e.Error())
			}
		}
	}
	for _, tl := range b.templateLNs() {
		for _, d := range tl.DOs {
			l, ok := m.LNs[tl.Class]
			if !ok {
				errs = append(errs, fmt.Errorf("bap %s template: unknown LN class %s", b.Name, tl.Class))
				break
			}
			md, ok := l.DataObject(d.Name)
			if !ok {
				errs = append(errs, fmt.Errorf("bap %s template: %s.%s is not a data object of the class", b.Name, tl.Class, d.Name))
				continue
			}
			if md.CDC != d.CDC {
				errs = append(errs, fmt.Errorf("bap %s template: %s.%s is %s, 7-4 says %s", b.Name, tl.Class, d.Name, d.CDC, md.CDC))
			}
			for _, da := range d.DAs {
				if _, ok := m.FindAttr(md.CDC, da); !ok {
					errs = append(errs, fmt.Errorf("bap %s template: %s.%s.%s is not an attribute of %s", b.Name, tl.Class, d.Name, da, md.CDC))
				}
			}
		}
	}
	return errs
}

func (b *BAP) templateLNs() []TemplateLN {
	if b.Template == nil {
		return nil
	}
	return b.Template.LNs
}

// checkTemplate compares a requirement read from the TR's tables with the
// ASD template: where the template has the LN class, it must have the
// data object with the same CDC and every required attribute.
func (b *BAP) checkTemplate(it Requirement, where string) []error {
	if b.Template == nil {
		return nil
	}
	tl, ok := b.Template.LN(it.LN)
	if !ok {
		return nil
	}
	d, ok := tl.DO(it.DO, it.Multi)
	if !ok {
		return []error{fmt.Errorf("%s: not in the ASD template's %s", where, it.LN)}
	}
	var errs []error
	if d.CDC != it.CDC {
		errs = append(errs, fmt.Errorf("%s: CDC %s, the ASD template says %s", where, it.CDC, d.CDC))
	}
	for _, at := range it.Attrs {
		found := false
		for _, da := range d.DAs {
			found = found || da == at
		}
		if !found {
			errs = append(errs, fmt.Errorf("%s: attribute %s not in the ASD template", where, at))
		}
	}
	return errs
}

// LNInstance is a logical node of a device model. DOs maps the data
// objects present (with instance numbers, e.g. BlkRef1) to their data
// attributes; a nil attribute list means the attributes are not known.
type LNInstance struct {
	LD   string
	Name string // e.g. PTOC1, Q0XCBR1, LLN0
	DOs  map[string][]string
}

// Device is the part of a device model a BAP check needs.
type Device struct {
	Name string
	LNs  []LNInstance
}

// Issue is one finding of a BAP check.
type Issue struct {
	Kind        string // missing-ln, missing-do, missing-da, not-in-model, missing-mandatory
	LN, DO, DA  string
	Requirement string
	Detail      string
}

// String names the value.
func (i Issue) String() string {
	s := i.Kind + ": " + i.LN
	if i.DO != "" {
		s += "." + i.DO
	}
	if i.DA != "" {
		s += "." + i.DA
	}
	if i.Detail != "" {
		s += " (" + i.Detail + ")"
	}
	return s
}

// CheckReport is the result of checking a device against a BAP actor.
type CheckReport struct {
	BAP, Actor string
	Variants   []string
	// Missing are server requirements (R) the device does not meet.
	Missing []Issue
	// Model are departures of the device from the 7-4 model (data
	// objects not in the class, mandatory data objects missing).
	Model []Issue
	// ClientRequired are the Rc items of the chosen variants: data a
	// client of this device must read; not a device failure.
	ClientRequired []Requirement
	// Subscribed lists the signals the ASD template's LNodes subscribe to
	// (CheckTemplate): what other IEDs must publish.
	Subscribed []string
}

// OK reports whether the device meets every server requirement.
func (r *CheckReport) OK() bool { return len(r.Missing) == 0 }

// CheckDevice checks a device model against actor of profile bap with
// the chosen variants (one per group; unknown variants are an error).
func (m *Model) CheckDevice(bap, actor string, variants []string, dev Device) (*CheckReport, error) {
	b, ok := m.BAPs[bap]
	if !ok {
		return nil, fmt.Errorf("iec61850 model: unknown BAP %s", bap)
	}
	a, ok := b.Actor(actor)
	if !ok {
		return nil, fmt.Errorf("iec61850 model: BAP %s has no actor %s", bap, actor)
	}
	chosen := map[string]bool{}
	for _, v := range variants {
		chosen[v] = true
	}
	for _, g := range b.VariantGroups {
		n := 0
		for _, v := range g.Variants {
			if chosen[v.Name] {
				n++
				delete(chosen, v.Name)
			}
		}
		if n > 1 {
			return nil, fmt.Errorf("iec61850 model: more than one variant of group %s chosen", g.Name)
		}
	}
	if len(chosen) > 0 {
		var extra []string
		for v := range chosen {
			extra = append(extra, v)
		}
		sort.Strings(extra)
		return nil, fmt.Errorf("iec61850 model: BAP %s has no variant %s", bap, strings.Join(extra, ", "))
	}
	rep := &CheckReport{BAP: bap, Actor: actor, Variants: append([]string(nil), variants...)}
	in := func(list []string) bool {
		for _, v := range list {
			for _, c := range variants {
				if v == c {
					return true
				}
			}
		}
		return false
	}
	for _, it := range a.Items {
		if in(it.Rc) {
			rep.ClientRequired = append(rep.ClientRequired, it)
		}
		if !in(it.R) {
			continue
		}
		lns := m.instancesOf(dev, it.LN, it.Inst)
		if len(lns) == 0 {
			rep.Missing = append(rep.Missing, Issue{Kind: "missing-ln", LN: it.LN + it.Inst, Requirement: it.String()})
			continue
		}
		found := false
		var missingDA []Issue
		for _, ln := range lns {
			for _, doName := range sortedKeys(ln.DOs) {
				das := ln.DOs[doName]
				if !(doName == it.DO || it.Multi && strings.TrimRight(doName, "0123456789") == it.DO && doName != it.DO) {
					continue
				}
				found = true
				if das == nil {
					continue
				}
				have := map[string]bool{}
				for _, d := range das {
					have[d] = true
				}
				for _, at := range it.Attrs {
					if !have[at] {
						missingDA = append(missingDA, Issue{Kind: "missing-da", LN: ln.Name, DO: doName, DA: at, Requirement: it.String()})
					}
				}
			}
		}
		if !found {
			rep.Missing = append(rep.Missing, Issue{Kind: "missing-do", LN: lns[0].Name, DO: it.DO, Requirement: it.String()})
		}
		rep.Missing = append(rep.Missing, missingDA...)
	}
	// the device against 7-4 itself
	for _, ln := range dev.LNs {
		_, class, _, err := SplitLN(ln.Name)
		if err != nil {
			rep.Model = append(rep.Model, Issue{Kind: "not-in-model", LN: ln.Name, Detail: err.Error()})
			continue
		}
		l, ok := m.LNs[class]
		if !ok || l.Abstract {
			rep.Model = append(rep.Model, Issue{Kind: "not-in-model", LN: ln.Name, Detail: "unknown LN class " + class})
			continue
		}
		var names []string
		for n := range ln.DOs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if _, ok := l.DataObject(n); !ok {
				rep.Model = append(rep.Model, Issue{Kind: "not-in-model", LN: ln.Name, DO: n, Detail: "not a data object of " + class})
			}
		}
		for _, d := range l.DataObjects {
			if !d.Mandatory(false) {
				continue
			}
			present := false
			for n := range ln.DOs {
				if n == d.Name || d.Multi() && strings.TrimRight(n, "0123456789") == d.Name {
					present = true
				}
			}
			if !present {
				rep.Model = append(rep.Model, Issue{Kind: "missing-mandatory", LN: ln.Name, DO: d.Name})
			}
		}
	}
	return rep, nil
}

func (m *Model) instancesOf(dev Device, class, inst string) []LNInstance {
	var out []LNInstance
	for _, ln := range dev.LNs {
		_, c, i, err := SplitLN(ln.Name)
		if err != nil || c != class || inst != "" && i != inst {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckTemplate checks a device model against the ASD application
// template of a profile: every LN class of the template must be present
// with the data objects and attributes its LNodeType defines. The inputs
// the template's LNodes subscribe to are returned in Subscribed.
func (m *Model) CheckTemplate(bap string, dev Device) (*CheckReport, error) {
	b, ok := m.BAPs[bap]
	if !ok {
		return nil, fmt.Errorf("iec61850 model: unknown BAP %s", bap)
	}
	if b.Template == nil {
		return nil, fmt.Errorf("iec61850 model: BAP %s has no ASD template", bap)
	}
	rep := &CheckReport{BAP: bap, Actor: "template"}
	for _, tl := range b.Template.LNs {
		lns := m.instancesOf(dev, tl.Class, "")
		if len(lns) == 0 {
			rep.Missing = append(rep.Missing, Issue{Kind: "missing-ln", LN: tl.Class, Requirement: "template " + tl.Class})
			continue
		}
		for _, d := range tl.DOs {
			base := strings.TrimRight(d.Name, "0123456789")
			req := "template " + tl.Class + "." + d.Name
			var das []string
			found := false
			for _, ln := range lns {
				for n, a := range ln.DOs {
					if n == d.Name || base != d.Name && strings.TrimRight(n, "0123456789") == base {
						found = true
						if a != nil {
							das = append(das, a...)
						}
					}
				}
			}
			if !found {
				rep.Missing = append(rep.Missing, Issue{Kind: "missing-do", LN: lns[0].Name, DO: d.Name, Requirement: req})
				continue
			}
			if das == nil {
				continue
			}
			have := map[string]bool{}
			for _, a := range das {
				have[a] = true
			}
			for _, a := range d.DAs {
				if !have[a] {
					rep.Missing = append(rep.Missing, Issue{Kind: "missing-da", LN: lns[0].Name, DO: d.Name, DA: a, Requirement: req})
				}
			}
		}
	}
	for _, in := range b.Template.Inputs {
		rep.Subscribed = append(rep.Subscribed, in.String())
	}
	return rep, nil
}
