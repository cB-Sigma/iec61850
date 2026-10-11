package model

import "fmt"

// Service is a step of a control model (IEC 61850-7-2 Ed. 2.1 Clause 20,
// mapped to MMS by IEC 61850-8-1 Ed. 2.1 Clause 20).
type Service string

// Control services.
const (
	SvcSelect             Service = "Select"             // read of SBO (normal security)
	SvcSelectWithValue    Service = "SelectWithValue"    // write of SBOw (enhanced security)
	SvcOperate            Service = "Operate"            // write of Oper
	SvcCommandTermination Service = "CommandTermination" // report of the operation's end (enhanced security)
	SvcCancel             Service = "Cancel"             // write of Cancel
)

// ControlInfo describes how a common data class is controlled.
type ControlInfo struct {
	CDC          string
	Controllable bool
	// CtlValType is the type of ctlVal (BOOLEAN for SPC, DpStatusKind is
	// not used: DPC takes BOOLEAN too; INT32 for INC …).
	CtlValType string
	// OperFields are the members of Oper and SBOw; CancelFields of Cancel.
	OperFields, CancelFields []Attr
	// Models lists the CtlModelKind literals the class accepts.
	Models []string
}

// Control returns the control description of a common data class. Every
// class has one; only the controllable classes (those with ctlModel and
// the ctlVal service parameter) have Controllable set.
func (m *Model) Control(cdc string) (*ControlInfo, bool) {
	c, ok := m.CDCs[cdc]
	if !ok {
		return nil, false
	}
	ci := &ControlInfo{CDC: cdc}
	var ctlVal *Attr
	for i := range c.Attrs {
		if c.Attrs[i].Name == "ctlVal" && c.Attrs[i].ServiceParameter {
			ctlVal = &c.Attrs[i]
		}
	}
	_, hasModel := c.Attr("ctlModel")
	e := m.Enums["CtlModelKind"]
	// The controllable classes are the service CDCs of the IEC 61850-8-1
	// SNSD (Oper, SBOw, Cancel under CO).
	if ctlVal == nil || !hasModel || !m.controllable[cdc] {
		ci.Models = []string{e.Items[0].Name}
		return ci, true
	}
	ci.Controllable = true
	ci.CtlValType = ctlVal.Type
	for _, it := range e.Items {
		ci.Models = append(ci.Models, it.Name)
	}
	// Oper/SBOw and Cancel members: the service constructed attributes of
	// the 8-1 SNSD, ctlVal typed by the class's service parameter.
	ci.OperFields = m.serviceFields("Oper", ctlVal.Type)
	ci.CancelFields = m.serviceFields("Cancel", ctlVal.Type)
	return ci, true
}

// serviceFields returns the members of an 8-1 service constructed
// attribute (Oper, SBOw, Cancel) with ctlVal of type ctlValType.
func (m *Model) serviceFields(name, ctlValType string) []Attr {
	tn := func(t string) string { return t }
	if m.text != nil {
		tn = func(t string) string {
			if n, ok := m.text.TypeNames[t]; ok {
				return n
			}
			return t
		}
	}
	var out []Attr
	for _, ca := range nsdTablesOf().ServiceCAs {
		if ca.Name != name {
			continue
		}
		for _, a := range ca.Attrs {
			f := convAttr(a, tn)
			f.ServiceParameter = false
			if f.Name == "ctlVal" {
				f.Type = ctlValType
			}
			out = append(out, f)
		}
	}
	return out
}

// Sequence returns the services a client issues for one operation under
// the control model (a CtlModelKind literal or its value as a string),
// in order; nil for status-only.
func (ci *ControlInfo) Sequence(model string) ([]Service, error) {
	switch model {
	case "status-only", "0":
		return nil, nil
	case "direct-with-normal-security", "1":
		return []Service{SvcOperate}, nil
	case "sbo-with-normal-security", "2":
		return []Service{SvcSelect, SvcOperate}, nil
	case "direct-with-enhanced-security", "3":
		return []Service{SvcOperate, SvcCommandTermination}, nil
	case "sbo-with-enhanced-security", "4":
		return []Service{SvcSelectWithValue, SvcOperate, SvcCommandTermination}, nil
	}
	return nil, fmt.Errorf("iec61850 model: unknown control model %q", model)
}

// RequiredAttrs lists the mandatory configuration attributes of a
// controllable class and those its presence conditions MOsbo and
// MOenhanced make mandatory under the control model (stSeld, sboTimeout,
// operTimeout).
func (m *Model) RequiredAttrs(cdc, model string) ([]string, error) {
	c, ok := m.CDCs[cdc]
	if !ok {
		return nil, fmt.Errorf("iec61850 model: unknown CDC %s", cdc)
	}
	ci, _ := m.Control(cdc)
	seq, err := ci.Sequence(model)
	if err != nil {
		return nil, err
	}
	sbo, enh := false, false
	for _, s := range seq {
		switch s {
		case SvcSelect, SvcSelectWithValue:
			sbo = true
		case SvcCommandTermination:
			enh = true
		}
	}
	var out []string
	for _, a := range c.Attrs {
		switch {
		case a.Presence == "M" && a.FC == "CF":
			out = append(out, a.Name)
		case a.Presence == "MOsbo" && sbo, a.Presence == "MOenhanced" && enh:
			out = append(out, a.Name)
		}
	}
	return out, nil
}
