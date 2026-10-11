package scl

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/cB-Sigma/iec61850/model"
)

// CheckModel compares the DataTypeTemplates with the IEC 61850-7-3 common
// data classes and the IEC 61850-7-4 logical node classes of package model.
// Departures are warnings: IEDs may use other name spaces (IEC 61850-7-4xx,
// vendor extensions under lnNs/dataNs, IEC 61850-7-1 Clause 14), so SCL
// that is valid by IEC 61850-6 is never refused for them. With m nil the
// default model is used; without one (IEC's NSD files not loaded) there
// is nothing to compare with and no issue is returned.
func CheckModel(d *Document, m *model.Model) Issues {
	if m == nil {
		dm, err := model.Default()
		if err != nil {
			return nil
		}
		m = dm
	}
	var out Issues
	dtn := d.Tree.Root.Element("DataTypeTemplates")
	dt := d.SCL.DataTypeTemplates
	if dt == nil || dtn == nil {
		return nil
	}
	warn := func(n *Node, clause, format string, args ...any) {
		i := Issue{Severity: Warning, Clause: clause, Msg: fmt.Sprintf(format, args...)}
		if n != nil {
			i.Path, i.Line = n.Path(), n.Line
		}
		out = append(out, i)
	}
	for _, lt := range dt.LNodeTypes {
		n := childNamed(dtn, "LNodeType", "id", lt.ID)
		cls, ok := m.LNClass(lt.LNClass)
		if !ok {
			warn(n, "9.5.2", "LN class %s of LNodeType %s is not an IEC 61850-7-4 class (other name space?)", lt.LNClass, lt.ID)
			continue
		}
		have := map[string]bool{}
		for _, do := range lt.DOs {
			have[do.Name] = true
			mdo, ok := cls.DataObject(do.Name)
			if !ok {
				warn(n, "9.5.2", "%s.%s is not a data object of the IEC 61850-7-4 class (extension?)%s", lt.LNClass, do.Name, didYouMean(cls, do.Name))
				continue
			}
			t, ok := d.Types.DOTypes[do.Type]
			if !ok {
				continue
			}
			if t.CDC != mdo.CDC && !strings.HasPrefix(t.CDC, mdo.CDC) {
				warn(n, "9.5.3", "%s.%s uses DOType %s of class %s; IEC 61850-7-4 gives %s", lt.LNClass, do.Name, t.ID, t.CDC, mdo.CDC)
			}
			checkDOType(d, m, t, lt.LNClass+"."+do.Name, n, warn, 0)
		}
		if mand, err := m.MandatoryDataObjects(lt.LNClass, false); err == nil {
			var missing []string
			for _, md := range mand {
				if !have[md.Name] && !(md.Multi() && hasNumbered(have, md.Name)) {
					missing = append(missing, md.Name)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				warn(n, "9.5.1", "LNodeType %s lacks the mandatory data objects %s of %s", lt.ID, strings.Join(missing, ", "), lt.LNClass)
			}
		}
	}
	return out
}

func hasNumbered(have map[string]bool, base string) bool {
	for k := range have {
		if strings.HasPrefix(k, base) && strings.Trim(k[len(base):], "0123456789") == "" {
			return true
		}
	}
	return false
}

// didYouMean hints at an I/l confusion, the usual typo in data object
// names (the model comes from the NSD, so it is the file's).
func didYouMean(cls *model.LNClass, name string) string {
	swap := strings.NewReplacer("I", "l", "l", "I")
	if alt := swap.Replace(name); alt != name {
		if _, ok := cls.DataObject(alt); ok {
			return " (did you mean " + alt + "?)"
		}
	}
	return ""
}

func checkDOType(d *Document, m *model.Model, t *DOType, path string, n *Node, warn func(*Node, string, string, ...any), depth int) {
	if depth > maxDepth {
		return
	}
	if _, ok := m.CDC(t.CDC); !ok {
		warn(n, "9.5.3", "%s: CDC %s is not an IEC 61850-7-3 class", path, t.CDC)
		return
	}
	for _, it := range t.Members() {
		a, ok := m.FindAttr(t.CDC, it.Name)
		if !ok {
			warn(n, "9.5.4", "%s.%s is not an attribute of CDC %s", path, it.Name, t.CDC)
			continue
		}
		if it.Kind() == "SDO" {
			if st, ok := d.Types.DOTypes[it.Type]; ok {
				checkDOType(d, m, st, path+"."+it.Name, n, warn, depth+1)
			}
			continue
		}
		if a.FC != "" && it.FC != "" && a.FC != it.FC && !(a.FC == "SG" && it.FC == "SE") && !(a.FC == "SE" && it.FC == "SG") {
			// Setting classes carry their FC per variant (SP, SG, SE).
			if !(isSettingFC(a.FC) && isSettingFC(it.FC)) {
				warn(n, "9.5.4", "%s.%s has fc %s; IEC 61850-7-3 gives %s", path, it.Name, it.FC, a.FC)
			}
		}
	}
}

func isSettingFC(fc string) bool { return fc == "SP" || fc == "SG" || fc == "SE" }

// Applications reads the BAP Application elements (IEC 61850-6-100
// extension, IEC TR 61850-7-6 6.1) of the document with package model.
func Applications(d *Document) ([]model.Application, error) {
	return model.ParseApplications(bytes.NewReader(d.Bytes()))
}

// Device builds the device model of an IED for a BAP check: every LN with
// its data objects and their top-level attribute names.
func (d *Document) Device(iedName string) (model.Device, error) {
	ied, err := d.IED(iedName)
	if err != nil {
		return model.Device{}, err
	}
	dev := model.Device{Name: ied.Name}
	for _, ap := range ied.AccessPoints {
		if ap.Server == nil {
			continue
		}
		for i := range ap.Server.LDevices {
			ld := &ap.Server.LDevices[i]
			for _, ln := range ld.AllLNs() {
				li := model.LNInstance{LD: ld.Inst, Name: ln.Name(), DOs: map[string][]string{}}
				attrs, _ := d.Expand(ln)
				for _, do := range d.DataObjects(ln) {
					li.DOs[do.Name] = nil
				}
				for _, a := range attrs {
					top := strings.SplitN(a.DO, ".", 2)[0]
					da := strings.SplitN(a.DA, ".", 2)[0]
					if !contains(li.DOs[top], da) {
						li.DOs[top] = append(li.DOs[top], da)
					}
				}
				dev.LNs = append(dev.LNs, li)
			}
		}
	}
	return dev, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// CheckBAP checks an IED of the document against an actor of a Basic
// Application Profile with the model's checker (IEC TR 61850-7-6 4.3).
func CheckBAP(d *Document, m *model.Model, iedName, bap, actor string, variants []string) (*model.CheckReport, error) {
	dev, err := d.Device(iedName)
	if err != nil {
		return nil, err
	}
	return m.CheckDevice(bap, actor, variants, dev)
}
