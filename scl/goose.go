package scl

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Member is a data set member as a GOOSE or SV subscriber sees it.
type Member struct {
	// Ref is LDinst/LN.DO[.DA] (IED-relative); Name the LN.DO[.DA] part.
	Ref, Name string
	FC        string
	// BType is the leaf's basic type ("Struct" for an FCD or a structured
	// attribute); Type the EnumType id of an Enum.
	BType, Type string
}

// McSecurity is the multicast security offered by the publishing server
// (GSESettings / SMVSettings McSecurity, used by IEC 62351-6).
type McSecurity struct {
	Signature, Encryption bool
}

// Publication is a GOOSE or sampled value control block with everything a
// subscriber or publisher needs: the block (9.3.10, 9.3.11), its data set
// (9.3.7) and its address (9.4.4, 9.4.5).
type Publication struct {
	IED, LDInst, LDName, Name string
	// CBRef is the control block reference in the IEC 61850-8-1 form
	// LDName/LLN0$GO$Name (MS for multicast SV, US for unicast).
	CBRef string
	// ID is the GOOSE appID (goID) or the SV smvID.
	ID string
	// DataSet is LDName/LLN0$Name.
	DataSet string
	ConfRev uint32
	Members []Member
	// Address parameters (all P elements) and the decoded common ones.
	Address  map[string]string
	APPID    int // -1 when not given
	DstMAC   string
	VLANID   *int
	Priority *int
	// MinTime and MaxTime (GSE only; 0 when not given).
	MinTime, MaxTime time.Duration
	// SecurityEnable is None, Signature or SignatureAndEncryption.
	SecurityEnable string
	// Offered is the server's McSecurity; KDA marks kdaParticipant.
	Offered McSecurity
	KDA     bool
	// Routable is set by a Protocol R-GOOSE / R-SV element.
	Routable bool
	// FixedOffs (GOOSE), SmpRate, NofASDU, SmpMod, Multicast (SV).
	FixedOffs bool
	SmpRate   int
	NofASDU   int
	SmpMod    string
	Multicast bool
	// Subscribers are the IEDName entries.
	Subscribers []IEDName
	SV          bool
}

// Publications lists the GOOSE (sv=false) or sampled value (sv=true)
// control blocks of an IED ("" for all IEDs).
func (d *Document) Publications(iedName string, sv bool) ([]Publication, error) {
	var out []Publication
	for i := range d.SCL.IEDs {
		ied := &d.SCL.IEDs[i]
		if iedName != "" && ied.Name != iedName {
			continue
		}
		for j := range ied.AccessPoints {
			ap := &ied.AccessPoints[j]
			if ap.Server == nil {
				continue
			}
			for k := range ap.Server.LDevices {
				ld := &ap.Server.LDevices[k]
				if ld.LN0 == nil {
					continue
				}
				if sv {
					for _, c := range ld.LN0.SampledValueControls {
						p, err := d.svPublication(ied, ap, ld, c)
						if err != nil {
							return nil, err
						}
						out = append(out, p)
					}
				} else {
					for _, c := range ld.LN0.GSEControls {
						if c.Type == "GSSE" {
							continue
						}
						p, err := d.goosePublication(ied, ap, ld, c)
						if err != nil {
							return nil, err
						}
						out = append(out, p)
					}
				}
			}
		}
	}
	return out, nil
}

// Subscriptions lists the publications an IED subscribes to: those whose
// IEDName lists it, and those its Inputs name with serviceType GOOSE or
// SMV and a source control block (9.3.13).
func (d *Document) Subscriptions(subscriber string, sv bool) ([]Publication, error) {
	all, err := d.Publications("", sv)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	if ied, err := d.IED(subscriber); err == nil {
		st := "GOOSE"
		if sv {
			st = "SMV"
		}
		for _, ap := range ied.AccessPoints {
			if ap.Server == nil {
				for _, ln := range ap.LNs {
					addInputs(want, &ln, st)
				}
				continue
			}
			for _, ld := range ap.Server.LDevices {
				for _, ln := range ld.AllLNs() {
					addInputs(want, ln, st)
				}
			}
		}
	}
	var out []Publication
	for _, p := range all {
		match := want[p.IED+"/"+p.LDInst+"/"+p.Name]
		for _, s := range p.Subscribers {
			match = match || strings.TrimSpace(s.Name) == subscriber
		}
		if match && p.IED != subscriber {
			out = append(out, p)
		}
	}
	return out, nil
}

func addInputs(want map[string]bool, ln *LN, st string) {
	if ln.Inputs == nil {
		return
	}
	for _, er := range ln.Inputs.ExtRefs {
		if er.ServiceType == st && er.SrcCBName != "" {
			want[er.IEDName+"/"+orDefault(er.SrcLDInst, er.LDInst)+"/"+er.SrcCBName] = true
		}
	}
}

func (d *Document) members(ied *IED, ld *LDevice, dsName string) ([]Member, error) {
	if ld.LN0 == nil || dsName == "" {
		return nil, nil
	}
	ds := ld.LN0.DataSet(dsName)
	if ds == nil {
		return nil, fmt.Errorf("scl: data set %s of %s/%s is not defined", dsName, ied.Name, ld.Inst)
	}
	var out []Member
	for _, f := range ds.FCDAs {
		m := Member{Ref: f.LDInst + "/" + f.Ref(), Name: f.Ref(), FC: f.FC, BType: "Struct"}
		if f.DAName != "" {
			if tld, _ := ied.LDevice(f.LDInst); tld != nil {
				if ln := tld.LN(f.Prefix, f.LNClass, f.LNInst); ln != nil {
					attrs, _ := d.Expand(ln)
					do, da := stripArrays(f.DOName), stripArrays(f.DAName)
					for _, a := range attrs {
						if a.DO == do && a.DA == da {
							m.BType, m.Type = a.BType, a.Type
						}
					}
				}
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func (d *Document) fillAddress(p *Publication, gse *GSE) {
	p.Address = map[string]string{}
	p.APPID = -1
	if gse == nil || gse.Address == nil {
		return
	}
	for _, x := range gse.Address.Ps {
		p.Address[x.Type] = strings.TrimSpace(x.Value)
	}
	if v, ok := p.Address["APPID"]; ok {
		if n, err := strconv.ParseUint(v, 16, 16); err == nil {
			p.APPID = int(n)
		}
	}
	p.DstMAC = strings.ToUpper(p.Address["MAC-Address"])
	if v, ok := p.Address["VLAN-ID"]; ok {
		if n, err := strconv.ParseUint(v, 16, 12); err == nil {
			x := int(n)
			p.VLANID = &x
		}
	}
	if v, ok := p.Address["VLAN-PRIORITY"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			p.Priority = &n
		}
	}
	p.MinTime, p.MaxTime = msValue(gse.MinTime), msValue(gse.MaxTime)
}

// msValue reads a tDurationInMilliSec value: milliseconds (9.4.4); a
// multiplier other than m is applied to the unit s (see F-1041).
func msValue(v *Value) time.Duration {
	if v == nil {
		return 0
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v.Value), 64)
	if err != nil || f < 0 {
		return 0
	}
	switch v.Multiplier {
	case "", "m":
		return time.Duration(f * float64(time.Millisecond))
	case "k":
		return time.Duration(f * float64(time.Second) * 1000)
	case "mu":
		return time.Duration(f * float64(time.Microsecond))
	}
	return time.Duration(f * float64(time.Millisecond))
}

func (d *Document) goosePublication(ied *IED, ap *AccessPoint, ld *LDevice, c GSEControl) (Publication, error) {
	ldName := ld.Name(ied.Name)
	p := Publication{IED: ied.Name, LDInst: ld.Inst, LDName: ldName, Name: c.Name,
		CBRef: ldName + "/LLN0$GO$" + c.Name, ID: c.AppID, SecurityEnable: orDefault(c.SecurityEnable, "None"),
		FixedOffs: parseBool(c.FixedOffs, false), Routable: c.Protocol != nil && strings.TrimSpace(c.Protocol.Value) == "R-GOOSE",
		Subscribers: c.IEDNames}
	if c.DatSet != "" {
		p.DataSet = ldName + "/LLN0$" + c.DatSet
	}
	if n, err := strconv.ParseUint(c.ConfRev, 10, 32); err == nil {
		p.ConfRev = uint32(n)
	}
	var err error
	if p.Members, err = d.members(ied, ld, c.DatSet); err != nil {
		return p, err
	}
	gse, _ := d.GSEAddress(ied.Name, ld.Inst, c.Name, false)
	d.fillAddress(&p, gse)
	set := ied.Service(ap, "GSESettings")
	if mc := set.Get("McSecurity"); mc != nil {
		p.Offered = McSecurity{mc.Bool("signature", false), mc.Bool("encryption", false)}
	}
	p.KDA = set.Bool("kdaParticipant", false)
	return p, nil
}

func (d *Document) svPublication(ied *IED, ap *AccessPoint, ld *LDevice, c SampledValueControl) (Publication, error) {
	ldName := ld.Name(ied.Name)
	multicast := parseBool(c.Multicast, true)
	fc := "MS"
	if !multicast {
		fc = "US"
	}
	p := Publication{IED: ied.Name, LDInst: ld.Inst, LDName: ldName, Name: c.Name, SV: true,
		CBRef: ldName + "/LLN0$" + fc + "$" + c.Name, ID: c.SmvID, SecurityEnable: orDefault(c.SecurityEnable, "None"),
		Routable: c.Protocol != nil && strings.TrimSpace(c.Protocol.Value) == "R-SV", Multicast: multicast,
		SmpMod: orDefault(c.SmpMod, "SmpPerPeriod"), Subscribers: c.IEDNames}
	p.SmpRate, _ = strconv.Atoi(c.SmpRate)
	p.NofASDU, _ = strconv.Atoi(c.NofASDU)
	if c.DatSet != "" {
		p.DataSet = ldName + "/LLN0$" + c.DatSet
	}
	if n, err := strconv.ParseUint(c.ConfRev, 10, 32); err == nil {
		p.ConfRev = uint32(n)
	}
	var err error
	if p.Members, err = d.members(ied, ld, c.DatSet); err != nil {
		return p, err
	}
	smv, _ := d.GSEAddress(ied.Name, ld.Inst, c.Name, true)
	d.fillAddress(&p, smv)
	set := ied.Service(ap, "SMVSettings")
	if mc := set.Get("McSecurity"); mc != nil {
		p.Offered = McSecurity{mc.Bool("signature", false), mc.Bool("encryption", false)}
	}
	p.KDA = set.Bool("kdaParticipant", false)
	return p, nil
}

// SubscriberSecurity is what a subscribing IED declares it supports
// (ClientServices GOOSEMcSecurity / SVMcSecurity; the older McSecurity is
// read as both, I.5.3.4).
func (ied *IED) SubscriberSecurity(sv bool) (McSecurity, bool) {
	cs := ied.Services.Get("ClientServices")
	if cs == nil {
		return McSecurity{}, false
	}
	name := "GOOSEMcSecurity"
	if sv {
		name = "SVMcSecurity"
	}
	mc := cs.Get(name)
	if mc == nil {
		mc = cs.Get("McSecurity")
	}
	if mc == nil {
		return McSecurity{}, false
	}
	return McSecurity{mc.Bool("signature", false), mc.Bool("encryption", false)}, true
}
