package scl

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cB-Sigma/iec61850/model"
)

// Gateway describes a gateway as an IEC 61850 server IED built from
// configured containers, for the server role: an IID file of this IED lets a
// system configurator engineer it into a substation (IEC 61850-6 Clause 7,
// 5.4; a gateway is modelled like any IED, 6.1).
type Gateway struct {
	// IEDName is the IED name (9.3.2 rules); FileType IID (default) or CID.
	IEDName, FileType string
	Manufacturer      string
	// APName is the access point (default S1).
	APName string
	// Address parameters of the server access point (IP, OSI selectors …).
	Address []P
	// SubNetwork (default W1, type 8-MMS).
	SubNetwork string
	// UUID of the file; generated when empty.
	UUID string
	// LDs are the logical devices (one per group of containers).
	LDs []GatewayLD
	// Tool is written as Header toolID.
	Tool string
}

// GatewayLD is a logical device of the gateway.
type GatewayLD struct {
	Inst   string
	Desc   string
	Points []GatewayPoint
	// Controls are controllable data objects of GGIO1 (SPCSO for binary,
	// ISCSO for integer controls).
	Controls []GatewayControl
	// Log adds a log control block logging the Points data set to the
	// log GeneralLog of LLN0 (IEC 61850-7-2 Clause 17.3).
	Log bool
	// Settings are analogue settings (GAPC1 StrValN, ASG of the SG
	// variant) with SettingGroups groups (LLN0 SettingControl; default
	// 1 when there are settings).
	Settings      []GatewaySetting
	SettingGroups int
	// GOOSE publishes the points (value and quality of each) as the data
	// set GoosePoints of the GOOSE control block gcbPoints.
	GOOSE *GatewayGOOSE
}

// GatewayGOOSE is the GOOSE control block of a logical device and its
// Communication GSE address (IEC 61850-8-1 Annex C; 61850-6 9.3.10).
type GatewayGOOSE struct {
	AppID          uint16 // APPID
	DstMAC         string // multicast MAC, 01-0C-CD-01-00-00 form
	VLANID         int    // -1: untagged
	VLANPriority   int
	MinTime        int // ms
	MaxTime        int // ms
	ConfRev        uint32
	SecurityEnable string // None, Signature, SignatureAndEncryption (IEC 62351-6)
}

// GoosePointMembers lists the GoosePoints members of a logical device's
// points: the value attribute and q of each ("AnIn1.mag.f", "AnIn1.q").
func (ld GatewayLD) GoosePointMembers() []string {
	pn, _, _ := ld.DONames()
	var out []string
	for i, p := range ld.Points {
		base, _, _, _ := pointKind(p.Kind)
		attr := "stVal"
		if base == "AnIn" {
			attr = "mag.f"
		}
		out = append(out, pn[i]+"."+attr, pn[i]+".q")
	}
	return out
}

// GatewaySetting is one analogue setting of a setting group.
type GatewaySetting struct {
	Name, Desc string
}

// GatewayControl is one controllable value the gateway serves: binary
// (SPC, GGIO SPCSO) or integer (INC, GGIO ISCSO), with its control model
// (a CtlModelKind literal of IEC 61850-7-3, default
// sbo-with-enhanced-security).
type GatewayControl struct {
	Name, Kind, Desc, CtlModel string
	// TimeActivated adds operTm to Oper, SBOw and Cancel (time activated
	// operate, IEC 61850-7-2 20.x).
	TimeActivated bool
}

// GatewayCtlModels are the control models a gateway control may have.
var GatewayCtlModels = []string{"direct-with-normal-security", "sbo-with-normal-security", "direct-with-enhanced-security", "sbo-with-enhanced-security"}

// DONames returns the GGIO1 data object names ExportGateway gives the
// logical device's points and controls, in order (AnIn1, Ind1, IntIn1,
// SPCSO1, ISCSO1 … numbered per kind).
func (ld GatewayLD) DONames() (points, controls []string, err error) {
	n := map[string]int{}
	for _, p := range ld.Points {
		base, _, _, err := pointKind(p.Kind)
		if err != nil {
			return nil, nil, fmt.Errorf("scl: point %s: %w", p.Name, err)
		}
		n[base]++
		points = append(points, base+strconv.Itoa(n[base]))
	}
	for _, c := range ld.Controls {
		base, _, err := controlKind(c.Kind)
		if err != nil {
			return nil, nil, fmt.Errorf("scl: control %s: %w", c.Name, err)
		}
		n[base]++
		controls = append(controls, base+strconv.Itoa(n[base]))
	}
	return points, controls, nil
}

func pointKind(kind string) (base, typ, fc string, err error) {
	switch kind {
	case "analog", "analogue":
		return "AnIn", "SIG_MV", "MX", nil
	case "binary", "boolean":
		return "Ind", "SIG_SPS", "ST", nil
	case "integer":
		return "IntIn", "SIG_INS", "ST", nil
	}
	return "", "", "", fmt.Errorf("kind %q is not analog, binary or integer", kind)
}

func controlKind(kind string) (base, cdc string, err error) {
	switch kind {
	case "binary", "boolean":
		return "SPCSO", "SPC", nil
	case "integer":
		return "ISCSO", "INC", nil
	}
	return "", "", fmt.Errorf("kind %q is not binary or integer", kind)
}

// ctlModelCode is the short form of a control model in type ids.
var ctlModelCode = map[string]string{"direct-with-normal-security": "DN", "sbo-with-normal-security": "SN",
	"direct-with-enhanced-security": "DE", "sbo-with-enhanced-security": "SE"}

// GatewayPoint is one value the gateway serves: analogue (MV, GGIO AnIn),
// binary (SPS, GGIO Ind) or integer (INS, GGIO IntIn). Desc becomes the
// data object's desc.
type GatewayPoint struct {
	Name, Kind, Desc string
}

func el(local string, attrs ...string) *Node {
	n := &Node{Kind: KindElement, Local: local, Space: NS}
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i+1] != "" || attrs[i] == "inst" {
			n.Attrs = append(n.Attrs, Attr{Local: attrs[i], Value: attrs[i+1]})
		}
	}
	return n
}

func (n *Node) add(children ...*Node) *Node {
	for _, c := range children {
		c.Parent = n
		n.Children = append(n.Children, c)
	}
	return n
}

func text(s string) *Node { return &Node{Kind: KindText, Text: s} }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// indent inserts line breaks and tabs between elements so the file reads
// well; it only adds whitespace text.
func indent(n *Node, depth int) {
	if len(n.Children) == 0 {
		return
	}
	var out []*Node
	for _, c := range n.Children {
		if c.Kind == KindText {
			out = append(out, c)
			continue
		}
		out = append(out, text("\n"+strings.Repeat("\t", depth+1)))
		indent(c, depth+1)
		c.Parent = n
		out = append(out, c)
	}
	if n.Children[0].Kind == KindElement {
		out = append(out, text("\n"+strings.Repeat("\t", depth)))
	}
	n.Children = out
}

// ExportGateway builds the SCL document of the gateway IED: Header,
// Communication with the access point address, the IED with services, one
// logical device per GatewayLD (LLN0 with a data set of all points and a
// buffered and an unbuffered report control block, LPHD1, GGIO1 with the
// points) and the DataTypeTemplates it uses.
func ExportGateway(g Gateway) (*Document, error) {
	if why := types["tIEDName"](g.IEDName); why != "" {
		return nil, fmt.Errorf("scl: IED name %q %s", g.IEDName, why)
	}
	ft := orDefault(g.FileType, "IID")
	ap := orDefault(g.APName, "S1")
	if g.UUID == "" {
		g.UUID = newUUID()
	}
	root := el("SCL", "version", "2007", "revision", "C", "release", "5")
	root.Attrs = append([]Attr{{Local: "xmlns", Space: "xmlns", Value: NS}}, root.Attrs...)
	root.add(el("Header", "id", g.IEDName+" "+ft, "toolID", orDefault(g.Tool, "SigmaM2M"), "fileType", ft, "uuid", g.UUID, "version", "1", "revision", "0"))
	cap := el("ConnectedAP", "iedName", g.IEDName, "apName", ap)
	if len(g.Address) > 0 {
		addr := el("Address")
		for _, p := range g.Address {
			addr.add(el("P", "type", p.Type).add(text(p.Value)))
		}
		cap.add(addr)
	}
	gooses := 0
	for _, ld := range g.LDs {
		gs := ld.GOOSE
		if gs == nil || len(ld.Points) == 0 {
			continue
		}
		gooses++
		addr := el("Address").add(el("P", "type", "MAC-Address").add(text(strings.ToUpper(gs.DstMAC))),
			el("P", "type", "APPID").add(text(fmt.Sprintf("%04X", gs.AppID))))
		if gs.VLANID >= 0 {
			addr.add(el("P", "type", "VLAN-ID").add(text(fmt.Sprintf("%03X", gs.VLANID))),
				el("P", "type", "VLAN-PRIORITY").add(text(strconv.Itoa(gs.VLANPriority))))
		}
		cap.add(el("GSE", "ldInst", ld.Inst, "cbName", "gcbPoints").add(addr,
			el("MinTime", "unit", "s", "multiplier", "m").add(text(strconv.Itoa(gs.MinTime))),
			el("MaxTime", "unit", "s", "multiplier", "m").add(text(strconv.Itoa(gs.MaxTime)))))
	}
	root.add(el("Communication").add(el("SubNetwork", "name", orDefault(g.SubNetwork, "W1"), "type", "8-MMS").add(cap)))
	logs := 0
	for _, ld := range g.LDs {
		if ld.Log && len(ld.Points) > 0 {
			logs++
		}
	}
	ied := el("IED", "name", g.IEDName, "manufacturer", orDefault(g.Manufacturer, "SigmaM2M"), "type", "gateway",
		"originalSclVersion", "2007", "originalSclRevision", "C", "originalSclRelease", "5")
	sgs, timedCtl := 0, false
	for _, ld := range g.LDs {
		if len(ld.Settings) > 0 {
			sgs = max(sgs, ld.SettingGroups, 1)
		}
		for _, c := range ld.Controls {
			timedCtl = timedCtl || c.TimeActivated
		}
	}
	services := []*Node{el("DynAssociation", "max", "8")}
	if sgs > 0 {
		services = append(services, el("SettingGroups").add(el("SGEdit"), el("ConfSG")))
	}
	services = append(services, el("GetDirectory"), el("GetDataObjectDefinition"), el("DataObjectDirectory"),
		el("GetDataSetValue"), el("DataSetDirectory"), el("DynDataSet", "max", "16", "maxAttributes", "64"), el("ReadWrite"))
	if timedCtl {
		services = append(services, el("TimerActivatedControl"))
	}
	services = append(services, el("ConfReportControl", "max", strconv.Itoa(2*len(g.LDs)), "bufConf", "false"), el("GetCBValues"))
	if logs > 0 {
		services = append(services, el("ConfLogControl", "max", strconv.Itoa(logs)))
	}
	services = append(services,
		el("ReportSettings", "cbName", "Fix", "datSet", "Dyn", "rptID", "Dyn", "optFields", "Dyn", "bufTime", "Dyn", "trgOps", "Dyn", "intgPd", "Dyn", "resvTms", "true"))
	if logs > 0 {
		services = append(services, el("LogSettings", "cbName", "Fix", "datSet", "Fix", "logEna", "Dyn", "trgOps", "Dyn", "intgPd", "Dyn"))
	}
	if gooses > 0 {
		gss := el("GSESettings", "cbName", "Fix", "datSet", "Fix", "appID", "Fix", "dataLabel", "Fix")
		sig, enc := false, false
		for _, ld := range g.LDs {
			if ld.GOOSE != nil {
				sig = sig || ld.GOOSE.SecurityEnable == "Signature" || ld.GOOSE.SecurityEnable == "SignatureAndEncryption"
				enc = enc || ld.GOOSE.SecurityEnable == "SignatureAndEncryption"
			}
		}
		if sig {
			gss.add(el("McSecurity", "signature", "true", "encryption", strconv.FormatBool(enc)))
		}
		services = append(services, gss, el("GOOSE", "max", strconv.Itoa(gooses)))
	}
	services = append(services, el("FileHandling", "mms", "true"), el("ConfLNs", "fixPrefix", "true", "fixLnInst", "true"))
	ied.add(el("Services", "nameLength", "64").add(services...))
	server := el("Server").add(el("Authentication"))
	lnTypes := map[string][]string{} // GGIO type id -> DO list
	used := map[string]bool{}
	for _, ld := range g.LDs {
		if why := types["tLDInst"](ld.Inst); why != "" {
			return nil, fmt.Errorf("scl: logical device %q %s", ld.Inst, why)
		}
		if len(g.IEDName+ld.Inst) > 64 {
			return nil, fmt.Errorf("scl: logical device name %s%s is longer than 64 characters", g.IEDName, ld.Inst)
		}
		ln0 := el("LN0", "lnClass", "LLN0", "inst", "", "lnType", "SIG_LLN0")
		ds := el("DataSet", "name", "Points")
		ggio := el("LN", "lnClass", "GGIO", "inst", "1", "lnType", "SIG_GGIO_"+ld.Inst)
		var dos []string
		pnames, cnames, err := ld.DONames()
		if err != nil {
			return nil, err
		}
		for i, p := range ld.Points {
			_, typ, fc, _ := pointKind(p.Kind)
			do := pnames[i]
			used[typ] = true
			dos = append(dos, do+"="+typ)
			ds.add(el("FCDA", "ldInst", ld.Inst, "lnClass", "GGIO", "lnInst", "1", "doName", do, "fc", fc))
			doi := el("DOI", "name", do, "desc", p.Name)
			if p.Desc != "" {
				doi.add(el("DAI", "name", "d").add(el("Val").add(text(p.Desc))))
			}
			ggio.add(doi)
		}
		for i, c := range ld.Controls {
			_, cdc, _ := controlKind(c.Kind)
			cm := orDefault(c.CtlModel, "sbo-with-enhanced-security")
			code, ok := ctlModelCode[cm]
			if !ok {
				return nil, fmt.Errorf("scl: control %s: ctlModel %q is not one of %s", c.Name, cm, strings.Join(GatewayCtlModels, ", "))
			}
			typ := "SIG_" + cdc + "_" + code
			if c.TimeActivated {
				typ += "T"
			}
			used[typ] = true
			dos = append(dos, cnames[i]+"="+typ)
			doi := el("DOI", "name", cnames[i], "desc", c.Name)
			if c.Desc != "" {
				doi.add(el("DAI", "name", "d").add(el("Val").add(text(c.Desc))))
			}
			ggio.add(doi)
		}
		if len(ld.Points) > 0 {
			ln0.add(ds,
				el("ReportControl", "name", "brcbPoints", "datSet", "Points", "rptID", g.IEDName+ld.Inst+"/Points", "confRev", "1", "buffered", "true", "bufTime", "50", "intgPd", "0").add(
					el("TrgOps", "dchg", "true", "qchg", "true", "period", "true"), el("OptFields", "seqNum", "true", "timeStamp", "true", "dataSet", "true", "reasonCode", "true", "entryID", "true", "configRef", "true"), el("RptEnabled", "max", "4")),
				el("ReportControl", "name", "urcbPoints", "datSet", "Points", "confRev", "1").add(
					el("TrgOps", "dchg", "true", "qchg", "true", "period", "true"), el("OptFields", "seqNum", "true", "timeStamp", "true", "dataSet", "true", "reasonCode", "true"), el("RptEnabled", "max", "4")))
		}
		if ld.Log && len(ld.Points) > 0 {
			ln0.add(el("LogControl", "name", "lcbPoints", "datSet", "Points", "logName", "GeneralLog", "logEna", "true", "reasonCode", "true", "intgPd", "0").add(
				el("TrgOps", "dchg", "true", "qchg", "true")))
		}
		ln0.add(el("DOI", "name", "Mod").add(el("DAI", "name", "ctlModel").add(el("Val").add(text("status-only")))))
		if ld.Log && len(ld.Points) > 0 {
			ln0.add(el("Log", "name", "GeneralLog"))
		}
		if gs := ld.GOOSE; gs != nil && len(ld.Points) > 0 {
			sec := gs.SecurityEnable
			if sec == "" {
				sec = "None"
			}
			gcb := el("GSEControl", "name", "gcbPoints", "datSet", "GoosePoints", "confRev", strconv.FormatUint(uint64(max(gs.ConfRev, 1)), 10),
				"type", "GOOSE", "appID", g.IEDName+ld.Inst+"/gcbPoints", "securityEnable", sec)
			// The data set comes before the report control blocks.
			gds := el("DataSet", "name", "GoosePoints")
			for _, m := range ld.GoosePointMembers() {
				do, da, _ := strings.Cut(m, ".")
				fc := "ST"
				if strings.HasPrefix(do, "AnIn") {
					fc = "MX"
				}
				gds.add(el("FCDA", "ldInst", ld.Inst, "lnClass", "GGIO", "lnInst", "1", "doName", do, "daName", da, "fc", fc))
			}
			ln0.Children = append([]*Node{gds}, ln0.Children...)
			gds.Parent = ln0
			ln0.add(gcb)
		}
		// One GAPC per setting (GAPC.StrVal is single, IEC 61850-7-4).
		var gapcs []*Node
		if len(ld.Settings) > 0 {
			n := max(ld.SettingGroups, 1)
			ln0.add(el("SettingControl", "numOfSGs", strconv.Itoa(n), "actSG", "1"))
			for i, st := range ld.Settings {
				doi := el("DOI", "name", "StrVal", "desc", st.Name)
				if st.Desc != "" {
					doi.add(el("DAI", "name", "d").add(el("Val").add(text(st.Desc))))
				}
				gapcs = append(gapcs, el("LN", "lnClass", "GAPC", "inst", strconv.Itoa(i+1), "lnType", "SIG_GAPC").add(doi))
			}
			used["SIG_ASG"] = true
			lnTypes["SIG_GAPC"] = []string{"StrVal=SIG_ASG"}
		}
		lds := el("LDevice", "inst", ld.Inst, "desc", ld.Desc).add(ln0, el("LN", "lnClass", "LPHD", "inst", "1", "lnType", "SIG_LPHD"))
		lds.add(gapcs...)
		if len(ld.Points)+len(ld.Controls) > 0 {
			lds.add(ggio)
			lnTypes["SIG_GGIO_"+ld.Inst] = dos
		}
		server.add(lds)
	}
	ied.add(el("AccessPoint", "name", ap).add(server))
	root.add(ied)
	root.add(gatewayTemplates(lnTypes, used))
	indent(root, 0)
	t := &Tree{Root: root, Prolog: []*Node{{Kind: KindProcInst, Target: "xml", Text: `version="1.0" encoding="UTF-8"`}, text("\n")}}
	setParents(root)
	return FromTree(t)
}

func setParents(n *Node) {
	for _, c := range n.Children {
		c.Parent = n
		setParents(c)
	}
}

func da(name, fc, bType string, more ...string) *Node {
	return el("DA", append([]string{"name", name, "fc", fc, "bType", bType}, more...)...)
}

func gatewayTemplates(ggio map[string][]string, used map[string]bool) *Node {
	dtt := el("DataTypeTemplates")
	dtt.add(el("LNodeType", "id", "SIG_LLN0", "lnClass", "LLN0").add(
		el("DO", "name", "Mod", "type", "SIG_ENC_Mod"), el("DO", "name", "Beh", "type", "SIG_ENS_Beh"),
		el("DO", "name", "Health", "type", "SIG_ENS_Health"), el("DO", "name", "NamPlt", "type", "SIG_LPL")))
	dtt.add(el("LNodeType", "id", "SIG_LPHD", "lnClass", "LPHD").add(
		el("DO", "name", "PhyNam", "type", "SIG_DPL"), el("DO", "name", "PhyHealth", "type", "SIG_ENS_Health"),
		el("DO", "name", "Proxy", "type", "SIG_SPS")))
	used["SIG_SPS"] = true
	ids := make([]string, 0, len(ggio))
	for id := range ggio {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cls := "GGIO"
		if id == "SIG_GAPC" {
			cls = "GAPC"
		}
		lt := el("LNodeType", "id", id, "lnClass", cls).add(el("DO", "name", "Beh", "type", "SIG_ENS_Beh"))
		for _, d := range ggio[id] {
			name, typ, _ := strings.Cut(d, "=")
			lt.add(el("DO", "name", name, "type", typ))
		}
		dtt.add(lt)
	}
	stq := func(t *Node, st *Node) *Node {
		return t.add(st, da("q", "ST", "Quality", "qchg", "true"), da("t", "ST", "Timestamp"))
	}
	dtt.add(stq(el("DOType", "id", "SIG_ENC_Mod", "cdc", "ENC"), da("stVal", "ST", "Enum", "type", "SIG_BehaviourModeKind", "dchg", "true")).
		add(da("ctlModel", "CF", "Enum", "type", "SIG_CtlModelKind", "valKind", "RO").add(el("Val").add(text("status-only")))))
	dtt.add(stq(el("DOType", "id", "SIG_ENS_Beh", "cdc", "ENS"), da("stVal", "ST", "Enum", "type", "SIG_BehaviourModeKind", "dchg", "true")))
	dtt.add(stq(el("DOType", "id", "SIG_ENS_Health", "cdc", "ENS"), da("stVal", "ST", "Enum", "type", "SIG_HealthKind", "dchg", "true")))
	dtt.add(el("DOType", "id", "SIG_LPL", "cdc", "LPL").add(da("vendor", "DC", "VisString255"), da("swRev", "DC", "VisString255"),
		da("configRev", "DC", "VisString255"), da("ldNs", "EX", "VisString255")))
	dtt.add(el("DOType", "id", "SIG_DPL", "cdc", "DPL").add(da("vendor", "DC", "VisString255")))
	// Points can be substituted (SV: subEna, subVal or subMag, subQ,
	// subID) and blocked (BL: blkEna), IEC 61850-7-3 SPS, INS, MV.
	subst := func(t *Node, subName, subType string, more ...string) *Node {
		return t.add(da("subEna", "SV", "BOOLEAN"), da(subName, "SV", subType, more...), da("subQ", "SV", "Quality"),
			da("subID", "SV", "VisString64"), da("blkEna", "BL", "BOOLEAN"))
	}
	if used["SIG_SPS"] {
		dtt.add(subst(stq(el("DOType", "id", "SIG_SPS", "cdc", "SPS"), da("stVal", "ST", "BOOLEAN", "dchg", "true")), "subVal", "BOOLEAN").add(da("d", "DC", "VisString255")))
	}
	if used["SIG_INS"] {
		dtt.add(subst(stq(el("DOType", "id", "SIG_INS", "cdc", "INS"), da("stVal", "ST", "INT32", "dchg", "true")), "subVal", "INT32").add(da("d", "DC", "VisString255")))
	}
	if used["SIG_MV"] || used["SIG_ASG"] {
		dtt.add(el("DAType", "id", "SIG_AV").add(el("BDA", "name", "f", "bType", "FLOAT32")))
	}
	if used["SIG_MV"] {
		dtt.add(subst(el("DOType", "id", "SIG_MV", "cdc", "MV").add(da("mag", "MX", "Struct", "type", "SIG_AV", "dchg", "true"),
			da("q", "MX", "Quality", "qchg", "true"), da("t", "MX", "Timestamp")), "subMag", "Struct", "type", "SIG_AV").add(da("d", "DC", "VisString255")))
	}
	if used["SIG_ASG"] {
		dtt.add(el("DOType", "id", "SIG_ASG", "cdc", "ASG").add(da("setMag", "SG", "Struct", "type", "SIG_AV"), da("d", "DC", "VisString255")))
	}
	gatewayControlTemplates(dtt, used, stq)
	enum := func(id string, vals ...string) *Node {
		e := el("EnumType", "id", id)
		for i := 0; i+1 < len(vals); i += 2 {
			e.add(el("EnumVal", "ord", vals[i]).add(text(vals[i+1])))
		}
		return e
	}
	dtt.add(enum("SIG_BehaviourModeKind", "1", "on", "2", "on-blocked", "3", "test", "4", "test/blocked", "5", "off"),
		enum("SIG_HealthKind", "1", "Ok", "2", "Warning", "3", "Alarm"),
		modelEnum("SIG_CtlModelKind", "CtlModelKind"))
	if used["SIG_Originator"] {
		dtt.add(modelEnum("SIG_OriginatorCategoryKind", "OriginatorCategoryKind"))
	}
	// The schema orders LNodeTypes, DOTypes, DATypes, EnumTypes.
	rank := map[string]int{"LNodeType": 0, "DOType": 1, "DAType": 2, "EnumType": 3}
	sort.SliceStable(dtt.Children, func(i, j int) bool { return rank[dtt.Children[i].Local] < rank[dtt.Children[j].Local] })
	return dtt
}

// modelEnum writes an EnumType with the literals of an enumeration of
// the IEC 61850 model (package model, from IEC's NSD files when they are
// loaded, else the literals of fallbackEnums).
func modelEnum(id, name string) *Node {
	e := el("EnumType", "id", id)
	if m, err := model.Default(); err == nil {
		if en, ok := m.Enum(name); ok {
			for _, it := range en.Items {
				if !it.Deprecated {
					e.add(el("EnumVal", "ord", strconv.Itoa(it.Value)).add(text(it.Name)))
				}
			}
			return e
		}
	}
	for i, lit := range fallbackEnums[name] {
		e.add(el("EnumVal", "ord", strconv.Itoa(i)).add(text(lit)))
	}
	return e
}

// fallbackEnums are the literals, by value from 0, of the enumerations
// the gateway export writes, for when the model is not loaded (facts of
// IEC 61850-7-3 and -7-2: names and values).
var fallbackEnums = map[string][]string{
	"CtlModelKind": {"status-only", "direct-with-normal-security", "sbo-with-normal-security", "direct-with-enhanced-security", "sbo-with-enhanced-security"},
	"OriginatorCategoryKind": {"not-supported", "bay-control", "station-control", "remote-control", "automatic-bay",
		"automatic-station", "automatic-remote", "maintenance", "process"},
}

// controlFields are the members of the Oper (and SBOw) and Cancel
// structures of a controllable class: from the IEC 61850-8-1 service name
// space of package model when it is loaded, else the same members as
// facts (names and types of the 8-1 mapping).
func controlFields(cdc string) (oper, cancel []model.Attr) {
	if m, err := model.Default(); err == nil {
		if ci, ok := m.Control(cdc); ok {
			return ci.OperFields, ci.CancelFields
		}
	}
	oper = []model.Attr{{Name: "ctlVal"}, {Name: "operTm", Type: "Timestamp"}, {Name: "origin"}, {Name: "ctlNum", Type: "INT8U"},
		{Name: "T", Type: "Timestamp"}, {Name: "Test", Type: "BOOLEAN"}, {Name: "Check", Type: "CheckConditions"}}
	return oper, oper[:6]
}

// gatewayControlTemplates adds the DOTypes of the controls used (SPC or
// INC per control model) with their Oper, SBOw and Cancel structures,
// whose members come from the IEC 61850-8-1 service name space of
// package model (without operTm: time activated operate is not offered).
func gatewayControlTemplates(dtt *Node, used map[string]bool, stq func(t, st *Node) *Node) {
	var ids []string
	for id := range used {
		if strings.HasPrefix(id, "SIG_SPC_") || strings.HasPrefix(id, "SIG_INC_") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	svcTypes := map[string]bool{}
	for _, id := range ids {
		cdc, code := id[4:7], id[8:10]
		timed := strings.HasSuffix(id, "T")
		var cm string
		for k, v := range ctlModelCode {
			if v == code {
				cm = k
			}
		}
		operFields, cancelFields := controlFields(cdc)
		stType := "BOOLEAN"
		if cdc == "INC" {
			stType = "INT32"
		}
		sbo := code == "SN" || code == "SE"
		enhanced := code == "DE" || code == "SE"
		t := stq(el("DOType", "id", id, "cdc", cdc), da("stVal", "ST", stType, "dchg", "true"))
		if sbo {
			t.add(da("stSeld", "ST", "BOOLEAN", "dchg", "true"))
		}
		svc := func(name string, fields []model.Attr) {
			tid := "SIG_" + cdc + "_" + name
			if timed {
				tid += "_T"
			}
			t.add(da(name, "CO", "Struct", "type", tid))
			if svcTypes[tid] {
				return
			}
			svcTypes[tid] = true
			dat := el("DAType", "id", tid)
			for _, f := range fields {
				switch f.Name {
				case "operTm":
					if !timed {
						continue
					}
					dat.add(el("BDA", "name", f.Name, "bType", "Timestamp"))
				case "ctlVal":
					dat.add(el("BDA", "name", f.Name, "bType", stType))
				case "origin":
					dat.add(el("BDA", "name", f.Name, "bType", "Struct", "type", "SIG_Originator"))
					used["SIG_Originator"] = true
				default:
					bt := f.Type
					if bt == "CheckConditions" { // the 7-2 name of the SCL basic type Check
						bt = "Check"
					}
					dat.add(el("BDA", "name", f.Name, "bType", bt))
				}
			}
			dtt.add(dat)
		}
		if code == "SN" {
			t.add(da("SBO", "CO", "ObjRef"))
		}
		if code == "SE" {
			svc("SBOw", operFields)
		}
		svc("Oper", operFields)
		if sbo {
			svc("Cancel", cancelFields)
		}
		t.add(da("ctlModel", "CF", "Enum", "type", "SIG_CtlModelKind", "valKind", "RO").add(el("Val").add(text(cm))))
		if sbo {
			t.add(da("sboTimeout", "CF", "INT32U").add(el("Val").add(text("30000"))))
		}
		if enhanced {
			t.add(da("operTimeout", "CF", "INT32U").add(el("Val").add(text("30000"))))
		}
		t.add(da("d", "DC", "VisString255"))
		dtt.add(t)
	}
	if used["SIG_Originator"] {
		dtt.add(el("DAType", "id", "SIG_Originator").add(el("BDA", "name", "orCat", "bType", "Enum", "type", "SIG_OriginatorCategoryKind"),
			el("BDA", "name", "orIdent", "bType", "Octet64")))
	}
}
