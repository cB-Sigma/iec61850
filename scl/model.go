package scl

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// Attribute values are kept as written (strings) so a wrong value never
// stops the parse; Validate reports it, and the accessor methods apply the
// defaults of IEC 61850-6.

// SCL is the typed model of a document (IEC 61850-6 Clause 9).
type SCL struct {
	Version  string `xml:"version,attr"`
	Revision string `xml:"revision,attr"`
	Release  string `xml:"release,attr"`

	Header            *Header            `xml:"Header"`
	Substations       []PSR              `xml:"Substation"`
	Communication     *Communication     `xml:"Communication"`
	IEDs              []IED              `xml:"IED"`
	DataTypeTemplates *DataTypeTemplates `xml:"DataTypeTemplates"`
	Lines             []PSR              `xml:"Line"`
	Processes         []PSR              `xml:"Process"`
}

// Header identifies the file (9.1).
type Header struct {
	ID            string             `xml:"id,attr"`
	Version       string             `xml:"version,attr"`
	Revision      string             `xml:"revision,attr"`
	ToolID        string             `xml:"toolID,attr"`
	FileType      string             `xml:"fileType,attr"`
	UUID          string             `xml:"uuid,attr"`
	BaseUUID      string             `xml:"baseUuid,attr"`
	NameStructure string             `xml:"nameStructure,attr"`
	History       []Hitem            `xml:"History>Hitem"`
	SourceFiles   []SclFileReference `xml:"SourceFiles>SclFileReference"`
}

// Hitem is a history entry.
type Hitem struct {
	Version     string             `xml:"version,attr"`
	Revision    string             `xml:"revision,attr"`
	When        string             `xml:"when,attr"`
	Who         string             `xml:"who,attr"`
	What        string             `xml:"what,attr"`
	Why         string             `xml:"why,attr"`
	SourceFiles []SclFileReference `xml:"SourceFiles>SclFileReference"`
}

// SclFileReference references another SCL file by UUID and/or name.
type SclFileReference struct {
	FileUUID string `xml:"fileUuid,attr"`
	FileName string `xml:"fileName,attr"`
	FileType string `xml:"fileType,attr"`
	Version  string `xml:"version,attr"`
	Revision string `xml:"revision,attr"`
	When     string `xml:"when,attr"`
}

// PSR is any element of the process sections (Substation, Line, Process,
// VoltageLevel, Bay, equipment, functions …): 9.2 is kept generically,
// with its logical node links, terminals and connectivity nodes typed.
type PSR struct {
	XMLName      xml.Name
	Name         string     `xml:"name,attr"`
	Desc         string     `xml:"desc,attr"`
	Type         string     `xml:"type,attr"`
	UUID         string     `xml:"uuid,attr"`
	TemplateUUID string     `xml:"templateUuid,attr"`
	PathName     string     `xml:"pathName,attr"`
	Phase        string     `xml:"phase,attr"`
	Virtual      string     `xml:"virtual,attr"`
	NomFreq      string     `xml:"nomFreq,attr"`
	NumPhases    string     `xml:"numPhases,attr"`
	LNodes       []LNode    `xml:"LNode"`
	Terminals    []Terminal `xml:"Terminal"`
	NeutralPoint *Terminal  `xml:"NeutralPoint"`
	Voltage      *Value     `xml:"Voltage"`
	Children     []PSR      `xml:",any"`
}

// Value is a value with unit and multiplier (Voltage, BitRate, MinTime …).
type Value struct {
	Unit       string `xml:"unit,attr"`
	Multiplier string `xml:"multiplier,attr"`
	Value      string `xml:",chardata"`
}

// LNode links a process element to a logical node (9.2.6).
type LNode struct {
	IEDName string `xml:"iedName,attr"`
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
	LNType  string `xml:"lnType,attr"`
	UUID    string `xml:"uuid,attr"`
	LNUUID  string `xml:"lnUuid,attr"`
}

// IEDNameOrNone returns the linked IED, None when not allocated.
func (l LNode) IEDNameOrNone() string {
	if l.IEDName == "" {
		return "None"
	}
	return l.IEDName
}

// Terminal connects equipment to a connectivity node.
type Terminal struct {
	Name             string `xml:"name,attr"`
	ConnectivityNode string `xml:"connectivityNode,attr"`
	ProcessName      string `xml:"processName,attr"`
	LineName         string `xml:"lineName,attr"`
	SubstationName   string `xml:"substationName,attr"`
	VoltageLevelName string `xml:"voltageLevelName,attr"`
	BayName          string `xml:"bayName,attr"`
	CNodeName        string `xml:"cNodeName,attr"`
	CNodeUUID        string `xml:"cNodeUuid,attr"`
}

// Communication is the communication section (9.4).
type Communication struct {
	SubNetworks []SubNetwork `xml:"SubNetwork"`
}

// SubNetwork is a logical bus.
type SubNetwork struct {
	Name         string        `xml:"name,attr"`
	Desc         string        `xml:"desc,attr"`
	Type         string        `xml:"type,attr"`
	UUID         string        `xml:"uuid,attr"`
	BitRate      *Value        `xml:"BitRate"`
	ConnectedAPs []ConnectedAP `xml:"ConnectedAP"`
}

// ConnectedAP is an IED access point on a subnetwork.
type ConnectedAP struct {
	IEDName   string     `xml:"iedName,attr"`
	APName    string     `xml:"apName,attr"`
	RedProt   string     `xml:"redProt,attr"`
	APUUID    string     `xml:"apUuid,attr"`
	Address   *Address   `xml:"Address"`
	GSEs      []GSE      `xml:"GSE"`
	SMVs      []GSE      `xml:"SMV"`
	PhysConns []PhysConn `xml:"PhysConn"`
}

// Address is a list of typed parameters.
type Address struct {
	Ps []P `xml:"P"`
}

// P is one address parameter.
type P struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// Get returns the (trimmed) value of the parameter type.
func (a *Address) Get(typ string) (string, bool) {
	if a == nil {
		return "", false
	}
	for _, p := range a.Ps {
		if p.Type == typ {
			return strings.TrimSpace(p.Value), true
		}
	}
	return "", false
}

// GSE is the address of a GSE (or, as SMV, a sampled value) control block.
type GSE struct {
	LDInst  string   `xml:"ldInst,attr"`
	CBName  string   `xml:"cbName,attr"`
	CBUUID  string   `xml:"cbUuid,attr"`
	Address *Address `xml:"Address"`
	MinTime *Value   `xml:"MinTime"`
	MaxTime *Value   `xml:"MaxTime"`
}

// PhysConn is a physical connection of an access point.
type PhysConn struct {
	Type string `xml:"type,attr"`
	Ps   []P    `xml:"P"`
}

// IED is an IED section (9.3).
type IED struct {
	Name               string        `xml:"name,attr"`
	Desc               string        `xml:"desc,attr"`
	Type               string        `xml:"type,attr"`
	Manufacturer       string        `xml:"manufacturer,attr"`
	ConfigVersion      string        `xml:"configVersion,attr"`
	OriginalSclVersion string        `xml:"originalSclVersion,attr"`
	OriginalSclRev     string        `xml:"originalSclRevision,attr"`
	OriginalSclRelease string        `xml:"originalSclRelease,attr"`
	EngRight           string        `xml:"engRight,attr"`
	Owner              string        `xml:"owner,attr"`
	UUID               string        `xml:"uuid,attr"`
	TemplateUUID       string        `xml:"templateUuid,attr"`
	Services           *Services     `xml:"Services"`
	AccessPoints       []AccessPoint `xml:"AccessPoint"`
	KDCs               []struct {
		IEDName string `xml:"iedName,attr"`
		APName  string `xml:"apName,attr"`
	} `xml:"KDC"`
	SourceFiles          []SclFileReference `xml:"IEDSourceFiles>SclFileReference"`
	MinRequestedSCDFiles []SclFileReference `xml:"MinRequestedSCDFiles>MinRequestedSCDFile"`
}

// Services lists service capabilities (9.3.2 Table 11). The capability
// elements are kept generically: Get("ConfReportControl").Attr("max").
type Services struct {
	NameLength string       `xml:"nameLength,attr"`
	Items      []ServiceCap `xml:",any"`
}

// ServiceCap is one capability element.
type ServiceCap struct {
	XMLName xml.Name
	Attrs   []xml.Attr   `xml:",any,attr"`
	Items   []ServiceCap `xml:",any"`
	Value   string       `xml:",chardata"`
}

// Get returns the capability element, nil when absent.
func (s *Services) Get(name string) *ServiceCap {
	if s == nil {
		return nil
	}
	for i := range s.Items {
		if s.Items[i].XMLName.Local == name {
			return &s.Items[i]
		}
	}
	return nil
}

// Get returns a sub-element.
func (c *ServiceCap) Get(name string) *ServiceCap {
	if c == nil {
		return nil
	}
	for i := range c.Items {
		if c.Items[i].XMLName.Local == name {
			return &c.Items[i]
		}
	}
	return nil
}

// Attr returns an attribute.
func (c *ServiceCap) Attr(name string) (string, bool) {
	if c == nil {
		return "", false
	}
	for _, a := range c.Attrs {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// Bool returns a boolean attribute with its default.
func (c *ServiceCap) Bool(name string, def bool) bool {
	v, ok := c.Attr(name)
	if !ok {
		return def
	}
	return parseBool(v, def)
}

// AccessPoint is an IED access point.
type AccessPoint struct {
	Name     string  `xml:"name,attr"`
	Desc     string  `xml:"desc,attr"`
	Router   string  `xml:"router,attr"`
	Clock    string  `xml:"clock,attr"`
	KDC      string  `xml:"kdc,attr"`
	UUID     string  `xml:"uuid,attr"`
	Server   *Server `xml:"Server"`
	LNs      []LN    `xml:"LN"`
	ServerAt *struct {
		APName string `xml:"apName,attr"`
	} `xml:"ServerAt"`
	Services      *Services     `xml:"Services"`
	GOOSESecurity []Certificate `xml:"GOOSESecurity"`
	SMVSecurity   []Certificate `xml:"SMVSecurity"`
}

// Certificate is a GOOSESecurity or SMVSecurity entry (IEC 62351-6).
type Certificate struct {
	Name         string `xml:"name,attr"`
	XferNumber   string `xml:"xferNumber,attr"`
	SerialNumber string `xml:"serialNumber,attr"`
	Subject      struct {
		CommonName  string `xml:"commonName,attr"`
		IDHierarchy string `xml:"idHierarchy,attr"`
	} `xml:"Subject"`
	IssuerName struct {
		CommonName  string `xml:"commonName,attr"`
		IDHierarchy string `xml:"idHierarchy,attr"`
	} `xml:"IssuerName"`
}

// Server is the IED server of an access point.
type Server struct {
	Timeout        string `xml:"timeout,attr"`
	Authentication *struct {
		None        string `xml:"none,attr"`
		Password    string `xml:"password,attr"`
		Weak        string `xml:"weak,attr"`
		Strong      string `xml:"strong,attr"`
		Certificate string `xml:"certificate,attr"`
	} `xml:"Authentication"`
	LDevices     []LDevice     `xml:"LDevice"`
	Associations []Association `xml:"Association"`
}

// Association is a pre-configured association.
type Association struct {
	APRef         string `xml:"apRef,attr"`
	Kind          string `xml:"kind,attr"`
	AssociationID string `xml:"associationID,attr"`
	Initiator     string `xml:"initiator,attr"`
	LNRef
}

// LNRef is the agLNRef attribute group.
type LNRef struct {
	IEDName string `xml:"iedName,attr"`
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
	Desc    string `xml:"desc,attr"`
	LNUUID  string `xml:"lnUuid,attr"`
}

// LDevice is a logical device.
type LDevice struct {
	Inst   string `xml:"inst,attr"`
	LDName string `xml:"ldName,attr"`
	Desc   string `xml:"desc,attr"`
	UUID   string `xml:"uuid,attr"`
	LN0    *LN    `xml:"LN0"`
	LNs    []LN   `xml:"LN"`
}

// Name returns the logical device name: ldName, else IED name + inst
// (9.3.4 Table 15).
func (ld *LDevice) Name(ied string) string {
	if ld.LDName != "" {
		return ld.LDName
	}
	return ied + ld.Inst
}

// LN is a logical node; LN0 uses the same type (lnClass LLN0, inst "").
type LN struct {
	LNClass              string                `xml:"lnClass,attr"`
	Inst                 string                `xml:"inst,attr"`
	Prefix               string                `xml:"prefix,attr"`
	LNType               string                `xml:"lnType,attr"`
	Desc                 string                `xml:"desc,attr"`
	UUID                 string                `xml:"uuid,attr"`
	DataSets             []DataSet             `xml:"DataSet"`
	ReportControls       []ReportControl       `xml:"ReportControl"`
	LogControls          []LogControl          `xml:"LogControl"`
	DOIs                 []DOI                 `xml:"DOI"`
	Inputs               *Inputs               `xml:"Inputs"`
	Outputs              *Outputs              `xml:"Outputs"`
	Logs                 []Log                 `xml:"Log"`
	GSEControls          []GSEControl          `xml:"GSEControl"`
	SampledValueControls []SampledValueControl `xml:"SampledValueControl"`
	SettingControl       *SettingControl       `xml:"SettingControl"`
}

// Name is prefix + class + inst ("LLN0" for LN0).
func (ln *LN) Name() string {
	if ln.LNClass == "LLN0" {
		return "LLN0"
	}
	return ln.Prefix + ln.LNClass + ln.Inst
}

// DataSet finds a data set of the LN.
func (ln *LN) DataSet(name string) *DataSet {
	for i := range ln.DataSets {
		if ln.DataSets[i].Name == name {
			return &ln.DataSets[i]
		}
	}
	return nil
}

// Log is a log of an LN.
type Log struct {
	Name string `xml:"name,attr"`
}

// DOI is an instantiated data object with instance values (9.3.6).
type DOI struct {
	Name          string `xml:"name,attr"`
	Desc          string `xml:"desc,attr"`
	Ix            string `xml:"ix,attr"`
	AccessControl string `xml:"accessControl,attr"`
	SDIs          []SDI  `xml:"SDI"`
	DAIs          []DAI  `xml:"DAI"`
}

// SDI is a structure name part.
type SDI struct {
	Name  string `xml:"name,attr"`
	Desc  string `xml:"desc,attr"`
	Ix    string `xml:"ix,attr"`
	SAddr string `xml:"sAddr,attr"`
	SDIs  []SDI  `xml:"SDI"`
	DAIs  []DAI  `xml:"DAI"`
}

// DAI is an attribute with instance values.
type DAI struct {
	Name      string `xml:"name,attr"`
	Desc      string `xml:"desc,attr"`
	SAddr     string `xml:"sAddr,attr"`
	ValKind   string `xml:"valKind,attr"`
	Ix        string `xml:"ix,attr"`
	ValImport string `xml:"valImport,attr"`
	Vals      []Val  `xml:"Val"`
}

// Val is a value, with its setting group when fc is SG/SE.
type Val struct {
	SGroup string `xml:"sGroup,attr"`
	Value  string `xml:",chardata"`
}

// DataSet is a data set definition (9.3.7).
type DataSet struct {
	Name  string `xml:"name,attr"`
	Desc  string `xml:"desc,attr"`
	UUID  string `xml:"uuid,attr"`
	FCDAs []FCDA `xml:"FCDA"`
}

// FCDA is a data set member.
type FCDA struct {
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
	DOName  string `xml:"doName,attr"`
	DAName  string `xml:"daName,attr"`
	FC      string `xml:"fc,attr"`
	Ix      string `xml:"ix,attr"`
	LNUUID  string `xml:"lnUuid,attr"`
}

// LNName is prefix + class + inst of the member's LN.
func (f FCDA) LNName() string {
	if f.LNClass == "LLN0" {
		return "LLN0"
	}
	return f.Prefix + f.LNClass + f.LNInst
}

// Ref is the member in dotted form LDinst/LN.DO[.DA] with the IED's name
// rules applied by the caller.
func (f FCDA) Ref() string {
	s := f.LNName() + "." + f.DOName
	if f.DAName != "" {
		s += "." + f.DAName
	}
	return s
}

// TrgOps are trigger options (9.3.8).
type TrgOps struct {
	Dchg   string `xml:"dchg,attr"`
	Qchg   string `xml:"qchg,attr"`
	Dupd   string `xml:"dupd,attr"`
	Period string `xml:"period,attr"`
	GI     string `xml:"gi,attr"`
}

// List returns the trigger options that are on, with the defaults of
// 9.3.8 (gi on, the others off); a missing element means all defaults.
func (t *TrgOps) List() []string {
	var x TrgOps
	if t != nil {
		x = *t
	}
	var out []string
	for _, o := range []struct {
		v, name string
		def     bool
	}{{x.Dchg, "dchg", false}, {x.Qchg, "qchg", false}, {x.Dupd, "dupd", false}, {x.Period, "period", false}, {x.GI, "gi", true}} {
		if parseBool(o.v, o.def) {
			out = append(out, o.name)
		}
	}
	return out
}

// OptFields are the report's optional fields.
type OptFields struct {
	SeqNum       string `xml:"seqNum,attr"`
	TimeStamp    string `xml:"timeStamp,attr"`
	DataSet      string `xml:"dataSet,attr"`
	ReasonCode   string `xml:"reasonCode,attr"`
	DataRef      string `xml:"dataRef,attr"`
	EntryID      string `xml:"entryID,attr"`
	ConfigRef    string `xml:"configRef,attr"`
	BufOvfl      string `xml:"bufOvfl,attr"`
	Segmentation string `xml:"segmentation,attr"`
}

// List returns the options that are on (bufOvfl on by default).
func (o *OptFields) List() []string {
	var x OptFields
	if o != nil {
		x = *o
	}
	var out []string
	for _, f := range []struct {
		v, name string
		def     bool
	}{{x.SeqNum, "seqNum", false}, {x.TimeStamp, "timeStamp", false}, {x.DataSet, "dataSet", false}, {x.ReasonCode, "reasonCode", false},
		{x.DataRef, "dataRef", false}, {x.EntryID, "entryID", false}, {x.ConfigRef, "configRef", false}, {x.BufOvfl, "bufOvfl", true}} {
		if parseBool(f.v, f.def) {
			out = append(out, f.name)
		}
	}
	return out
}

// ReportControl is a report control block type (9.3.8).
type ReportControl struct {
	Name       string     `xml:"name,attr"`
	Desc       string     `xml:"desc,attr"`
	DatSet     string     `xml:"datSet,attr"`
	IntgPd     string     `xml:"intgPd,attr"`
	RptID      *string    `xml:"rptID,attr"`
	ConfRev    string     `xml:"confRev,attr"`
	Buffered   string     `xml:"buffered,attr"`
	BufTime    string     `xml:"bufTime,attr"`
	Indexed    string     `xml:"indexed,attr"`
	UUID       string     `xml:"uuid,attr"`
	TrgOps     *TrgOps    `xml:"TrgOps"`
	OptFields  *OptFields `xml:"OptFields"`
	RptEnabled *struct {
		Max       string     `xml:"max,attr"`
		Desc      string     `xml:"desc,attr"`
		ClientLNs []ClientLN `xml:"ClientLN"`
	} `xml:"RptEnabled"`
}

// IsBuffered applies the default (false).
func (r *ReportControl) IsBuffered() bool { return parseBool(r.Buffered, false) }

// IsIndexed applies the default (true).
func (r *ReportControl) IsIndexed() bool { return parseBool(r.Indexed, true) }

// Max is RptEnabled max (default 1; a missing RptEnabled also gives 1).
func (r *ReportControl) Max() int {
	if r.RptEnabled == nil || r.RptEnabled.Max == "" {
		return 1
	}
	n, err := strconv.Atoi(strings.TrimSpace(r.RptEnabled.Max))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// Instances are the instance names: name01 … nameNN for indexed blocks,
// the name itself otherwise (9.3.8).
func (r *ReportControl) Instances() []string {
	if !r.IsIndexed() {
		return []string{r.Name}
	}
	n := min(r.Max(), 99)
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("%s%02d", r.Name, i))
	}
	return out
}

// ClientLN is a client of a report control block.
type ClientLN struct {
	APRef string `xml:"apRef,attr"`
	LNRef
}

// LogControl is a log control block (9.3.9).
type LogControl struct {
	Name       string  `xml:"name,attr"`
	Desc       string  `xml:"desc,attr"`
	DatSet     string  `xml:"datSet,attr"`
	IntgPd     string  `xml:"intgPd,attr"`
	LDInst     string  `xml:"ldInst,attr"`
	Prefix     string  `xml:"prefix,attr"`
	LNClass    string  `xml:"lnClass,attr"`
	LNInst     string  `xml:"lnInst,attr"`
	LogName    string  `xml:"logName,attr"`
	LogEna     string  `xml:"logEna,attr"`
	ReasonCode string  `xml:"reasonCode,attr"`
	BufTime    string  `xml:"bufTime,attr"`
	UUID       string  `xml:"uuid,attr"`
	TrgOps     *TrgOps `xml:"TrgOps"`
}

// IEDName is a subscriber of a GSE or SV control block.
type IEDName struct {
	Name    string `xml:",chardata"`
	APRef   string `xml:"apRef,attr"`
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
}

// Protocol marks a routable control block (R-GOOSE, R-SV).
type Protocol struct {
	MustUnderstand string `xml:"mustUnderstand,attr"`
	Value          string `xml:",chardata"`
}

// GSEControl is a GOOSE (or deprecated GSSE) control block (9.3.10).
type GSEControl struct {
	Name           string    `xml:"name,attr"`
	Desc           string    `xml:"desc,attr"`
	DatSet         string    `xml:"datSet,attr"`
	ConfRev        string    `xml:"confRev,attr"`
	Type           string    `xml:"type,attr"`
	AppID          string    `xml:"appID,attr"`
	FixedOffs      string    `xml:"fixedOffs,attr"`
	SecurityEnable string    `xml:"securityEnable,attr"`
	UUID           string    `xml:"uuid,attr"`
	IEDNames       []IEDName `xml:"IEDName"`
	Protocol       *Protocol `xml:"Protocol"`
}

// SampledValueControl is a sampled value control block (9.3.11).
type SampledValueControl struct {
	Name           string    `xml:"name,attr"`
	Desc           string    `xml:"desc,attr"`
	DatSet         string    `xml:"datSet,attr"`
	ConfRev        string    `xml:"confRev,attr"`
	SmvID          string    `xml:"smvID,attr"`
	Multicast      string    `xml:"multicast,attr"`
	SmpRate        string    `xml:"smpRate,attr"`
	NofASDU        string    `xml:"nofASDU,attr"`
	SmpMod         string    `xml:"smpMod,attr"`
	SecurityEnable string    `xml:"securityEnable,attr"`
	UUID           string    `xml:"uuid,attr"`
	IEDNames       []IEDName `xml:"IEDName"`
	SmvOpts        *struct {
		RefreshTime        string `xml:"refreshTime,attr"`
		SampleSynchronized string `xml:"sampleSynchronized,attr"`
		SampleRate         string `xml:"sampleRate,attr"`
		DataSet            string `xml:"dataSet,attr"`
		Security           string `xml:"security,attr"`
		Timestamp          string `xml:"timestamp,attr"`
		SynchSourceID      string `xml:"synchSourceId,attr"`
		SampleMode         string `xml:"sampleMode,attr"`
		DataRef            string `xml:"dataRef,attr"`
	} `xml:"SmvOpts"`
	Protocol *Protocol `xml:"Protocol"`
}

// SettingControl is the SGCB (9.3.12).
type SettingControl struct {
	NumOfSGs string `xml:"numOfSGs,attr"`
	ActSG    string `xml:"actSG,attr"`
	ResvTms  string `xml:"resvTms,attr"`
}

// Inputs lists external signals (9.3.13).
type Inputs struct {
	ExtRefs []ExtRef `xml:"ExtRef"`
}

// ExtRef is one external signal.
type ExtRef struct {
	Desc        string `xml:"desc,attr"`
	IEDName     string `xml:"iedName,attr"`
	LDInst      string `xml:"ldInst,attr"`
	Prefix      string `xml:"prefix,attr"`
	LNClass     string `xml:"lnClass,attr"`
	LNInst      string `xml:"lnInst,attr"`
	DOName      string `xml:"doName,attr"`
	DAName      string `xml:"daName,attr"`
	IntAddr     string `xml:"intAddr,attr"`
	ServiceType string `xml:"serviceType,attr"`
	SrcLDInst   string `xml:"srcLDInst,attr"`
	SrcPrefix   string `xml:"srcPrefix,attr"`
	SrcLNClass  string `xml:"srcLNClass,attr"`
	SrcLNInst   string `xml:"srcLNInst,attr"`
	SrcCBName   string `xml:"srcCBName,attr"`
	PLN         string `xml:"pLN,attr"`
	PDO         string `xml:"pDO,attr"`
	PDA         string `xml:"pDA,attr"`
	PServT      string `xml:"pServT,attr"`
}

// Outputs lists external controls (9.3.15).
type Outputs struct {
	ExtCtrls []struct {
		IEDName           string `xml:"iedName,attr"`
		APRef             string `xml:"apRef,attr"`
		LDInst            string `xml:"ldInst,attr"`
		Prefix            string `xml:"prefix,attr"`
		LNClass           string `xml:"lnClass,attr"`
		LNInst            string `xml:"lnInst,attr"`
		DOName            string `xml:"doName,attr"`
		IntAddr           string `xml:"intAddr,attr"`
		CheckInterlock    string `xml:"checkInterlock,attr"`
		CheckSynchrocheck string `xml:"checkSynchrocheck,attr"`
	} `xml:"ExtCtrl"`
}

// DataTypeTemplates is the type section (9.5).
type DataTypeTemplates struct {
	LNodeTypes []LNodeType `xml:"LNodeType"`
	DOTypes    []DOType    `xml:"DOType"`
	DATypes    []DAType    `xml:"DAType"`
	EnumTypes  []EnumType  `xml:"EnumType"`
}

// LNodeType is an instantiable LN type.
type LNodeType struct {
	ID      string `xml:"id,attr"`
	Desc    string `xml:"desc,attr"`
	IEDType string `xml:"iedType,attr"`
	LNClass string `xml:"lnClass,attr"`
	DOs     []DO   `xml:"DO"`
}

// DO is a data object of an LN type.
type DO struct {
	Name          string `xml:"name,attr"`
	Type          string `xml:"type,attr"`
	AccessControl string `xml:"accessControl,attr"`
	Transient     string `xml:"transient,attr"`
}

// DOType is an instantiable data object type; Items keeps SDO and DA in
// their order, which is the order of values in messages (9.5.1).
type DOType struct {
	ID      string     `xml:"id,attr"`
	Desc    string     `xml:"desc,attr"`
	IEDType string     `xml:"iedType,attr"`
	CDC     string     `xml:"cdc,attr"`
	Items   []TypeItem `xml:",any"`
}

// DAType is a structured attribute type.
type DAType struct {
	ID      string     `xml:"id,attr"`
	Desc    string     `xml:"desc,attr"`
	IEDType string     `xml:"iedType,attr"`
	Items   []TypeItem `xml:",any"`
}

// TypeItem is an SDO, DA or BDA (Kind is the element name); ProtNs,
// Labels, Text and Private children of a type are also listed and have
// to be skipped by Kind.
type TypeItem struct {
	XMLName   xml.Name
	Name      string `xml:"name,attr"`
	Desc      string `xml:"desc,attr"`
	Type      string `xml:"type,attr"`
	Count     string `xml:"count,attr"`
	FC        string `xml:"fc,attr"`
	BType     string `xml:"bType,attr"`
	Dchg      string `xml:"dchg,attr"`
	Qchg      string `xml:"qchg,attr"`
	Dupd      string `xml:"dupd,attr"`
	ValKind   string `xml:"valKind,attr"`
	ValImport string `xml:"valImport,attr"`
	SAddr     string `xml:"sAddr,attr"`
	Vals      []Val  `xml:"Val"`
	Value     string `xml:",chardata"`
}

// Kind is SDO, DA or BDA.
func (t TypeItem) Kind() string { return t.XMLName.Local }

// Members returns the SDO/DA (or BDA) items in order.
func (t *DOType) Members() []TypeItem { return members(t.Items) }

// Members returns the BDA items in order.
func (t *DAType) Members() []TypeItem { return members(t.Items) }

func members(items []TypeItem) []TypeItem {
	var out []TypeItem
	for _, it := range items {
		switch it.Kind() {
		case "SDO", "DA", "BDA":
			out = append(out, it)
		}
	}
	return out
}

// EnumType is an enumeration.
type EnumType struct {
	ID       string    `xml:"id,attr"`
	Desc     string    `xml:"desc,attr"`
	EnumVals []EnumVal `xml:"EnumVal"`
}

// EnumVal is one literal.
type EnumVal struct {
	Ord   string `xml:"ord,attr"`
	Desc  string `xml:"desc,attr"`
	Value string `xml:",chardata"`
}

func parseBool(s string, def bool) bool {
	switch strings.TrimSpace(s) {
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	return def
}

// Templates is an index of the DataTypeTemplates by id.
type Templates struct {
	LNodeTypes map[string]*LNodeType
	DOTypes    map[string]*DOType
	DATypes    map[string]*DAType
	EnumTypes  map[string]*EnumType
}

// Index builds the id maps (the first definition of a duplicate id wins;
// Validate reports duplicates).
func (d *DataTypeTemplates) Index() *Templates {
	t := &Templates{LNodeTypes: map[string]*LNodeType{}, DOTypes: map[string]*DOType{}, DATypes: map[string]*DAType{}, EnumTypes: map[string]*EnumType{}}
	if d == nil {
		return t
	}
	for i := range d.LNodeTypes {
		if _, ok := t.LNodeTypes[d.LNodeTypes[i].ID]; !ok {
			t.LNodeTypes[d.LNodeTypes[i].ID] = &d.LNodeTypes[i]
		}
	}
	for i := range d.DOTypes {
		if _, ok := t.DOTypes[d.DOTypes[i].ID]; !ok {
			t.DOTypes[d.DOTypes[i].ID] = &d.DOTypes[i]
		}
	}
	for i := range d.DATypes {
		if _, ok := t.DATypes[d.DATypes[i].ID]; !ok {
			t.DATypes[d.DATypes[i].ID] = &d.DATypes[i]
		}
	}
	for i := range d.EnumTypes {
		if _, ok := t.EnumTypes[d.EnumTypes[i].ID]; !ok {
			t.EnumTypes[d.EnumTypes[i].ID] = &d.EnumTypes[i]
		}
	}
	return t
}
