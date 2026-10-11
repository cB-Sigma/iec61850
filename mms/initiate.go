package mms

import (
	"errors"
	"fmt"
)

// The Initiate service (ISO 9506-2:2003 8.2, ISO 9506-1:2003 8.2) and the
// two conformance bit strings it negotiates (ISO 9506-1:2003 8.1.3.14,
// 8.1.3.15).

// Sizes of the conformance bit strings: ServiceSupportOptions is SIZE(93),
// ParameterSupportOptions SIZE(18). Every bit is encoded; bits a peer sends
// beyond these are ignored, and bits it leaves out read as not supported
// (ISO 9506-1:2003 8.2.1.1.6, 8.2.1.1.8; findings F-690).
const (
	NumServiceBits   = 93
	NumParameterBits = 18
)

// Parameter CBB bit positions (ParameterSupportOptions; bits 8 and 9 are
// reserved).
const (
	CBBStr1  = 0
	CBBStr2  = 1
	CBBVnam  = 2
	CBBValt  = 3
	CBBVadr  = 4
	CBBVsca  = 5
	CBBTpy   = 6
	CBBVlis  = 7
	CBBCei   = 10
	CBBAco   = 11
	CBBSem   = 12
	CBBCsr   = 13
	CBBCsnc  = 14
	CBBCsplc = 15
	CBBCspi  = 16
	CBBChar  = 17
)

// Service bit positions of the services that are not confirmed services.
// A confirmed service's bit is its ConfirmedServiceRequest tag number
// (status 0 to fileDirectory 77), so the Svc constants double as bits.
const (
	BitUnsolicitedStatus    = 78
	BitInformationReport    = 79
	BitEventNotification    = 80
	BitAttachToEventCond    = 81
	BitAttachToSemaphore    = 82
	BitConclude             = 83
	BitCancel               = 84
	BitGetDataExchangeAttrs = 85
)

// MinorVersion is the MMS minor version we propose and accept. The 2003
// edition is minor version 4 (ISO 9506-2:2003 24.11); we implement no
// service or parameter that minor versions 2 to 4 added, and IEC 61850-8-1
// peers propose 1, so 1 is proposed and a higher proposal is answered
// with 1 (ISO 9506-1:2003 8.2.1.1.5, 8.2.1.2.5).
const MinorVersion = 1

// Initiate is the content of an initiate-RequestPDU or -ResponsePDU.
type Initiate struct {
	// LocalDetail is the largest MMS PDU the sender accepts, in octets
	// (0 when absent).
	LocalDetail int
	// MaxServOutstandingCalling and Called are the proposed or negotiated
	// numbers of outstanding confirmed requests at each side.
	MaxServOutstandingCalling int
	MaxServOutstandingCalled  int
	// NestingLevel is the data structure nesting level; -1 when absent
	// (unlimited).
	NestingLevel int
	Version      int
	ParameterCBB BitString
	Services     BitString
}

// Encode encodes the PDU with its MMSpdu tag (TagInitiateRequest or
// TagInitiateResponse).
func (i Initiate) Encode(tag byte) []byte {
	var parts [][]byte
	if i.LocalDetail > 0 {
		parts = append(parts, Int(0x80, int64(i.LocalDetail)))
	}
	parts = append(parts, Int(0x81, int64(i.MaxServOutstandingCalling)), Int(0x82, int64(i.MaxServOutstandingCalled)))
	if i.NestingLevel >= 0 {
		parts = append(parts, Int(0x83, int64(i.NestingLevel)))
	}
	parts = append(parts, T(0xa4, Int(0x80, int64(i.Version)),
		T(0x81, fixed(i.ParameterCBB, NumParameterBits).Contents()),
		T(0x82, fixed(i.Services, NumServiceBits).Contents())))
	return T(tag, parts...)
}

// fixed returns b resized to n bits (missing bits clear, extra bits
// dropped).
func fixed(b BitString, n int) BitString {
	out := NewBitString(n)
	for i := 0; i < n; i++ {
		out.Set(i, b.Get(i))
	}
	return out
}

// DecodeInitiate decodes an initiate-RequestPDU or -ResponsePDU. Unknown
// elements are ignored (ISO 9506-2:2003 8.2).
func DecodeInitiate(e Elem) (Initiate, error) {
	kids, err := e.Children()
	if err != nil {
		return Initiate{}, err
	}
	i := Initiate{NestingLevel: -1}
	seen := 0
	for _, k := range kids {
		switch {
		case k.Tag == 0x80:
			v, _ := DecodeInt(k.Val)
			i.LocalDetail = int(v)
		case k.Tag == 0x81:
			v, err := DecodeInt(k.Val)
			if err != nil {
				return Initiate{}, err
			}
			i.MaxServOutstandingCalling = int(v)
			seen |= 1
		case k.Tag == 0x82:
			v, err := DecodeInt(k.Val)
			if err != nil {
				return Initiate{}, err
			}
			i.MaxServOutstandingCalled = int(v)
			seen |= 2
		case k.Tag == 0x83:
			v, _ := DecodeInt(k.Val)
			i.NestingLevel = int(v)
		case k.Tag == 0xa4:
			det, err := k.Children()
			if err != nil {
				return Initiate{}, err
			}
			for _, d := range det {
				switch d.Tag {
				case 0x80:
					v, _ := DecodeInt(d.Val)
					i.Version = int(v)
					seen |= 4
				case 0x81:
					if i.ParameterCBB, err = DecodeBitString(d.Val); err != nil {
						return Initiate{}, err
					}
					seen |= 8
				case 0x82:
					if i.Services, err = DecodeBitString(d.Val); err != nil {
						return Initiate{}, err
					}
					seen |= 16
				}
			}
		}
	}
	if seen != 31 {
		return Initiate{}, errors.New("mms: an initiate PDU without its mandatory parameters")
	}
	return i, nil
}

// Supports reports whether the negotiated services include bit n.
func (i Initiate) Supports(n int) bool { return i.Services.Get(n) }

// Capabilities are what a local MMS user implements, used to build its
// initiate request or to answer a peer's.
type Capabilities struct {
	MaxPDU         int
	MaxOutstanding int
	Nesting        int
	Parameters     []int // parameter CBB bits
	Services       []int // service bits
}

func bits(n int, set []int) BitString {
	b := NewBitString(n)
	for _, i := range set {
		b.Set(i, true)
	}
	return b
}

// Request is the initiate request of a calling user with these
// capabilities.
func (c Capabilities) Request() Initiate {
	return Initiate{LocalDetail: c.MaxPDU, MaxServOutstandingCalling: c.MaxOutstanding, MaxServOutstandingCalled: c.MaxOutstanding,
		NestingLevel: c.Nesting, Version: MinorVersion, ParameterCBB: bits(NumParameterBits, c.Parameters),
		Services: bits(NumServiceBits, c.Services)}
}

// Respond negotiates a peer's initiate request (ISO 9506-1:2003 8.2.1.2):
// the outstanding counts and nesting level are at most those proposed, the
// version at most the proposed one and not below 1, the parameter CBBs the
// intersection of the proposed ones and ours, the services ours.
func (c Capabilities) Respond(req Initiate) (Initiate, error) {
	if req.Version < 1 || req.MaxServOutstandingCalling < 1 || req.MaxServOutstandingCalled < 1 {
		return Initiate{}, fmt.Errorf("mms: an initiate request with version %d and outstanding counts %d, %d",
			req.Version, req.MaxServOutstandingCalling, req.MaxServOutstandingCalled)
	}
	r := Initiate{LocalDetail: c.MaxPDU, Version: min(req.Version, MinorVersion),
		MaxServOutstandingCalling: min(req.MaxServOutstandingCalling, c.MaxOutstanding),
		MaxServOutstandingCalled:  min(req.MaxServOutstandingCalled, c.MaxOutstanding),
		NestingLevel:              c.Nesting, Services: bits(NumServiceBits, c.Services), ParameterCBB: NewBitString(NumParameterBits)}
	if req.NestingLevel >= 0 && req.NestingLevel < r.NestingLevel {
		r.NestingLevel = req.NestingLevel
	}
	for _, p := range c.Parameters {
		r.ParameterCBB.Set(p, req.ParameterCBB.Get(p))
	}
	return r, nil
}

// InitiateResponseTo answers an initiate-RequestPDU (the Association's
// Initiate) for a server with capabilities c: an initiate-ResponsePDU, or
// an initiate-ErrorPDU (class initiate, code other) when the request
// cannot be read. ok is false for the error.
func InitiateResponseTo(reqPDU []byte, c Capabilities) (resp []byte, ok bool) {
	e, _, err := Parse(reqPDU)
	if err == nil && e.Tag != TagInitiateRequest {
		err = errors.New("mms: not an initiate request")
	}
	var req Initiate
	if err == nil {
		req, err = DecodeInitiate(e)
	}
	var r Initiate
	if err == nil {
		r, err = c.Respond(req)
	}
	if err != nil {
		return T(TagInitiateError, ServiceError{Class: ClassInitiate, Code: 0}.contents()...), false
	}
	return r.Encode(TagInitiateResponse), true
}

// ClientCapabilities are the capabilities of our MMS client: the services
// it calls or receives (the event management services are those of
// eventsvc.go) and the parameter CBBs of the variable access it uses.
var ClientCapabilities = Capabilities{MaxPDU: 65000, MaxOutstanding: 5, Nesting: 10,
	Parameters: []int{CBBStr1, CBBStr2, CBBVnam, CBBValt, CBBVlis, CBBCei},
	Services: []int{SvcStatus, SvcGetNameList, SvcIdentify, SvcRead, SvcWrite, SvcGetVariableAccessAttributes,
		SvcDefineNamedVariableList, SvcGetNamedVariableListAttributes, SvcDeleteNamedVariableList,
		SvcDefineEventCondition, SvcDeleteEventCondition, SvcGetEventConditionAttributes, SvcReportEventConditionStatus,
		SvcAlterEventConditionMonitoring, SvcTriggerEvent, SvcDefineEventAction, SvcDeleteEventAction,
		SvcGetEventActionAttributes, SvcReportEventActionStatus, SvcDefineEventEnrollment, SvcDeleteEventEnrollment,
		SvcAlterEventEnrollment, SvcReportEventEnrollmentStatus, SvcGetEventEnrollmentAttributes,
		SvcAcknowledgeEventNotification, SvcGetAlarmSummary, SvcGetAlarmEnrollmentSummary,
		SvcReadJournal, SvcObtainFile, SvcFileOpen, SvcFileRead, SvcFileClose, SvcFileDelete, SvcFileDirectory,
		BitInformationReport, BitEventNotification, BitConclude}}

// BasicServerCapabilities are those of a server offering only variable
// access by name and named variable lists, without alternate access (the
// set the IEC 61850 simulator implements; servers that implement more
// list more).
var BasicServerCapabilities = Capabilities{MaxPDU: 65000, MaxOutstanding: 5, Nesting: 10,
	Parameters: []int{CBBStr1, CBBStr2, CBBVnam, CBBVlis},
	Services: []int{SvcGetNameList, SvcRead, SvcWrite, SvcGetVariableAccessAttributes,
		SvcDefineNamedVariableList, SvcGetNamedVariableListAttributes, SvcDeleteNamedVariableList,
		BitInformationReport, BitConclude}}

// InitiateRequest is the initiate-RequestPDU our client sends.
func InitiateRequest() []byte { return ClientCapabilities.Request().Encode(TagInitiateRequest) }

// InitiateResponse answers our own client's initiate request with the
// basic server capabilities (kept for servers that do not read the
// request; servers use InitiateResponseTo).
func InitiateResponse() []byte {
	r, _ := BasicServerCapabilities.Respond(ClientCapabilities.Request())
	return r.Encode(TagInitiateResponse)
}
