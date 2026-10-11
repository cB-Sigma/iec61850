package mms

import (
	"errors"
	"fmt"
)

// MMS PDU tags (ISO 9506-2, MMSpdu).
const (
	TagConfirmedRequest  = 0xa0
	TagConfirmedResponse = 0xa1
	TagConfirmedError    = 0xa2
	TagUnconfirmed       = 0xa3
	TagReject            = 0xa4
	TagInitiateRequest   = 0xa8
	TagInitiateResponse  = 0xa9
	TagInitiateError     = 0xaa
	TagConcludeRequest   = 0x8b
	TagConcludeResponse  = 0x8c
	TagConcludeError     = 0xac // conclude-ErrorPDU [12] ServiceError
)

// Conclude error codes (ISO 9506-2:2003 7.4.1, class conclude).
const (
	ConcludeOther                   = 0
	ConcludeFurtherCommunicationReq = 1
)

// ConcludeErrorPDU refuses a Conclude (ISO 9506-1:2003 8.4): the
// association continues.
func ConcludeErrorPDU(code int) []byte {
	return T(TagConcludeError, ServiceError{Class: ClassConclude, Code: code}.contents()...)
}

// Confirmed service numbers: the context tags of ConfirmedServiceRequest
// and ConfirmedServiceResponse (ISO 9506-2:2003 7.1.1, 7.3.1), which are
// also the service bits of ServiceSupportOptions (ISO 9506-1:2003
// 8.1.3.14). Tags from 31 up use the high-tag-number form (TH).
const (
	SvcStatus                         = 0
	SvcGetNameList                    = 1
	SvcIdentify                       = 2
	SvcRead                           = 4
	SvcWrite                          = 5
	SvcGetVariableAccessAttributes    = 6
	SvcGetNamedVariableListAttributes = 12
	SvcObtainFile                     = 46
	SvcDefineEventCondition           = 47
	SvcDeleteEventCondition           = 48
	SvcGetEventConditionAttributes    = 49
	SvcReportEventConditionStatus     = 50
	SvcAlterEventConditionMonitoring  = 51
	SvcTriggerEvent                   = 52
	SvcDefineEventAction              = 53
	SvcDeleteEventAction              = 54
	SvcGetEventActionAttributes       = 55
	SvcReportEventActionStatus        = 56
	SvcDefineEventEnrollment          = 57
	SvcDeleteEventEnrollment          = 58
	SvcAlterEventEnrollment           = 59
	SvcReportEventEnrollmentStatus    = 60
	SvcGetEventEnrollmentAttributes   = 61
	SvcAcknowledgeEventNotification   = 62
	SvcGetAlarmSummary                = 63
	SvcGetAlarmEnrollmentSummary      = 64
	SvcReadJournal                    = 65
	SvcFileOpen                       = 72
	SvcFileDirectory                  = 77
)

// Unconfirmed service numbers (UnconfirmedService, ISO 9506-2:2003 7.2.1).
const (
	UsvcInformationReport = 0
	UsvcUnsolicitedStatus = 1
	UsvcEventNotification = 2
)

// Basic object classes of GetNameList (ObjectClass, ISO 9506-1:2003 9.1).
const (
	ClassNamedVariable     = 0
	ClassNamedVariableList = 2
	ClassNamedType         = 3
	ClassEventCondition    = 5
	ClassEventAction       = 6
	ClassEventEnrollment   = 7
	ClassJournal           = 8
	ClassDomain            = 9
)

// Scope of an object name.
type Scope int

const (
	ScopeVMD Scope = iota
	ScopeDomain
	ScopeAA
)

// ObjectName names an MMS object.
type ObjectName struct {
	Scope  Scope
	Domain string
	Item   string
}

// DomainName is a domain-specific name.
func DomainName(domain, item string) ObjectName {
	return ObjectName{Scope: ScopeDomain, Domain: domain, Item: item}
}

// VMDName is a VMD-specific name.
func VMDName(item string) ObjectName { return ObjectName{Scope: ScopeVMD, Item: item} }

// String names the value.
func (n ObjectName) String() string {
	if n.Scope == ScopeDomain {
		return n.Domain + "/" + n.Item
	}
	return n.Item
}

// Encode encodes the ObjectName CHOICE.
func (n ObjectName) Encode() []byte {
	switch n.Scope {
	case ScopeDomain:
		return T(0xa1, Str(0x1a, n.Domain), Str(0x1a, n.Item))
	case ScopeAA:
		return Str(0x82, n.Item)
	default:
		return Str(0x80, n.Item)
	}
}

// DecodeObjectName decodes the ObjectName CHOICE.
func DecodeObjectName(e Elem) (ObjectName, error) {
	switch {
	case e.Tag == 0x80:
		return VMDName(string(e.Val)), nil
	case e.Tag == 0x82:
		return ObjectName{Scope: ScopeAA, Item: string(e.Val)}, nil
	case e.Tag == 0xa1:
		kids, err := e.Children()
		if err != nil || len(kids) != 2 {
			return ObjectName{}, errors.New("mms: a bad domain-specific name")
		}
		return DomainName(string(kids[0].Val), string(kids[1].Val)), nil
	}
	return ObjectName{}, fmt.Errorf("mms: object name with tag %#x", e.Tag)
}

// DataAccessError is an MMS DataAccessError.
type DataAccessError int

// DataAccessError values.
const (
	ErrObjectInvalidated     DataAccessError = 0
	ErrHardwareFault         DataAccessError = 1
	ErrTemporarilyUnavail    DataAccessError = 2
	ErrObjectAccessDenied    DataAccessError = 3
	ErrObjectUndefined       DataAccessError = 4
	ErrInvalidAddress        DataAccessError = 5
	ErrTypeUnsupported       DataAccessError = 6
	ErrTypeInconsistent      DataAccessError = 7
	ErrObjectAttrInconsist   DataAccessError = 8
	ErrObjectAccessUnsupport DataAccessError = 9
	ErrObjectNonExistent     DataAccessError = 10
	ErrObjectValueInvalid    DataAccessError = 11
)

var dataAccessNames = map[DataAccessError]string{
	0: "object invalidated", 1: "hardware fault", 2: "temporarily unavailable", 3: "object access denied",
	4: "object undefined", 5: "invalid address", 6: "type unsupported", 7: "type inconsistent",
	8: "object attribute inconsistent", 9: "object access unsupported", 10: "object non-existent",
	11: "object value invalid",
}

// Error describes the failure.
func (e DataAccessError) Error() string {
	if s, ok := dataAccessNames[e]; ok {
		return "MMS data access error: " + s
	}
	return fmt.Sprintf("MMS data access error %d", int(e))
}

// AccessResult is a Read or InformationReport result: data or a failure.
type AccessResult struct {
	Data Data
	Err  error // a DataAccessError, or nil
}

// EncodeAccessResult encodes an AccessResult.
func EncodeAccessResult(r AccessResult) []byte {
	var dae DataAccessError
	if errors.As(r.Err, &dae) {
		return Int(0x80, int64(dae))
	}
	if r.Err != nil {
		return Int(0x80, int64(ErrObjectAccessDenied))
	}
	return r.Data.Encode()
}

// DecodeAccessResults decodes a list of AccessResult elements.
func DecodeAccessResults(b []byte) ([]AccessResult, error) {
	kids, err := ParseAll(b)
	if err != nil {
		return nil, err
	}
	out := make([]AccessResult, len(kids))
	for i, k := range kids {
		if k.Tag == 0x80 {
			v, _ := DecodeInt(k.Val)
			out[i].Err = DataAccessError(v)
			continue
		}
		if out[i].Data, err = DecodeData(k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// VariableSpec is a VariableAccessSpecification: a list of named variables
// (each with an optional alternate access, Alt[i], when Alt is not nil) or
// the name of a named variable list (ISO 9506-2:2003 14.5.1).
type VariableSpec struct {
	Vars     []ObjectName
	Alt      []AlternateAccess
	ListName *ObjectName
}

// AltOf is the alternate access of variable i (nil when none).
func (v VariableSpec) AltOf(i int) AlternateAccess {
	if i < len(v.Alt) {
		return v.Alt[i]
	}
	return nil
}

// Encode encodes the VariableAccessSpecification CHOICE: listOfVariable [0]
// of SEQUENCE { variableSpecification (name [0]), alternateAccess [5]
// OPTIONAL }, or variableListName [1].
func (v VariableSpec) Encode() []byte {
	if v.ListName != nil {
		return T(0xa1, v.ListName.Encode())
	}
	items := make([][]byte, len(v.Vars))
	for i, n := range v.Vars {
		if a := v.AltOf(i); len(a) > 0 {
			items[i] = T(0x30, T(0xa0, n.Encode()), T(0xa5, a.elements()...))
			continue
		}
		items[i] = T(0x30, T(0xa0, n.Encode()))
	}
	return T(0xa0, items...)
}

// DecodeVariableSpec decodes a VariableAccessSpecification. Only named
// variables are accepted (the vadr and vsca CBBs are not offered).
func DecodeVariableSpec(e Elem) (VariableSpec, error) {
	switch e.Tag {
	case 0xa1:
		in, _, err := Parse(e.Val)
		if err != nil {
			return VariableSpec{}, err
		}
		n, err := DecodeObjectName(in)
		return VariableSpec{ListName: &n}, err
	case 0xa0:
		kids, err := e.Children()
		if err != nil {
			return VariableSpec{}, err
		}
		var out VariableSpec
		for i, k := range kids {
			parts, err := k.Children()
			if err != nil || k.Tag != 0x30 || len(parts) == 0 || parts[0].Tag != 0xa0 {
				return VariableSpec{}, errors.New("mms: a variable specification that is not a name")
			}
			in, _, err := Parse(parts[0].Val)
			if err != nil {
				return VariableSpec{}, err
			}
			n, err := DecodeObjectName(in)
			if err != nil {
				return VariableSpec{}, err
			}
			out.Vars = append(out.Vars, n)
			for _, p := range parts[1:] {
				if p.Tag != 0xa5 {
					continue
				}
				a, err := DecodeAlternateAccess(p.Val)
				if err != nil {
					return VariableSpec{}, err
				}
				if out.Alt == nil {
					out.Alt = make([]AlternateAccess, len(kids))
				}
				out.Alt[i] = a
			}
		}
		return out, nil
	}
	return VariableSpec{}, fmt.Errorf("mms: variable access specification with tag %#x", e.Tag)
}

// Error classes of ServiceError (ISO 9506-2:2003 7.4.1).
const (
	ClassVMDState       = 0
	ClassApplicationRef = 1
	ClassDefinition     = 2
	ClassResource       = 3
	ClassService        = 4
	ClassServicePreempt = 5
	ClassTimeResolution = 6
	ClassAccess         = 7
	ClassInitiate       = 8
	ClassConclude       = 9
	ClassCancel         = 10
	ClassFile           = 11
	ClassOthers         = 12
)

// Common error codes (ISO 9506-2:2003 7.4.1).
const (
	CodeOther                  = 0
	CodeDefObjectUndefined     = 1 // definition
	CodeDefInvalidAddress      = 2 // definition
	CodeDefTypeUnsupported     = 3 // definition
	CodeDefTypeInconsistent    = 4 // definition
	CodeDefObjectExists        = 5 // definition
	CodeDefAttrInconsistent    = 6 // definition
	CodeResMemoryUnavailable   = 1 // resource
	CodeResCapabilityUnavail   = 4 // resource
	CodeSvcObjectStateConflict = 2 // service
	CodeSvcObjectConstraint    = 5 // service
	CodeAccUnsupported         = 1 // access
	CodeAccNonExistent         = 2 // access
	CodeAccDenied              = 3 // access
	CodeAccInvalidated         = 4 // access
)

// ServiceError is a ServiceError: the error class and code, an optional
// additional code and description, and the service-specific information
// (the serviceSpecificInfo alternative, encoded; nil when absent).
type ServiceError struct {
	Class, Code    int
	AdditionalCode *int64
	Description    string
	Specific       []byte
}

var errorClasses = []string{"vmd-state", "application-reference", "definition", "resource", "service",
	"service-preempt", "time-resolution", "access", "initiate", "conclude", "cancel", "file", "others"}

// Error describes the failure.
func (e ServiceError) Error() string {
	name := fmt.Sprint(e.Class)
	if e.Class >= 0 && e.Class < len(errorClasses) {
		name = errorClasses[e.Class]
	}
	s := fmt.Sprintf("MMS service error: class %s, code %d", name, e.Code)
	if e.Description != "" {
		s += ": " + e.Description
	}
	return s
}

// contents is the ServiceError SEQUENCE's elements.
func (e ServiceError) contents() [][]byte {
	parts := [][]byte{T(0xa0, Int(0x80|byte(e.Class), int64(e.Code)))}
	if e.AdditionalCode != nil {
		parts = append(parts, Int(0x81, *e.AdditionalCode))
	}
	if e.Description != "" {
		parts = append(parts, Str(0x82, e.Description))
	}
	if e.Specific != nil {
		parts = append(parts, T(0xa3, e.Specific))
	}
	return parts
}

// DecodeServiceError decodes a ServiceError's contents.
func DecodeServiceError(b []byte) (ServiceError, error) {
	kids, err := ParseAll(b)
	if err != nil {
		return ServiceError{}, err
	}
	se := ServiceError{Class: -1}
	for _, k := range kids {
		switch {
		case k.Context(0):
			in, _, err := Parse(k.Val)
			if err != nil {
				return ServiceError{}, err
			}
			v, _ := DecodeInt(in.Val)
			se.Class, se.Code = in.Num, int(v)
		case k.Context(1):
			v, err := DecodeInt(k.Val)
			if err == nil {
				se.AdditionalCode = &v
			}
		case k.Context(2):
			se.Description = string(k.Val)
		case k.Context(3):
			se.Specific = append([]byte(nil), k.Val...)
		}
	}
	if se.Class < 0 {
		return se, errors.New("mms: a service error without its class")
	}
	return se, nil
}

// PDU types named by a RejectPDU's rejectReason (ISO 9506-2:2003 8.6).
const (
	RejectConfirmedRequest  = 1
	RejectConfirmedResponse = 2
	RejectConfirmedError    = 3
	RejectUnconfirmed       = 4
	RejectPDUError          = 5
	RejectCancelRequest     = 6
	RejectCancelResponse    = 7
	RejectCancelError       = 8
	RejectConcludeRequest   = 9
	RejectConcludeResponse  = 10
	RejectConcludeError     = 11
)

// Reject codes of a confirmed-requestPDU reason.
const (
	RejectOther                  = 0
	RejectUnrecognizedService    = 1
	RejectUnrecognizedModifier   = 2
	RejectInvalidInvokeID        = 3
	RejectInvalidArgument        = 4
	RejectInvalidModifier        = 5
	RejectMaxServOutstanding     = 6
	RejectMaxRecursion           = 8
	RejectValueOutOfRange        = 9
	RejectPDUUnknownType         = 0 // pdu-error
	RejectPDUInvalid             = 1 // pdu-error
	RejectPDUIllegalACSEMapping  = 2 // pdu-error
	RejectResponseInvalidResult  = 3 // confirmed-responsePDU
	RejectErrorInvalidServiceErr = 3 // confirmed-errorPDU
)

// RejectError is a received RejectPDU: the PDU type rejected and the
// reason code within it.
type RejectError struct {
	PDU, Code int
	Reason    string
}

// Error describes the failure.
func (e *RejectError) Error() string {
	if e.Reason != "" {
		return "MMS reject: " + e.Reason
	}
	return fmt.Sprintf("MMS reject: PDU type %d, reason %d", e.PDU, e.Code)
}

// DecodeReject decodes a RejectPDU's contents.
func DecodeReject(e Elem) (invoke uint32, hasInvoke bool, r *RejectError) {
	r = &RejectError{PDU: -1}
	kids, _ := e.Children()
	for _, k := range kids {
		switch {
		case k.Context(0):
			v, _ := DecodeUint(k.Val)
			invoke, hasInvoke = uint32(v), true
		case k.Tag&0xc0 == 0x80 && k.Num >= 1 && k.Num <= 11:
			v, _ := DecodeInt(k.Val)
			r.PDU, r.Code = k.Num, int(v)
		}
	}
	return invoke, hasInvoke, r
}

// ---- request encoders ---------------------------------------------------------

// ConfirmedRequest wraps a service request with its invoke ID.
func ConfirmedRequest(invoke uint32, service []byte) []byte {
	return T(TagConfirmedRequest, Uint(0x02, uint64(invoke)), service)
}

// GetNameListRequest asks for names of a class, in a domain or the VMD.
func GetNameListRequest(class int, domain, continueAfter string) []byte {
	scope := T(0x80) // vmdSpecific NULL
	if domain != "" {
		scope = Str(0x81, domain)
	}
	parts := [][]byte{T(0xa0, Int(0x80, int64(class))), T(0xa1, scope)}
	if continueAfter != "" {
		parts = append(parts, Str(0x82, continueAfter))
	}
	return T(0xa0|SvcGetNameList, parts...)
}

// ReadRequest reads variables.
func ReadRequest(spec VariableSpec) []byte {
	return T(0xa0|SvcRead, T(0xa1, spec.Encode()))
}

// ReadRequestWithSpec reads variables and asks for the specification to be
// returned with the results (specificationWithResult true).
func ReadRequestWithSpec(spec VariableSpec) []byte {
	return T(0xa0|SvcRead, Bool(0x80, true), T(0xa1, spec.Encode()))
}

// IdentifyRequest is the Identify request (NULL).
func IdentifyRequest() []byte { return T(0x80 | SvcIdentify) }

// StatusRequest is the Status request; extended asks the server to derive
// the status afresh rather than report it as known.
func StatusRequest(extended bool) []byte { return Bool(0x80|SvcStatus, extended) }

// WriteRequest writes variables.
func WriteRequest(spec VariableSpec, values []Data) []byte {
	data := make([][]byte, len(values))
	for i, v := range values {
		data[i] = v.Encode()
	}
	return T(0xa0|SvcWrite, spec.Encode(), T(0xa0, data...))
}

// GetVariableAccessAttributesRequest asks for a variable's type.
func GetVariableAccessAttributesRequest(n ObjectName) []byte {
	return T(0xa0|SvcGetVariableAccessAttributes, T(0xa0, n.Encode()))
}

// GetNamedVariableListAttributesRequest asks for a data set's members.
func GetNamedVariableListAttributesRequest(n ObjectName) []byte {
	return T(0xa0|SvcGetNamedVariableListAttributes, n.Encode())
}

// ---- server-side decoding and response encoders -----------------------------

// Request is a decoded confirmed request.
type Request struct {
	InvokeID uint32
	Service  int
	Body     Elem
	// Modifiers reports a listOfModifiers, which no server of ours
	// supports (attachToEventCondition and attachToSemaphore are not
	// offered).
	Modifiers bool
}

// DecodeConfirmedRequest decodes a confirmed-RequestPDU's contents.
func DecodeConfirmedRequest(e Elem) (Request, error) {
	kids, err := e.Children()
	if err != nil || len(kids) < 2 {
		return Request{}, errors.New("mms: a bad confirmed request")
	}
	id, err := DecodeUint(kids[0].Val)
	if err != nil {
		return Request{}, err
	}
	// invokeID, then listOfModifiers (a SEQUENCE OF) when present, then
	// the service; a service-ext [79] may follow (ISO 9506-2:2003 7.1).
	i := 1
	if kids[i].Tag == 0x30 {
		i++
		if i >= len(kids) {
			return Request{}, errors.New("mms: a confirmed request without its service")
		}
	}
	svc := kids[i]
	if svc.Tag&0xc0 != 0x80 {
		return Request{}, errors.New("mms: a confirmed request whose service is not context-tagged")
	}
	return Request{InvokeID: uint32(id), Service: svc.Num, Body: svc, Modifiers: i == 2}, nil
}

// GetNameListArgs decodes a GetNameList request (an aaSpecific scope reads
// as the VMD; GetNameListScope tells them apart).
func GetNameListArgs(body Elem) (class int, domain, continueAfter string, err error) {
	class, _, domain, continueAfter, err = GetNameListScope(body)
	return class, domain, continueAfter, err
}

// GetNameListScope decodes a GetNameList request with its object scope:
// vmdSpecific [0], domainSpecific [1] or aaSpecific [2] (ISO 9506-2:2003
// 10.5).
func GetNameListScope(body Elem) (class int, scope Scope, domain, continueAfter string, err error) {
	kids, err := body.Children()
	if err != nil {
		return 0, 0, "", "", err
	}
	for _, k := range kids {
		switch {
		case k.Context(0):
			in, _, err := Parse(k.Val)
			if err != nil {
				return 0, 0, "", "", err
			}
			v, _ := DecodeInt(in.Val)
			class = int(v)
		case k.Context(1):
			in, _, err := Parse(k.Val)
			if err != nil {
				return 0, 0, "", "", err
			}
			switch in.Tag {
			case 0x81:
				scope, domain = ScopeDomain, string(in.Val)
			case 0x82:
				scope = ScopeAA
			}
		case k.Context(2):
			continueAfter = string(k.Val)
		}
	}
	return class, scope, domain, continueAfter, nil
}

// ReadArgs decodes a Read request.
func ReadArgs(body Elem) (VariableSpec, error) {
	spec, _, err := ReadArgsWithSpec(body)
	return spec, err
}

// ReadArgsWithSpec decodes a Read request and its specificationWithResult
// flag (default false).
func ReadArgsWithSpec(body Elem) (VariableSpec, bool, error) {
	kids, err := body.Children()
	if err != nil {
		return VariableSpec{}, false, err
	}
	with := false
	for _, k := range kids {
		if k.Tag == 0x80 {
			with = len(k.Val) == 1 && k.Val[0] != 0
		}
	}
	for _, k := range kids {
		if k.Tag == 0xa1 {
			in, _, err := Parse(k.Val)
			if err != nil {
				return VariableSpec{}, false, err
			}
			spec, err := DecodeVariableSpec(in)
			return spec, with, err
		}
	}
	return VariableSpec{}, false, errors.New("mms: a read request without variables")
}

// WriteArgs decodes a Write request.
func WriteArgs(body Elem) (VariableSpec, []Data, error) {
	kids, err := body.Children()
	if err != nil || len(kids) != 2 {
		return VariableSpec{}, nil, errors.New("mms: a bad write request")
	}
	spec, err := DecodeVariableSpec(kids[0])
	if err != nil {
		return VariableSpec{}, nil, err
	}
	items, err := kids[1].Children()
	if err != nil {
		return VariableSpec{}, nil, err
	}
	vals := make([]Data, len(items))
	for i, it := range items {
		if vals[i], err = DecodeData(it); err != nil {
			return VariableSpec{}, nil, err
		}
	}
	return spec, vals, nil
}

// NameArg decodes the object name of GetVariableAccessAttributes (wrapped
// in name [0]) or GetNamedVariableListAttributes (bare).
func NameArg(body Elem) (ObjectName, error) {
	in, _, err := Parse(body.Val)
	if err != nil {
		return ObjectName{}, err
	}
	if body.Num == SvcGetVariableAccessAttributes {
		if in.Tag != 0xa0 {
			return ObjectName{}, errors.New("mms: access attributes by address are not supported")
		}
		if in, _, err = Parse(in.Val); err != nil {
			return ObjectName{}, err
		}
	}
	return DecodeObjectName(in)
}

// ConfirmedResponse wraps a service response.
func ConfirmedResponse(invoke uint32, service []byte) []byte {
	return T(TagConfirmedResponse, Uint(0x02, uint64(invoke)), service)
}

// ConfirmedErrorPDU is a confirmed-ErrorPDU with an error class and code.
func ConfirmedErrorPDU(invoke uint32, class, code int) []byte {
	return ConfirmedErrorPDUFor(invoke, ServiceError{Class: class, Code: code})
}

// ConfirmedErrorPDUFor is a confirmed-ErrorPDU carrying a full
// ServiceError.
func ConfirmedErrorPDUFor(invoke uint32, se ServiceError) []byte {
	return T(TagConfirmedError, Uint(0x80, uint64(invoke)), T(0xa2, se.contents()...))
}

// RejectPDU rejects a confirmed request whose service is not recognised.
func RejectPDU(invoke uint32) []byte {
	return RejectPDUFor(invoke, RejectConfirmedRequest, RejectUnrecognizedService)
}

// RejectInvalidArgumentPDU rejects a confirmed request whose argument
// cannot be decoded.
func RejectInvalidArgumentPDU(invoke uint32) []byte {
	return RejectPDUFor(invoke, RejectConfirmedRequest, RejectInvalidArgument)
}

// RejectPDUFor is a RejectPDU naming the rejected PDU type and the reason
// code; pdu-error rejects carry no invoke ID (pass pduType RejectPDUError).
func RejectPDUFor(invoke uint32, pduType, code int) []byte {
	reason := Int(0x80|byte(pduType), int64(code))
	if pduType == RejectPDUError {
		return T(TagReject, reason)
	}
	return T(TagReject, Uint(0x80, uint64(invoke)), reason)
}

// NameListResponse answers GetNameList.
func NameListResponse(names []string, more bool) []byte {
	ids := make([][]byte, len(names))
	for i, n := range names {
		ids[i] = Str(0x1a, n)
	}
	return T(0xa0|SvcGetNameList, T(0xa0, ids...), Bool(0x81, more))
}

// ReadResponse answers Read.
func ReadResponse(results []AccessResult) []byte { return ReadResponseWithSpec(nil, results) }

// ReadResponseWithSpec answers Read, returning the specification when the
// request asked for it (specificationWithResult).
func ReadResponseWithSpec(spec *VariableSpec, results []AccessResult) []byte {
	parts := make([][]byte, len(results))
	for i, r := range results {
		parts[i] = EncodeAccessResult(r)
	}
	if spec != nil {
		return T(0xa0|SvcRead, T(0xa0, spec.Encode()), T(0xa1, parts...))
	}
	return T(0xa0|SvcRead, T(0xa1, parts...))
}

// Identity is the Identify response.
type Identity struct {
	Vendor, Model, Revision string
	AbstractSyntaxes        []string // object identifiers, dotted
}

// IdentifyResponse answers Identify.
func IdentifyResponse(id Identity) []byte {
	parts := [][]byte{Str(0x80, id.Vendor), Str(0x81, id.Model), Str(0x82, id.Revision)}
	if len(id.AbstractSyntaxes) > 0 {
		oids := make([][]byte, len(id.AbstractSyntaxes))
		for i, o := range id.AbstractSyntaxes {
			oids[i] = T(0x06, OID(o))
		}
		parts = append(parts, T(0xa3, oids...))
	}
	return T(0xa0|SvcIdentify, parts...)
}

// DecodeIdentity decodes an Identify response.
func DecodeIdentity(body Elem) (Identity, error) {
	kids, err := body.Children()
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	for _, k := range kids {
		switch k.Tag {
		case 0x80:
			id.Vendor = string(k.Val)
		case 0x81:
			id.Model = string(k.Val)
		case 0x82:
			id.Revision = string(k.Val)
		case 0xa3:
			oids, _ := k.Children()
			for _, o := range oids {
				id.AbstractSyntaxes = append(id.AbstractSyntaxes, DecodeOID(o.Val))
			}
		}
	}
	return id, nil
}

// VMD logical and physical status values (ISO 9506-2:2003 10.2).
const (
	LogicalStateChangesAllowed   = 0
	LogicalNoStateChangesAllowed = 1
	LogicalLimitedServices       = 2
	LogicalSupportServices       = 3
	PhysicalOperational          = 0
	PhysicalPartiallyOperative   = 1
	PhysicalInoperable           = 2
	PhysicalNeedsCommissioning   = 3
)

// VMDStatus is the Status response.
type VMDStatus struct {
	Logical, Physical int
	LocalDetail       *BitString
}

// StatusResponse answers Status (and is the UnsolicitedStatus content).
func StatusResponse(st VMDStatus) []byte {
	parts := [][]byte{Int(0x80, int64(st.Logical)), Int(0x81, int64(st.Physical))}
	if st.LocalDetail != nil {
		parts = append(parts, T(0x82, st.LocalDetail.Contents()))
	}
	return T(0xa0|SvcStatus, parts...)
}

// DecodeStatus decodes a Status response.
func DecodeStatus(body Elem) (VMDStatus, error) {
	kids, err := body.Children()
	if err != nil {
		return VMDStatus{}, err
	}
	st := VMDStatus{Logical: -1, Physical: -1}
	for _, k := range kids {
		switch k.Tag {
		case 0x80:
			v, _ := DecodeInt(k.Val)
			st.Logical = int(v)
		case 0x81:
			v, _ := DecodeInt(k.Val)
			st.Physical = int(v)
		case 0x82:
			b, err := DecodeBitString(k.Val)
			if err == nil {
				st.LocalDetail = &b
			}
		}
	}
	if st.Logical < 0 || st.Physical < 0 {
		return st, errors.New("mms: a status response without its logical or physical status")
	}
	return st, nil
}

// WriteResponse answers Write: nil for success, else a DataAccessError.
func WriteResponse(errs []error) []byte {
	parts := make([][]byte, len(errs))
	for i, e := range errs {
		var dae DataAccessError
		switch {
		case e == nil:
			parts[i] = T(0x81)
		case errors.As(e, &dae):
			parts[i] = Int(0x80, int64(dae))
		default:
			parts[i] = Int(0x80, int64(ErrObjectAccessDenied))
		}
	}
	return T(0xa0|SvcWrite, parts...)
}

// VariableAccessAttributesResponse answers GetVariableAccessAttributes.
func VariableAccessAttributesResponse(t TypeSpec) []byte {
	return T(0xa0|SvcGetVariableAccessAttributes, Bool(0x80, false), T(0xa2, t.Encode()))
}

// NamedVariableListAttributesResponse answers GetNamedVariableListAttributes.
func NamedVariableListAttributesResponse(members []ObjectName, deletable bool) []byte {
	items := make([][]byte, len(members))
	for i, n := range members {
		items[i] = T(0x30, T(0xa0, n.Encode()))
	}
	return T(0xa0|SvcGetNamedVariableListAttributes, Bool(0x80, deletable), T(0xa1, items...))
}

// InformationReportPDU is an unconfirmed informationReport.
func InformationReportPDU(spec VariableSpec, results []AccessResult) []byte {
	parts := make([][]byte, len(results))
	for i, r := range results {
		parts[i] = EncodeAccessResult(r)
	}
	return T(TagUnconfirmed, T(0xa0, spec.Encode(), T(0xa0, parts...)))
}

// ---- response decoders (client side) ------------------------------------------

func decodeNameList(body Elem) ([]string, bool, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, false, err
	}
	var names []string
	more := true
	for _, k := range kids {
		switch {
		case k.Context(0):
			ids, err := k.Children()
			if err != nil {
				return nil, false, err
			}
			for _, id := range ids {
				names = append(names, string(id.Val))
			}
		case k.Context(1):
			more = len(k.Val) == 1 && k.Val[0] != 0
		}
	}
	if more && len(names) == 0 {
		more = false
	}
	return names, more, nil
}

func decodeReadResponse(body Elem) ([]AccessResult, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if k.Context(1) {
			return DecodeAccessResults(k.Val)
		}
	}
	return nil, errors.New("mms: a read response without results")
}

func decodeWriteResponse(body Elem) ([]error, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, err
	}
	out := make([]error, len(kids))
	for i, k := range kids {
		if k.Tag == 0x80 {
			v, _ := DecodeInt(k.Val)
			out[i] = DataAccessError(v)
		}
	}
	return out, nil
}

func decodeVAAResponse(body Elem) (TypeSpec, error) {
	kids, err := body.Children()
	if err != nil {
		return TypeSpec{}, err
	}
	for _, k := range kids {
		if k.Context(2) {
			in, _, err := Parse(k.Val)
			if err != nil {
				return TypeSpec{}, err
			}
			return DecodeTypeSpec(in)
		}
	}
	return TypeSpec{}, errors.New("mms: an access attributes response without a type")
}

func decodeNVLAResponse(body Elem) ([]ObjectName, error) {
	spec, err := decodeNVLASpec(body)
	return spec.Vars, err
}

// decodeNVLASpec decodes a GetNamedVariableListAttributes response with
// the members' alternate access.
func decodeNVLASpec(body Elem) (VariableSpec, error) {
	kids, err := body.Children()
	if err != nil {
		return VariableSpec{}, err
	}
	for _, k := range kids {
		if k.Context(1) {
			return DecodeVariableSpec(Elem{Tag: 0xa0, Num: 0, Val: k.Val})
		}
	}
	return VariableSpec{}, errors.New("mms: a variable list response without members")
}

// InformationReport is a received informationReport.
type InformationReport struct {
	Spec    VariableSpec
	Results []AccessResult
}

// DecodeInformationReport decodes an unconfirmed PDU's informationReport.
func DecodeInformationReport(e Elem) (InformationReport, error) {
	kids, err := e.Children()
	if err != nil || len(kids) == 0 || kids[0].Tag != 0xa0 {
		return InformationReport{}, errors.New("mms: not an information report")
	}
	parts, err := kids[0].Children()
	if err != nil || len(parts) != 2 {
		return InformationReport{}, errors.New("mms: a bad information report")
	}
	spec, err := DecodeVariableSpec(parts[0])
	if err != nil {
		return InformationReport{}, err
	}
	res, err := DecodeAccessResults(parts[1].Val)
	if err != nil {
		return InformationReport{}, err
	}
	return InformationReport{Spec: spec, Results: res}, nil
}

func decodeServiceError(e Elem) error {
	kids, err := e.Children()
	if err != nil {
		return &ServiceError{Class: -1}
	}
	for _, k := range kids {
		if k.Context(2) {
			se, err := DecodeServiceError(k.Val)
			if err != nil {
				return &ServiceError{Class: -1}
			}
			return &se
		}
	}
	return &ServiceError{Class: -1}
}
