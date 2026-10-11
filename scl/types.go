package scl

import (
	"encoding/base64"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Value types of attributes (the simple types of the SCL schema, as
// described in IEC 61850-6 8.1, 9 and Annex E.2). Each checker returns ""
// when the value is valid, else a short reason.
type checker func(string) string

func rx(pattern string) *regexp.Regexp { return regexp.MustCompile("^(?:" + pattern + ")$") }

var (
	reAcsi        = rx(`[A-Za-z][0-9A-Za-z_]*`)
	reLDName      = rx(`[A-Za-z][0-9A-Za-z_]*`)
	reLDInst      = rx(`[A-Za-z0-9][0-9A-Za-z_]*`)
	rePrefix      = rx(`[A-Za-z][0-9A-Za-z_]*`)
	reLNInst      = rx(`[0-9]{1,12}`)
	reDataName    = rx(`[A-Z][0-9A-Za-z]*`)
	reSubName     = rx(`[a-z][0-9A-Za-z]*`)
	reAPName      = rx(`[A-Za-z0-9][0-9A-Za-z_]*`)
	reAssocID     = rx(`[0-9A-Za-z]+`)
	reFullDA      = rx(`[a-zA-Z][a-zA-Z0-9]*(\([0-9]+\))?(\.[a-zA-Z][a-zA-Z0-9]*(\([0-9]+\))?)*`)
	reFullDO      = rx(`[A-Z][0-9A-Za-z]{0,11}(\.[a-z][0-9A-Za-z]*(\([0-9]+\))?)*`)
	reVersion     = rx(`2[0-2][0-9]{2}`)
	reRevision    = rx(`[A-Z]`)
	reUUID        = rx(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reExtP        = rx(`[A-Z][0-9A-Za-z\-]*`)
	reExtEquip    = rx(`E[A-Z]{2,}`)
	reExtLNClass  = rx(`LLN0|[A-Z]{4}`)
	reExtCDC      = rx(`[A-Za-z]{1,5}`)
	reExtBType    = rx(`[A-Z][0-9A-Za-z]*`)
	reCNodeRef    = rx(`.+/.+(/.+)*`)
	reNamespace   = rx(`[\x20-\x7E]+:20\d\d[A-Z]?`)
	reNameLength  = rx(`32|64|6[5-9]|[7-9]\d|[1-9]\d\d+`)
	reMAC         = rx(`[0-9A-F]{2}(-[0-9A-F]{2}){5}`)
	reHex4        = rx(`[0-9A-F]{4}`)
	reHex3        = rx(`[0-9A-F]{3}`)
	predefinedFC  = set("ST MX CO SP SG SE SV CF DC EX SR BL OR")
	predefinedCDC = set("SPS DPS INS ENS ACT ACD SEC BCR HST VSS MV CMV SAV WYE DEL SEQ HMV HWYE HDEL SPC DPC INC ENC BSC ISC APC BAC SPG ING ENG ORG TSG CUG VSG ASG CURVE CSG DPL LPL CSD CST BTS UTS LTS GTS MTS NTS STS CTS OTS VSD ORS TCS")
	// BasicTypes are the predefined bType values (9.5.4.2).
	BasicTypes   = set("BOOLEAN INT8 INT16 INT24 INT32 INT64 INT128 INT8U INT16U INT24U INT32U FLOAT32 FLOAT64 Enum Dbpos Tcmd Quality Timestamp VisString32 VisString64 VisString65 VisString129 VisString255 Octet64 Unicode255 Struct EntryTime Check ObjRef Currency PhyComAddr TrgOps OptFlds SvOptFlds LogOptFlds EntryID Octet6 Octet16")
	predefinedP  = set("IP IP-SUBNET IP-GATEWAY OSI-NSAP OSI-TSEL OSI-SSEL OSI-PSEL OSI-AP-Title OSI-AP-Invoke OSI-AE-Qualifier OSI-AE-Invoke MAC-Address APPID VLAN-PRIORITY VLAN-ID SNTP-Port MMS-Port DNSName IPv6FlowLabel IPv6ClassOfTraffic C37-118-IP-Port IP-UDP-PORT IP-TCP-PORT IPv6 IPv6-SUBNET IPv6-GATEWAY IPv6-IGMPv3Src IP-IGMPv3Src IP-ClassOfTraffic")
	predefinedDA = set("T Test Check SIUnit Oper SBO SBOw Cancel Addr PRIORITY VID APPID TransportInUse IPClassOfTraffic IPv6FlowLabel IPAddressLength IPAddress")
	condEquip    = set("CBR DIS VTR CTR GEN CAP REA CON MOT EFN PSH BAT BSH CAB GIL LIN RES RRC SAR TCF TCR IFL FAN SCR SMC PMP")
	genEquip     = set("AXN BAT MOT FAN FIL PMP TNK VLV")
	fileTypes    = set("ICD IID CID SCD SSD SED ISD")
	multipliers  = set(" m k M mu y z a f p n c d da h G T P E Z Y")
)

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Split(s, " ") {
		m[f] = true
	}
	return m
}

func enum(values string) checker {
	m := set(values)
	return func(v string) string {
		if m[v] {
			return ""
		}
		return "is not one of " + strings.ReplaceAll(values, " ", ", ")
	}
}

func pattern(re *regexp.Regexp, max int, what string) checker {
	return func(v string) string {
		if max > 0 && utf8.RuneCountInString(v) > max {
			return "is longer than " + strconv.Itoa(max) + " characters"
		}
		if !re.MatchString(v) {
			return "is not " + what
		}
		return ""
	}
}

func normalized(v string) string {
	if strings.ContainsAny(v, "\t\r\n") {
		return "contains a tab, carriage return or line feed"
	}
	return ""
}

func uintRange(lo uint64) checker {
	return func(v string) string {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return "is not an unsigned 32-bit integer"
		}
		if n < lo {
			return "is below " + strconv.FormatUint(lo, 10)
		}
		return ""
	}
}

// types maps an SCL simple type name to our reading of it from the clause
// text: it gives the specific message when a value fails the XSD type and
// adds the few restrictions the XSD does not express (xsd.go attrValue).
var types = map[string]checker{
	"string":   normalized,
	"tName":    func(v string) string { return firstOf(normalized(v), nonEmpty(v)) },
	"tAnyName": normalized,
	"tID": func(v string) string {
		if v == "" || strings.ContainsAny(v, " \t\r\n") || utf8.RuneCountInString(v) > 255 {
			return "is not an identifier of 1 to 255 characters without blanks"
		}
		return ""
	},
	"tIEDName":         checkIEDName(false, false),
	"tIEDNameOrNone":   checkIEDName(true, false),
	"tIEDNameOrRel":    checkIEDName(false, true),
	"tLDName":          pattern(reLDName, 64, "a logical device name"),
	"tLDInst":          pattern(reLDInst, 64, "a logical device instance"),
	"tLDInstOrEmpty":   orEmpty(pattern(reLDInst, 64, "a logical device instance")),
	"tPrefix":          orEmpty(pattern(rePrefix, 11, "an LN prefix")),
	"tLNInst":          pattern(reLNInst, 0, "an LN instance number"),
	"tLNInstOrEmpty":   orEmpty(pattern(reLNInst, 0, "an LN instance number")),
	"tLNClass":         pattern(reExtLNClass, 0, "an LN class (four capital letters)"),
	"tDataName":        pattern(reDataName, 12, "a data object name"),
	"tSubDataName":     pattern(reSubName, 60, "a sub data object name"),
	"tAttributeName":   checkAttrName,
	"tDataSetName":     pattern(reAcsi, 32, "a data set name"),
	"tCBName":          pattern(reAcsi, 32, "a control block name"),
	"tLogName":         pattern(reAcsi, 32, "a log name"),
	"tAccessPointName": pattern(reAPName, 32, "an access point name"),
	"tAssociationID":   pattern(reAssocID, 0, "an association identifier"),
	"tMessageID": func(v string) string {
		if v == "" || utf8.RuneCountInString(v) > 129 {
			return "is not 1 to 129 characters"
		}
		for _, r := range v {
			if r < 0x20 || r > 0x7E {
				return "has characters outside Basic Latin"
			}
		}
		return ""
	},
	"tFullAttributeName": pattern(reFullDA, 0, "an attribute name path"),
	"tFullDOName":        pattern(reFullDO, 0, "a data object name path"),
	"tFC": func(v string) string {
		if predefinedFC[v] {
			return ""
		}
		return "is not a functional constraint"
	},
	"tCDC": func(v string) string {
		if predefinedCDC[v] || reExtCDC.MatchString(v) {
			return ""
		}
		return "is not a common data class"
	},
	"tBasicType": func(v string) string {
		if BasicTypes[v] {
			return ""
		}
		return "is not a basic type"
	},
	"tValKind":     enum("Spec Conf RO Set"),
	"bool":         checkBool,
	"uint":         uintRange(0),
	"uint1":        uintRange(1),
	"ushort":       func(v string) string { return intRange(v, 0, 65535) },
	"int":          func(v string) string { return intRange(v, math.MinInt32, math.MaxInt32) },
	"decimal0":     checkDecimal,
	"ubyte1":       func(v string) string { return intRange(v, 1, 255) },
	"tSclVersion":  pattern(reVersion, 0, "an SCL version year"),
	"tSclRevision": pattern(reRevision, 0, "an SCL revision letter"),
	"tSclRelease":  func(v string) string { return intRange(v, 1, 255) },
	"tUUID":        pattern(reUUID, 0, "a UUID in 8-4-4-4-12 hexadecimal form"),
	"tSCLFileType": func(v string) string {
		if fileTypes[v] {
			return ""
		}
		return "is not a file type (ICD, IID, CID, SCD, SSD, SED, ISD)"
	},
	"tRight":                enum("full fix dataflow"),
	"tServiceSettings":      enum("Dyn Conf Fix"),
	"tServiceSettingsNoDyn": enum("Conf Fix"),
	"tRedProt":              enum("none hsr prp rstp"),
	"tSMVDelivery":          enum("unicast multicast both"),
	"tPhase":                enum("A B C N all none AB BC CA"),
	"tAssociationKind":      enum("pre-established predefined"),
	"tAssociationInitiator": enum("client server"),
	"tGSEControlType":       enum("GSSE GOOSE"),
	"tSecurity":             enum("None Signature SignatureAndEncryption"),
	"tSmpMod":               enum("SmpPerPeriod SmpPerSec SecPerSmp"),
	"tServiceType":          enum("Poll Report GOOSE SMV"),
	"tExtControlCheck":      enum("true false conserve"),
	"tBufMode":              enum("unbuffered buffered both"),
	"tNameStructure":        enum("IEDName"),
	"tPType": func(v string) string {
		if predefinedP[v] || reExtP.MatchString(v) {
			return ""
		}
		return "is not a P type"
	},
	"tPTypePhysConn": func(v string) string {
		if v == "Type" || v == "Plug" || v == "Cable" || v == "Port" || reExtP.MatchString(v) {
			return ""
		}
		return "is not a PhysConn P type"
	},
	"tPhysConnType": func(v string) string {
		if v == "Connection" || v == "RedConn" || reExtP.MatchString(v) {
			return ""
		}
		return "is not a PhysConn type"
	},
	"tCondEquip": func(v string) string {
		if condEquip[v] || reExtEquip.MatchString(v) {
			return ""
		}
		return "is not a conducting equipment type"
	},
	"tGenEquip": func(v string) string {
		if genEquip[v] || reExtEquip.MatchString(v) {
			return ""
		}
		return "is not a general equipment type"
	},
	"tMultiplier": func(v string) string {
		if multipliers[v] {
			return ""
		}
		return "is not a unit multiplier"
	},
	"tPTR":        enum("PTR"),
	"tPTW":        enum("PTW"),
	"tLTC":        enum("LTC"),
	"tLLN0":       enum("LLN0"),
	"tEmpty":      func(v string) string { return firstOf(map[bool]string{true: "", false: "is not empty"}[v == ""]) },
	"tSDOCount":   func(v string) string { return firstOf(countOf(v, reSubName)) },
	"tDACount":    func(v string) string { return firstOf(countOf(v, reSubName)) },
	"tCNodeRef":   pattern(reCNodeRef, 0, "a connectivity node path (a/b[/c…])"),
	"tNameLength": pattern(reNameLength, 0, "a name length (32, 64 or more)"),
	"tLanguage":   func(v string) string { return firstOf(nonEmpty(v)) },
	"anyURI":      normalized,
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func nonEmpty(v string) string {
	if v == "" {
		return "is empty"
	}
	return ""
}

func orEmpty(c checker) checker {
	return func(v string) string {
		if v == "" {
			return ""
		}
		return c(v)
	}
}

func countOf(v string, re *regexp.Regexp) string {
	if _, err := strconv.ParseUint(v, 10, 32); err == nil {
		return ""
	}
	if re.MatchString(v) {
		return ""
	}
	return "is not a count or an attribute name"
}

func checkBool(v string) string {
	switch v {
	case "true", "false", "1", "0":
		return ""
	}
	return "is not a boolean (true, false, 1, 0)"
}

func intRange(v string, lo, hi int64) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return "is not an integer"
	}
	if n < lo || n > hi {
		return "is out of range " + strconv.FormatInt(lo, 10) + ".." + strconv.FormatInt(hi, 10)
	}
	return ""
}

func checkDecimal(v string) string {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || strings.ContainsAny(v, "eEnN") {
		return "is not a decimal number"
	}
	if f < 0 {
		return "is negative"
	}
	return ""
}

func checkAttrName(v string) string {
	if predefinedDA[v] {
		return ""
	}
	if !reSubName.MatchString(v) || len(v) > 60 {
		return "is not an attribute name (lower-case first letter, letters and digits, at most 60)"
	}
	return ""
}

// checkIEDName applies 9.3.2: 1 to 64 characters, a letter first, then
// letters, digits and underscore; None only where allowed (process
// section) and @ only where relative references are allowed (ExtRef).
func checkIEDName(allowNone, allowRel bool) checker {
	return func(v string) string {
		if allowRel && v == "@" {
			return ""
		}
		if v == "None" {
			if allowNone {
				return ""
			}
			return "is the reserved name None"
		}
		if len(v) > 64 || !reAcsi.MatchString(v) {
			return "is not an IED name (1-64 characters: a letter, then letters, digits, underscore)"
		}
		return ""
	}
}

// CheckValue checks a Val text against the attribute's basic type
// (9.5.4.1 Table 45). enumVals are the literals of an Enum type (nil when
// unknown).
func CheckValue(bType, v string, enumVals map[string]bool) string {
	v = strings.TrimSpace(v)
	switch bType {
	case "BOOLEAN":
		return checkBool(v)
	case "INT8":
		return intRange(v, -128, 127)
	case "INT16":
		return intRange(v, -32768, 32767)
	case "INT24":
		return intRange(v, -1<<23, 1<<23-1)
	case "INT32":
		return intRange(v, math.MinInt32, math.MaxInt32)
	case "INT64":
		return intRange(v, math.MinInt64, math.MaxInt64)
	case "INT8U":
		return intRange(v, 0, 255)
	case "INT16U":
		return intRange(v, 0, 65535)
	case "INT24U":
		return intRange(v, 0, 1<<24-1)
	case "INT32U":
		return intRange(v, 0, math.MaxUint32)
	case "FLOAT32", "FLOAT64":
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return "is not a number"
		}
	case "Enum":
		if enumVals != nil && !enumVals[v] {
			return "is not a literal of the enumeration"
		}
	case "Octet64", "Octet6", "Octet16":
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "is not base64"
		}
		n := map[string]int{"Octet64": 64, "Octet6": 6, "Octet16": 16}[bType]
		if len(b) > n {
			return "is longer than " + strconv.Itoa(n) + " octets"
		}
	case "VisString32", "VisString64", "VisString65", "VisString129", "VisString255":
		n, _ := strconv.Atoi(strings.TrimPrefix(bType, "VisString"))
		if len(v) > n {
			return "is longer than " + strconv.Itoa(n) + " octets"
		}
		for _, r := range v {
			if r > 0xFF {
				return "has characters outside ISO/IEC 8859-1"
			}
		}
	case "Unicode255":
		if utf8.RuneCountInString(v) > 255 {
			return "is longer than 255 characters"
		}
	case "Timestamp":
		for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
			if _, err := time.Parse(layout, v); err == nil {
				return ""
			}
		}
		return "is not a date-time without time zone"
	case "Currency":
		if len(v) != 3 || strings.ToUpper(v) != v {
			return "is not a three-letter currency code"
		}
	case "ObjRef":
		if len(v) > 129 {
			return "is longer than 129 characters"
		}
	}
	return ""
}

// CheckP checks the value of a predefined address parameter (the tP_
// restrictions named in 9.4.3; formats as used by IEC 61850-8-1 and -9-2).
func CheckP(typ, v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "is empty"
	}
	switch typ {
	case "IP", "IP-SUBNET", "IP-GATEWAY", "IP-IGMPv3Src":
		if ip := net.ParseIP(v); ip == nil || ip.To4() == nil || strings.Contains(v, ":") {
			return "is not an IPv4 address"
		}
	case "IPv6", "IPv6-GATEWAY", "IPv6-IGMPv3Src":
		if ip := net.ParseIP(v); ip == nil || !strings.Contains(v, ":") {
			return "is not an IPv6 address"
		}
	case "IPv6-SUBNET":
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 128 {
			if !strings.HasPrefix(v, "/") {
				return "is not an IPv6 prefix length"
			}
		}
	case "MAC-Address":
		if !reMAC.MatchString(strings.ToUpper(v)) {
			return "is not a MAC address (six hexadecimal octets separated by -)"
		}
	case "APPID":
		if !reHex4.MatchString(strings.ToUpper(v)) {
			return "is not four hexadecimal digits"
		}
	case "VLAN-ID":
		if !reHex3.MatchString(strings.ToUpper(v)) {
			return "is not three hexadecimal digits"
		}
	case "VLAN-PRIORITY":
		return intRange(v, 0, 7)
	case "OSI-TSEL", "OSI-SSEL", "OSI-PSEL":
		if len(v)%2 != 0 || len(v) > 32 {
			return "is not an even number of hexadecimal digits (at most 16 octets)"
		}
		for _, r := range v {
			if !strings.ContainsRune("0123456789ABCDEFabcdef", r) {
				return "is not hexadecimal"
			}
		}
	case "OSI-AP-Title":
		for _, f := range strings.Split(v, ",") {
			if _, err := strconv.ParseUint(strings.TrimSpace(f), 10, 32); err != nil {
				return "is not a comma-separated object identifier"
			}
		}
	case "OSI-AE-Qualifier", "OSI-AP-Invoke", "OSI-AE-Invoke":
		return intRange(v, math.MinInt32, math.MaxInt32)
	case "IP-UDP-PORT", "IP-TCP-PORT", "SNTP-Port", "MMS-Port", "C37-118-IP-Port":
		return intRange(v, 0, 65535)
	}
	return ""
}
