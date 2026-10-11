package mms

import (
	"context"
	"errors"
	"strings"
	"time"
)

// File management (ISO 9506-2:2003 Annex C ObtainFile, Annex D FileOpen,
// FileRead, FileClose, FileRename, FileDelete, FileDirectory). A FileName
// is a SEQUENCE OF GraphicString; the helpers take and give a path and
// send it as one GraphicString, as IEC 61850-8-1 23.1 uses it.

// Confirmed service numbers of the file services (SvcObtainFile,
// SvcFileOpen and SvcFileDirectory are in pdu.go).
const (
	SvcFileRead   = 73
	SvcFileClose  = 74
	SvcFileRename = 75
	SvcFileDelete = 76
)

// Error codes of the ServiceError class file (ISO 9506-2:2003 7.4.1).
const (
	FileErrOther             = 0
	FileErrNameAmbiguous     = 1
	FileErrBusy              = 2
	FileErrNameSyntax        = 3
	FileErrContentInvalid    = 4
	FileErrPositionInvalid   = 5
	FileErrAccessDenied      = 6
	FileErrNonExistent       = 7
	FileErrDuplicateName     = 8
	FileErrInsufficientSpace = 9
)

// FileAttributes are a file's size (octets) and last modification.
type FileAttributes struct {
	Size         uint64
	LastModified time.Time // zero when absent
}

// DirectoryEntry is a FileDirectory entry.
type DirectoryEntry struct {
	Name string
	FileAttributes
}

// FileNameElem encodes a FileName holding path under tag (0x30 for an
// untagged SEQUENCE, 0xa0|n for an implicit context tag).
func FileNameElem(tag byte, path string) []byte { return T(tag, Str(0x19, path)) }

// DecodeFileName joins the GraphicStrings of a FileName.
func DecodeFileName(e Elem) (string, error) {
	parts, err := e.Children()
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, p := range parts {
		sb.Write(p.Val)
	}
	return sb.String(), nil
}

func (a FileAttributes) contents() [][]byte {
	out := [][]byte{Uint(0x80, a.Size)}
	if !a.LastModified.IsZero() {
		out = append(out, Str(0x81, FormatGeneralizedTime(a.LastModified)))
	}
	return out
}

func decodeFileAttributes(e Elem) (FileAttributes, error) {
	var a FileAttributes
	kids, err := e.Children()
	if err != nil {
		return a, err
	}
	for _, k := range kids {
		switch {
		case k.Context(0):
			if a.Size, err = DecodeUint(k.Val); err != nil {
				return a, err
			}
		case k.Context(1):
			a.LastModified = ParseGeneralizedTime(string(k.Val))
		}
	}
	return a, nil
}

// FormatGeneralizedTime is t as a GeneralizedTime in UTC.
func FormatGeneralizedTime(t time.Time) string { return t.UTC().Format("20060102150405.000Z") }

// ParseGeneralizedTime reads the GeneralizedTime forms servers use; a
// time without a zone is read as UTC. An unreadable time is zero.
func ParseGeneralizedTime(s string) time.Time {
	s = strings.Replace(s, ",", ".", 1)
	for _, f := range []string{"20060102150405.999999999Z0700", "20060102150405Z0700", "20060102150405.999999999", "20060102150405", "200601021504Z0700"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// FileDirectoryRequest lists the files matching spec ("" for all) after
// the file named after ("" for the first).
func FileDirectoryRequest(spec, after string) []byte {
	var parts [][]byte
	if spec != "" {
		parts = append(parts, FileNameElem(0xa0, spec))
	}
	if after != "" {
		parts = append(parts, FileNameElem(0xa1, after))
	}
	return svc(SvcFileDirectory, parts...)
}

// DecodeFileDirectory decodes a FileDirectory-Request.
func DecodeFileDirectory(body Elem) (spec, after string, err error) {
	kids, err := body.Children()
	if err != nil {
		return "", "", err
	}
	for _, k := range kids {
		switch {
		case k.Context(0):
			spec, err = DecodeFileName(k)
		case k.Context(1):
			after, err = DecodeFileName(k)
		}
		if err != nil {
			return "", "", err
		}
	}
	return spec, after, nil
}

// FileDirectoryResponse answers FileDirectory. listOfDirectoryEntry is
// an explicitly tagged [0] around the SEQUENCE OF (the MMS module has no
// IMPLICIT on that component, and its tag default is explicit), so the
// entries sit inside a universal SEQUENCE inside [0].
func FileDirectoryResponse(entries []DirectoryEntry, more bool) []byte {
	items := make([][]byte, len(entries))
	for i, e := range entries {
		items[i] = T(0x30, FileNameElem(0xa0, e.Name), T(0xa1, e.FileAttributes.contents()...))
	}
	parts := [][]byte{T(0xa0, T(0x30, items...))}
	if more {
		parts = append(parts, Bool(0x81, true))
	}
	return svc(SvcFileDirectory, parts...)
}

// explicitSequenceOf unwraps the universal SEQUENCE an explicitly tagged
// SEQUENCE OF carries (one 0x30 element holding only 0x30 elements, or
// nothing); a list already holding the entries is returned as it is.
func explicitSequenceOf(list []Elem) ([]Elem, error) {
	if len(list) != 1 || list[0].Tag != 0x30 {
		return list, nil
	}
	inner, err := list[0].Children()
	if err != nil {
		return nil, err
	}
	for _, x := range inner {
		if x.Tag != 0x30 {
			return list, nil
		}
	}
	return inner, nil
}

// DecodeFileDirectoryResponse decodes a FileDirectory-Response. The
// standard form wraps the entries in a SEQUENCE inside the explicit [0]
// (FileDirectoryResponse); the implicit form, entries directly in [0],
// which this package sent before, is accepted too.
func DecodeFileDirectoryResponse(body Elem) ([]DirectoryEntry, bool, error) {
	kids, err := body.Children()
	if err != nil {
		return nil, false, err
	}
	var out []DirectoryEntry
	more := false
	for _, k := range kids {
		switch {
		case k.Context(0):
			list, err := k.Children()
			if err != nil {
				return nil, false, err
			}
			if list, err = explicitSequenceOf(list); err != nil {
				return nil, false, err
			}
			for _, de := range list {
				f, err := de.Children()
				if err != nil {
					return nil, false, err
				}
				var e DirectoryEntry
				for _, x := range f {
					switch {
					case x.Context(0):
						e.Name, err = DecodeFileName(x)
					case x.Context(1):
						e.FileAttributes, err = decodeFileAttributes(x)
					}
					if err != nil {
						return nil, false, err
					}
				}
				out = append(out, e)
			}
		case k.Context(1):
			more = len(k.Val) == 1 && k.Val[0] != 0
		}
	}
	return out, more, nil
}

// FileOpenRequest opens a file for reading from position pos.
func FileOpenRequest(name string, pos uint32) []byte {
	return svc(SvcFileOpen, FileNameElem(0xa0, name), Uint(0x81, uint64(pos)))
}

// DecodeFileOpen decodes a FileOpen-Request.
func DecodeFileOpen(body Elem) (name string, pos uint32, err error) {
	kids, err := body.Children()
	if err != nil {
		return "", 0, err
	}
	found := false
	for _, k := range kids {
		switch {
		case k.Context(0):
			name, err = DecodeFileName(k)
			found = true
		case k.Context(1):
			var p uint64
			p, err = DecodeUint(k.Val)
			pos = uint32(p)
		}
		if err != nil {
			return "", 0, err
		}
	}
	if !found {
		return "", 0, errors.New("mms: a FileOpen request without a file name")
	}
	return name, pos, nil
}

// FileOpenResponse answers FileOpen with the FRSM identifier and the
// file's attributes.
func FileOpenResponse(frsm int32, a FileAttributes) []byte {
	return svc(SvcFileOpen, Int(0x80, int64(frsm)), T(0xa1, a.contents()...))
}

// FRSMRequest is a FileRead or FileClose request (service SvcFileRead or
// SvcFileClose) for an FRSM identifier.
func FRSMRequest(service int, frsm int32) []byte { return TH(0x80, service, IntBytes(int64(frsm))) }

// DecodeFRSM decodes a FileRead or FileClose request's FRSM identifier.
func DecodeFRSM(body Elem) (int32, error) {
	n, err := DecodeInt(body.Val)
	return int32(n), err
}

// FileReadResponse answers FileRead; moreFollows defaults to true and is
// sent only when false.
func FileReadResponse(data []byte, more bool) []byte {
	parts := [][]byte{T(0x80, data)}
	if !more {
		parts = append(parts, Bool(0x81, false))
	}
	return svc(SvcFileRead, parts...)
}

// NullResponse is the NULL response of FileClose, FileDelete,
// FileRename and ObtainFile (service number n).
func NullResponse(n int) []byte { return TH(0x80, n) }

// FileDeleteRequest deletes a file (FileDelete-Request is the FileName
// itself).
func FileDeleteRequest(name string) []byte { return svc(SvcFileDelete, Str(0x19, name)) }

// DecodeFileDelete decodes a FileDelete-Request.
func DecodeFileDelete(body Elem) (string, error) { return DecodeFileName(body) }

// ObtainFileRequest asks the server to fetch sourceFile from the client's
// file store into destinationFile (sourceFileServer absent).
func ObtainFileRequest(source, dest string) []byte {
	return svc(SvcObtainFile, FileNameElem(0xa1, source), FileNameElem(0xa2, dest))
}

// DecodeObtainFile decodes an ObtainFile-Request (a sourceFileServer is
// read and ignored).
func DecodeObtainFile(body Elem) (source, dest string, err error) {
	kids, err := body.Children()
	if err != nil {
		return "", "", err
	}
	for _, k := range kids {
		switch {
		case k.Context(1):
			source, err = DecodeFileName(k)
		case k.Context(2):
			dest, err = DecodeFileName(k)
		}
		if err != nil {
			return "", "", err
		}
	}
	if source == "" || dest == "" {
		return "", "", errors.New("mms: an ObtainFile request without both file names")
	}
	return source, dest, nil
}

// FileDirectory lists files (one response; ask again after the last name
// while more is true).
func (c *Client) FileDirectory(ctx context.Context, spec, after string) ([]DirectoryEntry, bool, error) {
	body, err := c.call(ctx, FileDirectoryRequest(spec, after), SvcFileDirectory)
	if err != nil {
		return nil, false, err
	}
	return DecodeFileDirectoryResponse(body)
}

// FileOpen opens a file and returns its FRSM identifier and attributes.
func (c *Client) FileOpen(ctx context.Context, name string, pos uint32) (int32, FileAttributes, error) {
	body, err := c.call(ctx, FileOpenRequest(name, pos), SvcFileOpen)
	if err != nil {
		return 0, FileAttributes{}, err
	}
	kids, err := body.Children()
	if err != nil {
		return 0, FileAttributes{}, err
	}
	var frsm int64
	var a FileAttributes
	gotID := false
	for _, k := range kids {
		switch {
		case k.Context(0):
			frsm, err = DecodeInt(k.Val)
			gotID = true
		case k.Context(1):
			a, err = decodeFileAttributes(k)
		}
		if err != nil {
			return 0, FileAttributes{}, err
		}
	}
	if !gotID {
		return 0, a, errors.New("mms: a FileOpen response without an FRSM identifier")
	}
	return int32(frsm), a, nil
}

// FileRead reads the next part of an open file.
func (c *Client) FileRead(ctx context.Context, frsm int32) (data []byte, more bool, err error) {
	body, err := c.call(ctx, FRSMRequest(SvcFileRead, frsm), SvcFileRead)
	if err != nil {
		return nil, false, err
	}
	kids, err := body.Children()
	if err != nil {
		return nil, false, err
	}
	more = true // DEFAULT TRUE
	for _, k := range kids {
		switch {
		case k.Context(0):
			data = k.Val
		case k.Context(1):
			more = len(k.Val) == 1 && k.Val[0] != 0
		}
	}
	return data, more, nil
}

// FileClose closes an open file.
func (c *Client) FileClose(ctx context.Context, frsm int32) error {
	_, err := c.call(ctx, FRSMRequest(SvcFileClose, frsm), SvcFileClose)
	return err
}

// FileDelete deletes a file.
func (c *Client) FileDelete(ctx context.Context, name string) error {
	_, err := c.call(ctx, FileDeleteRequest(name), SvcFileDelete)
	return err
}

// ObtainFile asks the server to obtain a file from this client.
func (c *Client) ObtainFile(ctx context.Context, source, dest string) error {
	_, err := c.call(ctx, ObtainFileRequest(source, dest), SvcObtainFile)
	return err
}
