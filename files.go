package iec61850

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// File services (IEC 61850-8-1 23): GetServerDirectory(FILE) and
// GetFileAttributeValues map to MMS FileDirectory, GetFile to FileOpen,
// FileRead and FileClose, DeleteFile to FileDelete (ISO 9506-2 Annex D).
// A file name is a path with "/" separators (8-1 23.1).

// MaxFileName is the longest IEC 61850 file name (8-1 23.1: 255 octets).
const MaxFileName = 255

// FileEntry is a directory entry (8-1 Table 112).
type FileEntry struct {
	Name         string    `json:"name"`
	Size         uint64    `json:"size"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

// CheckFileName checks a file name before a file service uses it.
func CheckFileName(name string) error { return checkFileName(name) }

func checkFileName(name string) error {
	if name == "" || len(name) > MaxFileName {
		return fmt.Errorf("file name %q is empty or longer than %d octets", name, MaxFileName)
	}
	return nil
}

// FileDirectory lists the files under spec ("" or "/" for all, or a
// directory such as "/COMTRADE/"), reading further parts after the last
// name while the IED says more follow (8-1 9.3, Table 46).
func (cl *Client) FileDirectory(ctx context.Context, spec string) ([]FileEntry, error) {
	var out []FileEntry
	after := ""
	for page := 0; page < maxLogPages; page++ {
		entries, more, err := cl.c.FileDirectory(ctx, spec, after)
		if err != nil {
			return out, err
		}
		for _, e := range entries {
			out = append(out, FileEntry{Name: e.Name, Size: e.Size, LastModified: e.LastModified})
		}
		if !more {
			return out, nil
		}
		if len(entries) == 0 {
			return out, errors.New("the IED said more files follow but sent none")
		}
		after = entries[len(entries)-1].Name
	}
	return out, errors.New("the file directory did not end")
}

// ErrFileTooLarge reports a file longer than GetFile was allowed to read.
var ErrFileTooLarge = errors.New("the file is larger than allowed")

// GetFile reads a whole file (8-1 23.2.1: FileOpen at position 0, FileRead
// until moreFollows is false, FileClose), at most max octets (0 for no
// limit).
func (cl *Client) GetFile(ctx context.Context, name string, max int) ([]byte, FileEntry, error) {
	fe := FileEntry{Name: name}
	if err := checkFileName(name); err != nil {
		return nil, fe, err
	}
	frsm, attrs, err := cl.c.FileOpen(ctx, name, 0)
	if err != nil {
		return nil, fe, fmt.Errorf("opening %s: %w", name, err)
	}
	fe.Size, fe.LastModified = attrs.Size, attrs.LastModified
	var data []byte
	for {
		part, more, err := cl.c.FileRead(ctx, frsm)
		if err != nil {
			_ = cl.c.FileClose(ctx, frsm)
			return nil, fe, fmt.Errorf("reading %s: %w", name, err)
		}
		data = append(data, part...)
		if max > 0 && len(data) > max {
			_ = cl.c.FileClose(ctx, frsm)
			return nil, fe, fmt.Errorf("%w: %s is over %d octets", ErrFileTooLarge, name, max)
		}
		if !more {
			break
		}
	}
	if err := cl.c.FileClose(ctx, frsm); err != nil {
		return nil, fe, fmt.Errorf("closing %s: %w", name, err)
	}
	return data, fe, nil
}

// DeleteFile deletes a file (8-1 23.2.3: FileDelete).
func (cl *Client) DeleteFile(ctx context.Context, name string) error {
	if err := checkFileName(name); err != nil {
		return err
	}
	if err := cl.c.FileDelete(ctx, name); err != nil {
		return fmt.Errorf("deleting %s: %w", name, err)
	}
	return nil
}
