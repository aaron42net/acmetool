// +build cgo

package fdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestParsePerm(t *testing.T) {
	tests := []struct {
		In    string
		Out   []Permission
		Erase map[string]struct{}
	}{
		{``, nil, map[string]struct{}{}},
		{`

     # this is a comment
     foo/bar 0644 0755
     foo/*/baz  0640  0750  
     alpha  0644 0755  root root
     beta  0644 0755  42 42
     gamma  0644 0755  $r $r
     delta   inherit
     x 0644 0755 root -
     y 0644 0755 - root
     `, []Permission{
			{Path: "foo/bar", FileMode: 0o644, DirMode: 0o755},
			{Path: "foo/*/baz", FileMode: 0o640, DirMode: 0o750},
			{Path: "alpha", FileMode: 0o644, DirMode: 0o755, UID: "root", GID: "root"},
			{Path: "beta", FileMode: 0o644, DirMode: 0o755, UID: "42", GID: "42"},
			{Path: "gamma", FileMode: 0o644, DirMode: 0o755, UID: "$r", GID: "$r"},
			{Path: "x", FileMode: 0o644, DirMode: 0o755, UID: "root", GID: ""},
			{Path: "y", FileMode: 0o644, DirMode: 0o755, UID: "", GID: "root"},
		}, map[string]struct{}{"delta": {}}},
	}

	for _, tst := range tests {
		ps, erase, err := parsePermissions(strings.NewReader(tst.In))
		if err != nil {
			t.Fatalf("error parsing permissions: %v", err)
		}

		if !reflect.DeepEqual(ps, tst.Out) {
			t.Fatalf("permissions don't match: got %#v, expected %#v", ps, tst.Out)
		}

		if !reflect.DeepEqual(erase, tst.Erase) {
			t.Fatalf("erase list doesn't match: got %v, expected %v", erase, tst.Erase)
		}
	}
}
