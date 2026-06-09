// Package utils provides shared helpers used across scanner modules.
package utils

import (
	"sort"
	"strings"
)

// BoolVal safely dereferences a *bool, returning false for nil.
func BoolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// Int32Val safely dereferences a *int32, returning 0 for nil.
func Int32Val(i *int32) int32 {
	if i == nil {
		return 0
	}
	return *i
}

// HasAnyPrefix returns true if s has any of the given prefixes (case-insensitive).
func HasAnyPrefix(s string, prefixes []string) bool {
	sl := strings.ToLower(s)
	for _, p := range prefixes {
		pl := strings.ToLower(p)
		if sl == pl || strings.HasPrefix(sl, pl+"-") || strings.HasPrefix(sl, pl+"_") || strings.HasPrefix(sl, pl) {
			return true
		}
	}
	return false
}

// ContainsFold is a case-insensitive strings.Contains.
func ContainsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// StringSet is a set of strings backed by a map.
type StringSet map[string]struct{}

// NewStringSet creates a StringSet from zero or more initial values.
func NewStringSet(items ...string) StringSet {
	m := make(StringSet, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

// Has returns true if s is in the set.
func (ss StringSet) Has(s string) bool {
	_, ok := ss[s]
	return ok
}

// Add adds s to the set.
func (ss StringSet) Add(s string) {
	ss[s] = struct{}{}
}

// Len returns the number of elements in the set.
func (ss StringSet) Len() int {
	return len(ss)
}

// Sorted returns the set elements as a sorted slice.
func (ss StringSet) Sorted() []string {
	out := make([]string, 0, len(ss))
	for k := range ss {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// InSet returns true if s is present in the set.
// Kept for compatibility with existing code.
func InSet(set StringSet, s string) bool {
	return set.Has(s)
}
