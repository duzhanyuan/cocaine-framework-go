// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Originaly copied from https://github.com/golang/net/blob/master/http2/hpack/tables.go
// package hpack

package cocaine12

import (
	"fmt"
)

// A HeaderField is a name-value pair. Both the name and value are
// treated as opaque sequences of octets.
type HeaderField struct {
	Name, Value string

	// Sensitive means that this header field should never be
	// indexed.
	Sensitive bool
}

func (hf HeaderField) String() string {
	var suffix string
	if hf.Sensitive {
		suffix = " (sensitive)"
	}
	return fmt.Sprintf("header field %q = %q%s", hf.Name, hf.Value, suffix)
}

// Size returns the size of an entry per RFC 7541 section 4.1.
func (hf HeaderField) Size() uint32 {
	// http://http2.github.io/http2-spec/compression.html#rfc.section.4.1
	// "The size of the dynamic table is the sum of the size of
	// its entries. The size of an entry is the sum of its name's
	// length in octets (as defined in Section 5.2), its value's
	// length in octets (see Section 5.2), plus 32.  The size of
	// an entry is calculated using the length of the name and
	// value without any Huffman encoding applied."

	// This can overflow if somebody makes a large HeaderField
	// Name and/or Value by hand, but we don't care, because that
	// won't happen on the wire because the encoding doesn't allow
	// it.
	return uint32(len(hf.Name) + len(hf.Value) + 32)
}

// headerFieldTable implements a list of HeaderFields.
// This is used to implement the static and dynamic tables.
type headerFieldTable struct {
	// For static tables, entries are never evicted.
	//
	// For dynamic tables, entries are evicted from ents[0] and added to the end.
	// Each entry has a unique id that starts at one and increments for each
	// entry that is added. This unique id is stable across evictions, meaning
	// it can be used as a pointer to a specific entry. As in hpack, unique ids
	// are 1-based. The unique id for ents[k] is k + evictCount + 1.
	//
	// Zero is not a valid unique id.
	//
	// evictCount should not overflow in any remotely practical situation. In
	// practice, we will have one dynamic table per HTTP/2 connection. If we
	// assume a very powerful server that handles 1M QPS per connection and each
	// request adds (then evicts) 100 entries from the table, it would still take
	// 2M years for evictCount to overflow.
	ents       []HeaderField
	evictCount uint64

	// byName maps a HeaderField name to the unique id of the newest entry with
	// the same name. See above for a definition of "unique id".
	byName map[string]uint64

	// byNameValue maps a HeaderField name/value pair to the unique id of the newest
	// entry with the same name and value. See above for a definition of "unique id".
	byNameValue map[pairNameValue]uint64
}

type pairNameValue struct {
	name, value string
}

func (t *headerFieldTable) init() {
	t.byName = make(map[string]uint64)
	t.byNameValue = make(map[pairNameValue]uint64)
}

// len reports the number of entries in the table.
func (t *headerFieldTable) len() int {
	return len(t.ents)
}

// addEntry adds a new entry.
func (t *headerFieldTable) addEntry(f HeaderField) {
	id := uint64(t.len()) + t.evictCount + 1
	t.byName[f.Name] = id
	t.byNameValue[pairNameValue{f.Name, f.Value}] = id
	t.ents = append(t.ents, f)
}

// evictOldest evicts the n oldest entries in the table.
func (t *headerFieldTable) evictOldest(n int) {
	if n > t.len() {
		panic(fmt.Sprintf("evictOldest(%v) on table with %v entries", n, t.len()))
	}
	for k := 0; k < n; k++ {
		f := t.ents[k]
		id := t.evictCount + uint64(k) + 1
		if t.byName[f.Name] == id {
			t.byName[f.Name] = 0
		}
		if p := (pairNameValue{f.Name, f.Value}); t.byNameValue[p] == id {
			t.byNameValue[p] = 0
		}
	}
	copy(t.ents, t.ents[n:])
	for k := t.len() - n; k < t.len(); k++ {
		t.ents[k] = HeaderField{} // so strings can be garbage collected
	}
	t.ents = t.ents[:t.len()-n]
	if t.evictCount+uint64(n) < t.evictCount {
		panic("evictCount overflow")
	}
	t.evictCount += uint64(n)
}

// search finds f in the table. If there is no match, i is 0.
// If both name and value match, i is the matched index and nameValueMatch
// becomes true. If only name matches, i points to that index and
// nameValueMatch becomes false.
//
// The returned index is a 1-based HPACK index. For dynamic tables, HPACK says
// that index 1 should be the newest entry, but t.ents[0] is the oldest entry,
// meaning t.ents is reversed for dynamic tables. Hence, when t is a dynamic
// table, the return value i actually refers to the entry t.ents[t.len()-i].
//
// All tables are assumed to be a dynamic tables except for the global
// staticTable pointer.
//
// See Section 2.3.3.
func (t *headerFieldTable) search(f HeaderField) (i uint64, nameValueMatch bool) {
	if !f.Sensitive {
		if id := t.byNameValue[pairNameValue{f.Name, f.Value}]; id != 0 {
			return t.idToIndex(id), true
		}
	}
	if id := t.byName[f.Name]; id != 0 {
		return t.idToIndex(id), false
	}
	return 0, false
}

// idToIndex converts a unique id to an HPACK index.
// See Section 2.3.3.
func (t *headerFieldTable) idToIndex(id uint64) uint64 {
	if id <= t.evictCount {
		panic(fmt.Sprintf("id (%v) <= evictCount (%v)", id, t.evictCount))
	}
	k := id - t.evictCount - 1 // convert id to an index t.ents[k]
	if t != staticTable {
		return uint64(t.len()) - k // dynamic table
	}
	return k + 1
}

func pair(name, value string) HeaderField {
	return HeaderField{Name: name, Value: value}
}

// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-07#appendix-B
var staticTable = newStaticTable()

func newStaticTable() *headerFieldTable {
	t := &headerFieldTable{}
	t.init()
	t.addEntry(pair(":authority", ""))
	t.addEntry(pair(":method", "GET"))
	t.addEntry(pair(":method", "POST"))
	t.addEntry(pair(":path", "/"))
	t.addEntry(pair(":path", "/index.html"))
	t.addEntry(pair(":scheme", "http"))
	t.addEntry(pair(":scheme", "https"))
	t.addEntry(pair(":status", "200"))
	t.addEntry(pair(":status", "204"))
	t.addEntry(pair(":status", "206"))
	t.addEntry(pair(":status", "304"))
	t.addEntry(pair(":status", "400"))
	t.addEntry(pair(":status", "404"))
	t.addEntry(pair(":status", "500"))
	t.addEntry(pair("accept-charset", ""))
	t.addEntry(pair("accept-encoding", "gzip, deflate"))
	t.addEntry(pair("accept-language", ""))
	t.addEntry(pair("accept-ranges", ""))
	t.addEntry(pair("accept", ""))
	t.addEntry(pair("access-control-allow-origin", ""))
	t.addEntry(pair("age", ""))
	t.addEntry(pair("allow", ""))
	t.addEntry(pair("authorization", ""))
	t.addEntry(pair("cache-control", ""))
	t.addEntry(pair("content-disposition", ""))
	t.addEntry(pair("content-encoding", ""))
	t.addEntry(pair("content-language", ""))
	t.addEntry(pair("content-length", ""))
	t.addEntry(pair("content-location", ""))
	t.addEntry(pair("content-range", ""))
	t.addEntry(pair("content-type", ""))
	t.addEntry(pair("cookie", ""))
	t.addEntry(pair("date", ""))
	t.addEntry(pair("etag", ""))
	t.addEntry(pair("expect", ""))
	t.addEntry(pair("expires", ""))
	t.addEntry(pair("from", ""))
	t.addEntry(pair("host", ""))
	t.addEntry(pair("if-match", ""))
	t.addEntry(pair("if-modified-since", ""))
	t.addEntry(pair("if-none-match", ""))
	t.addEntry(pair("if-range", ""))
	t.addEntry(pair("if-unmodified-since", ""))
	t.addEntry(pair("last-modified", ""))
	t.addEntry(pair("link", ""))
	t.addEntry(pair("location", ""))
	t.addEntry(pair("max-forwards", ""))
	t.addEntry(pair("proxy-authenticate", ""))
	t.addEntry(pair("proxy-authorization", ""))
	t.addEntry(pair("range", ""))
	t.addEntry(pair("referer", ""))
	t.addEntry(pair("refresh", ""))
	t.addEntry(pair("retry-after", ""))
	t.addEntry(pair("server", ""))
	t.addEntry(pair("set-cookie", ""))
	t.addEntry(pair("strict-transport-security", ""))
	t.addEntry(pair("transfer-encoding", ""))
	t.addEntry(pair("user-agent", ""))
	t.addEntry(pair("vary", ""))
	t.addEntry(pair("via", ""))
	t.addEntry(pair("www-authenticate", "")) // 69
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", ""))
	t.addEntry(pair("", "")) // 79
	// Cocaine specific headers
	t.addEntry(pair("trace_id", ""))
	t.addEntry(pair("span_id", ""))
	t.addEntry(pair("parent_id", ""))
	return t
}
