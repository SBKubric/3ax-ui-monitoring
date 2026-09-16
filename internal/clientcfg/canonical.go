package clientcfg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// RevisionHexLen is how many hex characters of the SHA-256 make up a config
// revision (protocol §4.1).
const RevisionHexLen = 16

// RevisionField is the one field of the document left out of its own hash.
const RevisionField = "configRevision"

// Revision returns the config revision of doc: the first 16 hex characters of
// the SHA-256 of its canonical JSON with configRevision removed (protocol
// §4.1). Whatever doc.ConfigRevision currently holds is ignored.
func Revision(doc Document) (string, error) {
	raw, err := marshalDocument(doc)
	if err != nil {
		return "", err
	}
	return RevisionOf(raw)
}

// RevisionOf returns the config revision of an already encoded document.
//
// The document is parsed and re-emitted rather than hashed as it arrived, so
// that the revision depends on what the document says and not on how it was
// written: key order, insignificant whitespace and the choice of string
// escaping all wash out. That is what makes the revision safe to recompute
// from a stored document, or from a document another component built.
func RevisionOf(document []byte) (string, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", fmt.Errorf("clientcfg: parse document: %w", err)
	}
	if obj, ok := value.(map[string]any); ok {
		delete(obj, RevisionField)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])[:RevisionHexLen], nil
}

// writeCanonical writes v as canonical JSON: object keys sorted, no
// insignificant whitespace, one spelling per value. v is a tree of the types
// encoding/json decodes into with UseNumber.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		buf.WriteString(strconv.FormatBool(t))
		return nil
	case json.Number:
		return writeCanonicalNumber(buf, t)
	case string:
		return writeCanonicalString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		// Sorting the keys as Go strings sorts them by byte, which for UTF-8
		// is the same order as by code point.
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("clientcfg: canonical json: unsupported value of type %T", v)
	}
}

// writeCanonicalString writes s as a JSON string, escaping only what JSON
// requires so that the same text always produces the same bytes.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("clientcfg: canonical json: encode string: %w", err)
	}
	// Encode appends a newline; the canonical form has no whitespace.
	buf.Truncate(buf.Len() - 1)
	return nil
}

// writeCanonicalNumber writes n in one spelling: integers as integers,
// anything else as the shortest float64 that reads back the same. The document
// only ever carries integers, so this exists to keep the canonicaliser total
// rather than to serve a case mon-server produces.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	if i, err := n.Int64(); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("clientcfg: canonical json: number %q: %w", n.String(), err)
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}
