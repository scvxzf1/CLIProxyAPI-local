package util

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// inplaceJSONOpts prefers in-place replacement for existing paths so multi-megabyte
// payloads (especially image base64) are not fully rewritten on every field update.
var inplaceJSONOpts = &sjson.Options{Optimistic: true, ReplaceInPlace: true}

// SetJSONBytes sets a JSON path, preferring in-place updates when the path already exists.
func SetJSONBytes(body []byte, path string, value any) []byte {
	if len(body) == 0 || strings.TrimSpace(path) == "" {
		return body
	}
	if gjson.GetBytes(body, path).Exists() {
		updated, err := sjson.SetBytesOptions(body, path, value, inplaceJSONOpts)
		if err == nil {
			return updated
		}
	}
	updated, err := sjson.SetBytes(body, path, value)
	if err != nil {
		return body
	}
	return updated
}

// SetJSONRawBytes sets a raw JSON value at path, preferring in-place updates.
func SetJSONRawBytes(body []byte, path string, raw []byte) []byte {
	if len(body) == 0 || strings.TrimSpace(path) == "" {
		return body
	}
	if gjson.GetBytes(body, path).Exists() {
		updated, err := sjson.SetRawBytesOptions(body, path, raw, inplaceJSONOpts)
		if err == nil {
			return updated
		}
	}
	updated, err := sjson.SetRawBytes(body, path, raw)
	if err != nil {
		return body
	}
	return updated
}

// DeleteJSONBytes deletes a path only when it exists, avoiding full rewrites for no-ops.
func DeleteJSONBytes(body []byte, path string) []byte {
	if len(body) == 0 || strings.TrimSpace(path) == "" {
		return body
	}
	if !gjson.GetBytes(body, path).Exists() {
		return body
	}
	updated, err := sjson.DeleteBytes(body, path)
	if err != nil {
		return body
	}
	return updated
}

// JoinJSONRawMessages joins already-encoded JSON values into a JSON array without
// re-marshaling each item. This keeps large base64 blobs byte-identical and cheap.
func JoinJSONRawMessages(items [][]byte) []byte {
	if len(items) == 0 {
		return []byte("[]")
	}
	var b bytes.Buffer
	b.Grow(2 + len(items))
	b.WriteByte('[')
	wrote := false
	for _, item := range items {
		item = bytes.TrimSpace(item)
		if len(item) == 0 {
			continue
		}
		if wrote {
			b.WriteByte(',')
		}
		b.Write(item)
		wrote = true
	}
	b.WriteByte(']')
	return b.Bytes()
}

// MergeJSONArrayRaw concatenates two JSON arrays without re-encoding item contents.
// Empty/missing arrays are treated as []. Invalid JSON arrays return an error.
func MergeJSONArrayRaw(existingRaw, appendRaw string) (string, error) {
	existingRaw = strings.TrimSpace(existingRaw)
	appendRaw = strings.TrimSpace(appendRaw)
	if existingRaw == "" {
		existingRaw = "[]"
	}
	if appendRaw == "" {
		appendRaw = "[]"
	}

	existing := gjson.Parse(existingRaw)
	appendItems := gjson.Parse(appendRaw)
	if !existing.IsArray() {
		return "", fmt.Errorf("existing value is not a json array")
	}
	if !appendItems.IsArray() {
		return "", fmt.Errorf("append value is not a json array")
	}
	if existingRaw == "[]" {
		return appendRaw, nil
	}
	if appendRaw == "[]" {
		return existingRaw, nil
	}

	// Strip surrounding brackets and join the raw item streams. Item payloads
	// (including multi-megabyte image data URLs) are left untouched.
	existingInner := strings.TrimSpace(existingRaw[1 : len(existingRaw)-1])
	appendInner := strings.TrimSpace(appendRaw[1 : len(appendRaw)-1])
	if existingInner == "" {
		return appendRaw, nil
	}
	if appendInner == "" {
		return existingRaw, nil
	}
	return "[" + existingInner + "," + appendInner + "]", nil
}
