package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ConfigError wraps a config loading/parsing/validation error with detailed location and hints.
type ConfigError struct {
	Path    string
	Line    int
	Column  int
	Message string
	Hint    string
}

func (e *ConfigError) Error() string {
	loc := ""
	if e.Line > 0 {
		loc = fmt.Sprintf("line %d, column %d: ", e.Line, e.Column)
	}
	msg := fmt.Sprintf("config: %s: %s%s", e.Path, loc, e.Message)
	if e.Hint != "" {
		msg += fmt.Sprintf(" Note: %s.", e.Hint)
	}
	return msg
}

// ValidationErrors collects multiple validation errors.
type ValidationErrors struct {
	Path   string
	Errors []string
}

func (ve *ValidationErrors) Error() string {
	return fmt.Sprintf("config: %s: validation failed:\n  - %s", ve.Path, strings.Join(ve.Errors, "\n  - "))
}

// ReadConfigBytes reads the config file, strips BOMs, converts UTF-16, normalises line endings,
// strips comments outside strings, and removes trailing commas.
func ReadConfigBytes(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var infoNote string
	var utf8Data []byte

	// 1. Detect and strip BOM / encoding
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		utf8Data = raw[3:]
		infoNote = "file has a UTF-8 BOM; it was removed"
	} else if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		// UTF-16 LE
		u16s := make([]uint16, (len(raw)-2)/2)
		for i := 0; i < len(u16s); i++ {
			u16s[i] = uint16(raw[2+2*i]) | uint16(raw[2+2*i+1])<<8
		}
		utf8Data = []byte(string(utf16.Decode(u16s)))
		// Strip BOM if present in decoded text
		if len(utf8Data) >= 3 && utf8Data[0] == 0xEF && utf8Data[1] == 0xBB && utf8Data[2] == 0xBF {
			utf8Data = utf8Data[3:]
		}
		infoNote = "file is UTF-16; it was converted"
	} else if len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
		// UTF-16 BE
		u16s := make([]uint16, (len(raw)-2)/2)
		for i := 0; i < len(u16s); i++ {
			u16s[i] = uint16(raw[2+2*i])<<8 | uint16(raw[2+2*i+1])
		}
		utf8Data = []byte(string(utf16.Decode(u16s)))
		if len(utf8Data) >= 3 && utf8Data[0] == 0xEF && utf8Data[1] == 0xBB && utf8Data[2] == 0xBF {
			utf8Data = utf8Data[3:]
		}
		infoNote = "file is UTF-16; it was converted"
	} else {
		utf8Data = raw
	}

	if !utf8Valid(utf8Data) {
		return nil, "", &ConfigError{Path: path, Message: "file contains invalid UTF-8 bytes"}
	}

	// 2. Normalise line endings (CRLF -> LF)
	norm := normalizeLineEndings(utf8Data)

	// 3. Strip comments and build original offset mapping
	stripped, origMap, commentsRemoved := stripCommentsAndMap(norm)
	if commentsRemoved && infoNote == "" {
		infoNote = "comments were removed"
	}

	// 4. Remove trailing commas before } or ]
	finalBytes := removeTrailingCommas(stripped, origMap)

	return finalBytes, infoNote, nil
}

func utf8Valid(b []byte) bool {
	return utf8.Valid(b)
}

func normalizeLineEndings(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// stripCommentsAndMap strips // and /* */ comments outside string literals,
// and returns the stripped bytes along with an array mapping stripped byte index to original byte index.
func stripCommentsAndMap(raw []byte) ([]byte, []int, bool) {
	var stripped bytes.Buffer
	var origMap []int
	commentsRemoved := false

	inString := false
	escaped := false
	inLineComment := false
	inBlockComment := false

	n := len(raw)
	for i := 0; i < n; {
		c := raw[i]

		if inLineComment {
			if c == '\n' {
				inLineComment = false
				stripped.WriteByte(c)
				origMap = append(origMap, i)
			}
			i++
			continue
		}

		if inBlockComment {
			if i+1 < n && raw[i] == '*' && raw[i+1] == '/' {
				inBlockComment = false
				i += 2
				continue
			}
			i++
			continue
		}

		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			stripped.WriteByte(c)
			origMap = append(origMap, i)
			i++
			continue
		}

		// Check for line comment //
		if i+1 < n && c == '/' && raw[i+1] == '/' {
			commentsRemoved = true
			i += 2
			inLineComment = true
			continue
		}

		// Check for block comment /*
		if i+1 < n && c == '/' && raw[i+1] == '*' {
			commentsRemoved = true
			i += 2
			inBlockComment = true
			continue
		}

		if c == '"' {
			inString = true
		}

		stripped.WriteByte(c)
		origMap = append(origMap, i)
		i++
	}

	return stripped.Bytes(), origMap, commentsRemoved
}

// removeTrailingCommas removes trailing commas before } or ] outside string literals.
func removeTrailingCommas(stripped []byte, origMap []int) []byte {
	var out bytes.Buffer
	n := len(stripped)
	inString := false
	escaped := false

	for i := 0; i < n; i++ {
		c := stripped[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			out.WriteByte(c)
			continue
		}

		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}

		if c == ',' {
			// Check if next non-whitespace/newline is } or ]
			nextIdx := -1
			for j := i + 1; j < n; j++ {
				nc := stripped[j]
				if nc == ' ' || nc == '\t' || nc == '\n' || nc == '\r' {
					continue
				}
				nextIdx = j
				break
			}
			if nextIdx != -1 && (stripped[nextIdx] == '}' || stripped[nextIdx] == ']') {
				// Skip this trailing comma
				continue
			}
		}

		out.WriteByte(c)
	}
	return out.Bytes()
}

// DecodeConfig decodes JSON config bytes into a map.
func DecodeConfig(data []byte) (map[string]interface{}, error) {
	var userConfig map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&userConfig); err != nil {
		return nil, err
	}
	return userConfig, nil
}
