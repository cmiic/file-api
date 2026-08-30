// Package image provides server-side image dimension probing.
//
// Used after the bytes are persisted to disk so callers receive
// authoritative width/height that survive a hostile browser hop. The
// stdlib `image/*` DecodeConfig functions read only the header bytes
// (cheap — no full decode), and the WEBP path goes through
// golang.org/x/image/webp's DecodeConfig for the same reason.
//
// Unknown / non-image MIME types (PDF, DOCX, …) return (0, 0, nil) so
// callers can fall back to their previous behaviour silently.
package image

import (
	stdimage "image"
	_ "image/gif"  // register gif decoder
	_ "image/jpeg" // register jpeg decoder
	_ "image/png"  // register png decoder
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"encoding/xml"

	_ "golang.org/x/image/webp" // register webp decoder
)

// ProbeDims opens the file at absPath, sniffs its content type, and
// reads the image header to extract intrinsic width + height.
//
// Returns (0, 0, nil) for unrecognised types so a probe failure
// degrades gracefully — the caller (upload handler) can then fall
// back to client-supplied form values for backwards compatibility.
//
// Returns a non-nil error only for I/O failures opening / reading the
// file; format-specific decode failures are swallowed (the caller
// already has bytes on disk and can render with a CSS-only aspect
// ratio if dims aren't available).
func ProbeDims(absPath string) (width, height int, err error) {
	f, err := os.Open(absPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return 0, 0, err
	}
	head = head[:n]
	contentType := http.DetectContentType(head)

	// Rewind for the format-specific decoder.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}

	switch {
	case strings.HasPrefix(contentType, "image/jpeg"),
		strings.HasPrefix(contentType, "image/png"),
		strings.HasPrefix(contentType, "image/gif"),
		strings.HasPrefix(contentType, "image/webp"):
		cfg, _, decErr := stdimage.DecodeConfig(f)
		if decErr != nil {
			return 0, 0, nil
		}
		return cfg.Width, cfg.Height, nil
	}

	// SVG path: http.DetectContentType reports text/xml for content
	// with an `<?xml` declaration, text/plain for SVGs without one,
	// and image/svg+xml almost never (the stdlib detector has no
	// signature for it). Match on the raw head bytes instead so all
	// three shapes hit the XML parser.
	if strings.Contains(contentType, "xml") || strings.HasPrefix(contentType, "image/svg") || hasSvgRoot(head) {
		return probeSVG(f)
	}

	return 0, 0, nil
}

// hasSvgRoot returns true when the head bytes contain a `<svg`
// element start (allowing for leading whitespace + an optional XML
// declaration). Used as a heuristic when http.DetectContentType
// falls through to text/plain.
func hasSvgRoot(head []byte) bool {
	s := string(head)
	// Skip any UTF-8 BOM (U+FEFF), then leading whitespace.
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.TrimLeft(s, " \t\r\n")
	// An <?xml ... ?> declaration may come first.
	if strings.HasPrefix(s, "<?xml") {
		if end := strings.Index(s, "?>"); end != -1 {
			s = strings.TrimLeft(s[end+2:], " \t\r\n")
		}
	}
	return strings.HasPrefix(s, "<svg") || strings.HasPrefix(s, "<SVG")
}

// probeSVG reads the root <svg> element and resolves dimensions from
// width/height (px-stripped), falling back to the last two viewBox
// components when explicit dims aren't set. Best-effort: returns
// (0, 0, nil) on any parse failure.
func probeSVG(r io.Reader) (int, int, error) {
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err != nil {
			return 0, 0, nil
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if strings.EqualFold(start.Name.Local, "svg") {
			var w, h string
			var viewBox string
			for _, a := range start.Attr {
				switch strings.ToLower(a.Name.Local) {
				case "width":
					w = a.Value
				case "height":
					h = a.Value
				case "viewbox":
					viewBox = a.Value
				}
			}
			wi := parseSvgLen(w)
			hi := parseSvgLen(h)
			if wi > 0 && hi > 0 {
				return wi, hi, nil
			}
			if viewBox != "" {
				parts := strings.Fields(viewBox)
				if len(parts) == 4 {
					vw, errW := strconv.ParseFloat(parts[2], 64)
					vh, errH := strconv.ParseFloat(parts[3], 64)
					// Guard against degenerate viewBoxes ("0 0 -10 -10",
					// "0 0 0.4 0.4" rounding to 0, etc). Anything that
					// can't render as a positive pixel rectangle falls
					// through to (0, 0) so the caller treats it like an
					// unknown format.
					if errW == nil && errH == nil && vw > 0 && vh > 0 {
						return int(vw), int(vh), nil
					}
				}
			}
			return 0, 0, nil
		}
	}
}

func parseSvgLen(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Strip a trailing unit (px / pt / em / …). We only care about
	// the magnitude — SVGs without an explicit unit are pixel-based.
	for i, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != '-' && r != '+' {
			s = s[:i]
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int(v)
}
