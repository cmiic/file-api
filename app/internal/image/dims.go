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
	"strconv"
	"strings"
	"unicode"

	"encoding/xml"

	_ "golang.org/x/image/webp" // register webp decoder
)

// ProbeDims sniffs the content type of f and reads the image header to
// extract intrinsic width + height.
//
// Takes an already-open reader rather than a path: the caller opens through
// the storage root, so this cannot be pointed at a file outside it.
//
// Returns (0, 0, nil) for unrecognised types so a probe failure
// degrades gracefully — the caller (upload handler) can then fall
// back to client-supplied form values for backwards compatibility.
//
// Returns a non-nil error only for I/O failures opening / reading the
// file; format-specific decode failures are swallowed (the caller
// already has bytes on disk and can render with a CSS-only aspect
// ratio if dims aren't available).
func ProbeDims(f io.ReadSeeker) (width, height int, err error) {
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
		if start, ok := tok.(xml.StartElement); ok && strings.EqualFold(start.Name.Local, "svg") {
			w, h := svgRootDims(start)
			return w, h, nil
		}
	}
}

// svgRootDims reads the size of an <svg> root element: its width and height
// attributes when both are usable, otherwise its viewBox, otherwise 0x0.
func svgRootDims(root xml.StartElement) (int, int) {
	var width, height, viewBox string
	for _, a := range root.Attr {
		switch strings.ToLower(a.Name.Local) {
		case "width":
			width = a.Value
		case "height":
			height = a.Value
		case "viewbox":
			viewBox = a.Value
		}
	}
	if w, h := parseSvgLen(width), parseSvgLen(height); w > 0 && h > 0 {
		return w, h
	}
	return viewBoxDims(viewBox)
}

// viewBoxDims returns the width and height of a viewBox="min-x min-y width
// height", or 0x0 when it is absent or malformed. The four numbers may be
// separated by whitespace, commas or both, as the SVG grammar allows.
func viewBoxDims(viewBox string) (int, int) {
	parts := strings.FieldsFunc(viewBox, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	if len(parts) != 4 {
		return 0, 0
	}
	vw, errW := strconv.ParseFloat(parts[2], 64)
	vh, errH := strconv.ParseFloat(parts[3], 64)
	// Guard against degenerate viewBoxes ("0 0 -10 -10", "0 0 0.4 0.4"
	// rounding to 0, "0 0 NaN Inf", etc). Anything that can't render as a
	// positive pixel rectangle comes back as (0, 0) so the caller treats it
	// like an unknown format.
	w, h := toPixels(vw), toPixels(vh)
	if errW != nil || errH != nil || w == 0 || h == 0 {
		return 0, 0
	}
	return w, h
}

// maxPixels bounds a probed dimension. Far beyond any real image, and well
// inside int on every platform, so the conversion below is always defined.
const maxPixels = 1 << 30

// toPixels truncates a parsed length to whole pixels, or returns 0 when it is
// not a usable size. strconv.ParseFloat accepts "NaN" and "Inf", NaN fails
// every comparison, and converting NaN, an infinity or an out-of-range value
// to int is implementation-defined in Go, so the bounds are checked as a
// single positive condition that NaN cannot satisfy.
func toPixels(v float64) int {
	if !(v >= 1 && v <= maxPixels) {
		return 0
	}
	return int(v)
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
	return toPixels(v)
}
