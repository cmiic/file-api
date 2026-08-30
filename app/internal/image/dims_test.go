package image

import (
	"bytes"
	stdimage "image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, name string, payload []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func encodeJPEG(t *testing.T, w, h int) []byte {
	img := stdimage.NewRGBA(stdimage.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

func encodePNG(t *testing.T, w, h int) []byte {
	img := stdimage.NewNRGBA(stdimage.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func encodeGIF(t *testing.T, w, h int) []byte {
	img := stdimage.NewPaletted(stdimage.Rect(0, 0, w, h), color.Palette{color.Black, color.White})
	var buf bytes.Buffer
	if err := gif.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode gif: %v", err)
	}
	return buf.Bytes()
}

func TestProbeDims_JPEG(t *testing.T) {
	p := writeFixture(t, "f.jpg", encodeJPEG(t, 300, 200))
	w, h, err := ProbeDims(p)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if w != 300 || h != 200 {
		t.Fatalf("dims = %dx%d, want 300x200", w, h)
	}
}

func TestProbeDims_PNG(t *testing.T) {
	p := writeFixture(t, "f.png", encodePNG(t, 64, 128))
	w, h, _ := ProbeDims(p)
	if w != 64 || h != 128 {
		t.Fatalf("dims = %dx%d, want 64x128", w, h)
	}
}

func TestProbeDims_GIF(t *testing.T) {
	p := writeFixture(t, "f.gif", encodeGIF(t, 10, 20))
	w, h, _ := ProbeDims(p)
	if w != 10 || h != 20 {
		t.Fatalf("dims = %dx%d, want 10x20", w, h)
	}
}

func TestProbeDims_SVG_WidthHeight(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200px" height="50">
  <rect width="200" height="50" fill="red"/>
</svg>`)
	p := writeFixture(t, "f.svg", body)
	w, h, _ := ProbeDims(p)
	if w != 200 || h != 50 {
		t.Fatalf("dims = %dx%d, want 200x50", w, h)
	}
}

func TestProbeDims_SVG_ViewBoxFallback(t *testing.T) {
	body := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100"></svg>`)
	p := writeFixture(t, "vb.svg", body)
	w, h, _ := ProbeDims(p)
	if w != 400 || h != 100 {
		t.Fatalf("dims = %dx%d, want 400x100 (viewBox)", w, h)
	}
}

func TestProbeDims_UnknownFormat(t *testing.T) {
	// A PDF magic header — recognised by http.DetectContentType but
	// not by any of our image decoders. Probe should return 0/0
	// silently so the caller falls back to form-supplied dims.
	body := []byte("%PDF-1.4\n%??\n1 0 obj\n<</Type/Catalog>>\nendobj\n")
	p := writeFixture(t, "f.pdf", body)
	w, h, err := ProbeDims(p)
	if err != nil {
		t.Fatalf("probe pdf: %v", err)
	}
	if w != 0 || h != 0 {
		t.Fatalf("dims = %dx%d, want 0x0 for unrecognised format", w, h)
	}
}

func TestProbeDims_MissingFile(t *testing.T) {
	if _, _, err := ProbeDims("/no/such/file.jpg"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}
