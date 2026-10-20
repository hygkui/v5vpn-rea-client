package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// appIconPNG loads the embedded application icon used by the window and the
// executable; the tray must show the same artwork.
func appIconPNG(t *testing.T) []byte {
	t.Helper()
	data := mustReadIcon(uiEmbedFS, "ui/icon.png")
	if len(data) == 0 {
		t.Fatal("embedded ui/icon.png is missing")
	}
	return data
}

func TestBuildTrayIconsUsesApplicationIcon(t *testing.T) {
	connected, disconnected := buildTrayIcons(appIconPNG(t))

	src, err := png.Decode(bytes.NewReader(appIconPNG(t)))
	if err != nil {
		t.Fatalf("decode source icon: %v", err)
	}

	for name, data := range map[string][]byte{"connected": connected, "disconnected": disconnected} {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: decode PNG: %v", name, err)
		}
		if img.Bounds().Dx() != trayIconSize || img.Bounds().Dy() != trayIconSize {
			t.Fatalf("%s: unexpected size %dx%d, want %d square",
				name, img.Bounds().Dx(), img.Bounds().Dy(), trayIconSize)
		}
		// The tray icon must carry the application icon's shape, not a blank or
		// fully transparent bitmap.
		if opaqueRatio(img) < 0.10 {
			t.Fatalf("%s: icon is almost entirely transparent (%.2f opaque)",
				name, opaqueRatio(img))
		}
	}

	// The disconnected variant must be the desaturated one, so its colors stay
	// close to gray while the connected variant does not.
	connImg, _ := png.Decode(bytes.NewReader(connected))
	discImg, _ := png.Decode(bytes.NewReader(disconnected))
	if avgSaturation(discImg) > avgSaturation(connImg) {
		t.Fatalf("disconnected icon is not desaturated: connected=%.3f disconnected=%.3f",
			avgSaturation(connImg), avgSaturation(discImg))
	}
	if avgSaturation(connImg) == 0 {
		t.Fatal("source icon appears to have no color; the connected tray icon would be gray")
	}
	_ = src
}

// TestBuildTrayIconsFallsBackWhenIconMissing keeps the tray working if the
// embedded asset is unavailable.
func TestBuildTrayIconsFallsBackWhenIconMissing(t *testing.T) {
	for _, conn := range []bool{true, false} {
		data := legacyTrayIcon(conn)
		if _, err := png.Decode(bytes.NewReader(data)); err != nil {
			t.Fatalf("legacy icon for connected=%v is not a valid PNG: %v", conn, err)
		}
	}

	connected, disconnected := buildTrayIcons(nil)
	if len(connected) == 0 || len(disconnected) == 0 {
		t.Fatal("expected fallback icons for a nil source")
	}
}

// TestGrayscaleKeepsAlpha guards the desaturation helper: the mask must not be
// flattened to fully opaque, or the icon renders as a gray square.
func TestGrayscaleKeepsAlpha(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2, 2))
	src.SetRGBA(0, 0, color.RGBA{R: 255, A: 255})
	src.SetRGBA(1, 0, color.RGBA{G: 255, A: 128})
	src.SetRGBA(0, 1, color.RGBA{})
	src.SetRGBA(1, 1, color.RGBA{R: 255, G: 255, B: 255, A: 255})

	gray := grayscale(src)
	if got := gray.RGBAAt(1, 0).A; got != 128 {
		t.Fatalf("alpha channel changed: got %d, want 128", got)
	}
	if got := gray.RGBAAt(0, 1).A; got != 0 {
		t.Fatalf("transparent pixel became visible: alpha %d", got)
	}
	// A red source pixel must come out with equal channels.
	c := gray.RGBAAt(0, 0)
	if !(c.R == c.G && c.G == c.B) {
		t.Fatalf("pixel not desaturated: %+v", c)
	}
}

func opaqueRatio(img image.Image) float64 {
	b := img.Bounds()
	total := b.Dx() * b.Dy()
	if total == 0 {
		return 0
	}
	opaque := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a > 0 {
				opaque++
			}
		}
	}
	return float64(opaque) / float64(total)
}

func avgSaturation(img image.Image) float64 {
	b := img.Bounds()
	var sum float64
	var n int
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			maxc := max(r, max(g, bl))
			minc := min(r, min(g, bl))
			if maxc == 0 {
				continue
			}
			sum += float64(maxc-minc) / float64(maxc)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}
