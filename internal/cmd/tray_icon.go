package main

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

// trayIconSize is the system-tray bitmap size. 64px stays crisp on high-DPI
// trays while remaining small enough for the notification area.
const trayIconSize = 64

// buildTrayIcons derives the tray bitmaps from the application icon so the tray
// shows the same shield as the window and the executable.
//
// connected=true returns the untouched artwork; connected=false returns a
// desaturated copy, which is the "not connected" affordance. Decoding happens
// once at startup; the caller keeps both buffers and swaps them on status
// changes.
func buildTrayIcons(appIconPNG []byte) (connected, disconnected []byte) {
	src, err := png.Decode(bytes.NewReader(appIconPNG))
	if err != nil || src == nil {
		// Fall back to the drawn emblem when the embedded artwork is missing.
		return legacyTrayIcon(true), legacyTrayIcon(false)
	}

	scaled := scaleDown(src, trayIconSize, trayIconSize)
	connected = encodePNG(scaled)
	disconnected = encodePNG(grayscale(scaled))
	return connected, disconnected
}

// scaleDown resizes with area-averaging sampling. This delivers smooth,
// anti-aliased contours without jagged edges when downscaling high-resolution
// application artwork to system tray dimensions.
func scaleDown(src image.Image, w, h int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	b := src.Bounds()
	srcW := b.Dx()
	srcH := b.Dy()
	if srcW == 0 || srcH == 0 {
		return dst
	}

	for dy := 0; dy < h; dy++ {
		sy0 := b.Min.Y + dy*srcH/h
		sy1 := b.Min.Y + (dy+1)*srcH/h
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for dx := 0; dx < w; dx++ {
			sx0 := b.Min.X + dx*srcW/w
			sx1 := b.Min.X + (dx+1)*srcW/w
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}

			var rSum, gSum, bSum, aSum uint64
			var count uint64
			for py := sy0; py < sy1; py++ {
				for px := sx0; px < sx1; px++ {
					pr, pg, pb, pa := src.At(px, py).RGBA()
					rSum += uint64(pr)
					gSum += uint64(pg)
					bSum += uint64(pb)
					aSum += uint64(pa)
					count++
				}
			}
			if count > 0 {
				avgA := aSum / count
				if avgA == 0 {
					dst.SetRGBA(dx, dy, color.RGBA{})
				} else {
					avgR := (rSum / count) * 0xffff / avgA
					avgG := (gSum / count) * 0xffff / avgA
					avgB := (bSum / count) * 0xffff / avgA
					if avgR > 0xffff {
						avgR = 0xffff
					}
					if avgG > 0xffff {
						avgG = 0xffff
					}
					if avgB > 0xffff {
						avgB = 0xffff
					}
					dst.SetRGBA(dx, dy, color.RGBA{
						R: uint8(avgR >> 8),
						G: uint8(avgG >> 8),
						B: uint8(avgB >> 8),
						A: uint8(avgA >> 8),
					})
				}
			}
		}
	}
	return dst
}

// grayscale renders the artwork in muted gray while keeping the alpha channel,
// so the shape stays recognizable but reads as inactive.
func grayscale(src *image.RGBA) *image.RGBA {
	dst := image.NewRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Src)
	b := dst.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := dst.RGBAAt(x, y)
			if c.A == 0 {
				continue
			}
			// Rec. 601 luma, blended toward a mid gray so dark artwork stays
			// visible on both light and dark taskbars.
			luma := (299*uint32(c.R) + 587*uint32(c.G) + 114*uint32(c.B)) / 1000
			v := uint8(96 + luma*3/5)
			dst.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: c.A})
		}
	}
	return dst
}

func encodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// legacyTrayIcon is the previously drawn emblem, kept as a fallback for when
// the embedded icon cannot be decoded.
func legacyTrayIcon(connected bool) []byte {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	var primaryColor color.RGBA
	if connected {
		primaryColor = color.RGBA{R: 16, G: 185, B: 129, A: 255} // #10B981
	} else {
		primaryColor = color.RGBA{R: 2, G: 132, B: 199, A: 255} // #0284C7
	}
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}

	for y := 2; y < size-2; y++ {
		for x := 2; x < size-2; x++ {
			dx := 0
			if x < 6 {
				dx = 6 - x
			} else if x > size-7 {
				dx = x - (size - 7)
			}
			dy := 0
			if y < 6 {
				dy = 6 - y
			} else if y > size-7 {
				dy = y - (size - 7)
			}
			if dx*dx+dy*dy <= 20 {
				img.Set(x, y, primaryColor)
			}
		}
	}

	for t := 0; t <= 13; t++ {
		lx := 8 + t/2
		ly := 9 + t
		img.Set(lx, ly, white)
		img.Set(lx+1, ly, white)
		img.Set(lx-1, ly, white)

		rx := 24 - t/2
		ry := 9 + t
		img.Set(rx, ry, white)
		img.Set(rx+1, ry, white)
		img.Set(rx-1, ry, white)
	}

	return encodePNG(img)
}
