package utils

import (
	"bytes"
)

const (
	baseSz = 8
	sizeY  = baseSz + 1
	sizeX  = baseSz*2 + 1
)

func FingerprintRandomArt(head string, digest []byte) []byte {
	dict := " .o+=*BOX@%&#/^SE"
	dictLen := len(dict) - 2
	startSym := dictLen
	endSym := dictLen + 1

	field := make([]int, sizeX*sizeY)

	x := sizeX / 2
	y := sizeY / 2

	for _, input := range digest {
		for range 4 {
			if input&0x1 != 0 {
				x += 1
			} else {
				x -= 1
			}
			if input&0x2 != 0 {
				y += 1
			} else {
				y -= 1
			}

			if x < 0 {
				x = 0
			}
			if y < 0 {
				y = 0
			}
			if x > sizeX-1 {
				x = sizeX - 1
			}
			if y > sizeY-1 {
				y = sizeY - 1
			}

			idx := x + y*sizeX
			if field[idx] < dictLen-1 {
				field[idx]++
			}
			input = input >> 2
		}
	}

	/* mark starting point and end point*/
	field[sizeX/2+(sizeY/2)*sizeX] = startSym
	field[x+y*sizeX] = endSym

	var out bytes.Buffer
	if head != "" {
		if len(head) > sizeX {
			head = head[:sizeX]
		}
		hPadL := (sizeX - len(head)) / 2
		hPadR := sizeX - len(head) - hPadL
		if hPadL != 0 {
			out.WriteRune('+')
			for range hPadL - 1 {
				out.WriteRune('-')
			}
		}
		out.WriteRune('[')
		out.WriteString(head)
		out.WriteRune(']')
		if hPadR != 0 {
			for range hPadR - 1 {
				out.WriteRune('-')
			}
			out.WriteRune('+')
		}
	} else {
		out.WriteRune('+')
		for range sizeX - 2 {
			out.WriteRune('-')
		}
		out.WriteRune('+')
	}
	out.WriteRune('\n')
	i := 0
	for range sizeY {
		out.WriteRune('|')
		for range sizeX {
			out.WriteRune(rune(dict[field[i]]))
			i++
		}
		out.WriteRune('|')
		out.WriteRune('\n')
	}
	out.WriteRune('+')
	for range sizeX {
		out.WriteRune('-')
	}
	out.WriteRune('+')
	out.WriteRune('\n')

	return out.Bytes()
}
