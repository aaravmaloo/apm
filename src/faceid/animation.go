//go:build faceid

package faceid

import (
	"fmt"
	"time"
)

const (
	colorReset     = "\033[0m"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorYellow    = "\033[33m"
	colorDimGray   = "\033[90m"
	colorBoldGreen = "\033[1;32m"
	colorBoldRed   = "\033[1;31m"
	cursorUp       = "\033[%dA"
	clearLine      = "\033[2K"
)

func PlaySuccessAnimation() {
	frame1 := fmt.Sprintf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   %s[  FACE  ]%s   │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorDimGray, colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
	)
	fmt.Print(frame1)
	time.Sleep(100 * time.Millisecond)

	clearAnimationArea(5)
	frame2 := fmt.Sprintf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   %s[ ···SCAN···]%s  │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorYellow, colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
	)
	fmt.Print(frame2)
	time.Sleep(200 * time.Millisecond)

	clearAnimationArea(5)
	frame3 := fmt.Sprintf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   %s[  ✓ FACE  ]%s  │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorGreen, colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
	)
	fmt.Print(frame3)
	time.Sleep(200 * time.Millisecond)

	clearAnimationArea(5)
	fmt.Printf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   ✓  Unlocked   │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n"+
			"  %sVault unlocked via Face ID%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorBoldGreen, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorBoldGreen, colorReset,
	)
}

func PlayScanningState() {
	fmt.Printf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   %s[ ···SCAN···]%s  │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorYellow, colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
	)
}

func PlayFailureAnimation() {
	clearAnimationArea(5)
	fmt.Printf(
		"%s┌─────────────────┐%s\n"+
			"%s│                 │%s\n"+
			"%s│   ✗  No Match   │%s\n"+
			"%s│                 │%s\n"+
			"%s└─────────────────┘%s\n",
		colorDimGray, colorReset,
		colorDimGray, colorReset,
		colorBoldRed, colorReset,
		colorDimGray, colorReset,
		colorDimGray, colorReset,
	)
	time.Sleep(500 * time.Millisecond)
	clearAnimationArea(5)
}

func clearAnimationArea(lines int) {
	for i := 0; i < lines; i++ {
		fmt.Print(fmt.Sprintf(cursorUp, 1))
		fmt.Print(clearLine)
	}
}
