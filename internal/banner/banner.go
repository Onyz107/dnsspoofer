package banner

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/common-nighthawk/go-figure"
)

func PrintBanner(text, version string) {
	randomFont := fonts[rand.Intn(len(fonts))]
	fig := figure.NewColorFigure(text, randomFont, "purple", true)

	lines := fig.Slicify()

	fmt.Println()
	var banner strings.Builder
	maxWidth := 0
	for _, line := range lines {
		if len(line) > maxWidth {
			maxWidth = len(line)
		}
		coloredLine := bold + purple + line + reset
		banner.WriteString(coloredLine + "\n")
	}
	bannerStr := banner.String()
	fmt.Print(bannerStr)
	fmt.Println(strings.Repeat(" ", maxWidth), version)
	fmt.Println()
	fmt.Println()
}
