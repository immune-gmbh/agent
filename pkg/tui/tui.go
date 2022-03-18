package tui

import (
	"fmt"
	"io"
	"runtime"

	"github.com/mattn/go-colorable"
)

var out io.Writer = io.Discard

func Init() {
	out = colorable.NewColorableStdout()

	if runtime.GOOS == "windows" {
		CheckMark = "o"
		Cross = "x"
	}
}

func printf(format string, a ...interface{}) {
	fmt.Fprintf(out, format, a...)
}
