package tui

import (
	"fmt"
	"io"

	"github.com/mattn/go-colorable"
)

var out io.Writer = io.Discard

func Init() {
	out = colorable.NewColorableStdout()
}

func printf(format string, a ...interface{}) {
	fmt.Fprintf(out, format, a...)
}
