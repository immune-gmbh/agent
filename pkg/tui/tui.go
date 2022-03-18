package tui

import (
	"fmt"
	"io"
	"runtime"

	"github.com/armon/circbuf"
	"github.com/mattn/go-colorable"
)

var (
	Out io.Writer = io.Discard
	Err io.Writer = io.Discard
)

func Init() {
	Out = colorable.NewColorableStdout()
	Err, _ = circbuf.NewBuffer(1024 * 128)

	if runtime.GOOS == "windows" {
		CheckMark = "o"
		Cross = "x"
	}
}

func DumpErr() {
	buf, ok := Err.(*circbuf.Buffer)
	if ok {
		fmt.Print(buf.String())
		buf.Reset()
	}
}

func printf(format string, a ...interface{}) {
	fmt.Fprintf(Out, format, a...)
}
