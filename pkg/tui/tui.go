package tui

import (
	"fmt"
	"io"
	"runtime"

	"github.com/armon/circbuf"
	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
)

var (
	Out io.Writer = io.Discard
	Err io.Writer = io.Discard
)

func Init(noColor bool) {
	Out = colorable.NewColorableStdout()
	Err, _ = circbuf.NewBuffer(1024 * 128)
	color.Output = Out
	color.Error = Err
	color.NoColor = noColor

	if runtime.GOOS == "windows" {
		CheckMark = "o"
		Cross = "x"
	}
}

func DumpErr() {
	buf, ok := Err.(*circbuf.Buffer)
	if ok {
		fmt.Fprint(Out, buf.String())
		buf.Reset()
	}
}

func printf(format string, a ...interface{}) {
	fmt.Fprintf(Out, format, a...)
}
