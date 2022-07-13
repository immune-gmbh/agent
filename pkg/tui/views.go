package tui

import (
	"fmt"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
)

var chainTexts []string = []string{
	"Supply Chain",
	"Configuration",
	"Firmware",
	"Bootloader",
	"Operating System",
	"Endpoint Protection",
}

const eppStep = 5

type Spinner struct {
	Spinner  *spinner.Spinner
	Current  string
	Callback func(string)
}

var step *Spinner

// styles
var (
	InfoStyle    = color.New(color.FgCyan, color.BgBlack, color.Bold).SprintFunc()
	SuccessStyle = color.New(color.FgGreen, color.BgBlack, color.Bold).SprintFunc()
	FailureStyle = color.New(color.FgRed, color.BgBlack, color.Bold).SprintFunc()
	LinkStyle    = color.New(color.Underline).SprintFunc()
)

// platform dependent strings
var (
	CheckMark = "✔"
	Cross     = "✘"
)

func haveSpinner() bool {
	return step != nil && step.Spinner != nil
}

func killSpinner() {
	step.Spinner.Stop()
	step = nil
}

func showTrust(trusted bool) {
	var status string
	if trusted {
		status = SuccessStyle("TRUSTED")
	} else {
		status = FailureStyle("UNTRUSTED")
	}
	printf("\n >> This device is %s <<\n", status)
}

func completeLastStep(success bool) {
	if haveSpinner() {
		showStepDone(step.Current, success)
	}
}

func showStepDone(message string, success bool) {
	if haveSpinner() {
		killSpinner()
	}

	var status string
	if success {
		status = SuccessStyle(CheckMark)
	} else {
		status = FailureStyle(Cross)
	}
	printf("[%s] %s\n", status, message)
}

func showSpinner(message string) {
	if haveSpinner() {
		killSpinner()
	}

	step = new(Spinner)
	step.Current = message
	step.Spinner = spinner.New(spinner.CharSets[9], 100*time.Millisecond, spinner.WithWriter(Out))
	step.Spinner.Prefix = "["
	step.Spinner.Suffix = fmt.Sprintf("] %s", step.Current)
	step.Spinner.Start()
}

func renderChainElement(first, odd, enabled, fail bool, text string) {
	color.Set(color.BgBlack)

	if !enabled {
		color.Set(color.FgWhite)
	} else {
		if fail {
			color.Set(color.FgRed)
		} else {
			color.Set(color.FgGreen)
		}
	}

	var pre string
	if odd {
		pre = " "
	}

	if first {
		fmt.Println(pre + " __")
	}

	fmt.Print(pre + "/  \\")

	if !enabled {
		color.Set(color.FgWhite)
	} else {
		if fail {
			color.Set(color.FgRed)
		} else {
			color.Set(color.FgGreen)
		}
	}

	color.Set(color.FgWhite)

	if odd {
		fmt.Print("... ")
	} else {
		fmt.Print(".... ")
	}

	if !enabled {
		color.Set(color.FgWhite)
		fmt.Print("o ")
	} else {
		if fail {
			color.Set(color.FgHiRed)
			fmt.Print(Cross + " ")
		} else {
			color.Set(color.FgHiGreen)
			fmt.Print(CheckMark + " ")
		}
	}

	color.Set(color.FgHiWhite)
	fmt.Println(text)

	if !enabled {
		color.Set(color.FgWhite)
	} else {
		if fail {
			color.Set(color.FgRed)
		} else {
			color.Set(color.FgGreen)
		}
	}

	fmt.Println(pre + "\\__/")
}

func showTrustChain(failAt int, tscSupported, eppSupported bool) {
	renderChainElement(true, false, tscSupported, failAt == 0, chainTexts[0])
	for i := 1; i < len(chainTexts); i++ {
		eppEnabled := true
		if i == eppStep {
			eppEnabled = eppSupported
		}
		renderChainElement(false, i&1 == 1, eppEnabled, i >= failAt, chainTexts[i])
	}
	color.Unset()
}

func ShowAppraisalLink(link string) {
	if link != "" {
		printf("\nSee detailed results here:\n%s\n", LinkStyle(link))
	}
}
