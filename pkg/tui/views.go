package tui

import (
	"fmt"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
)

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
		status = FailureStyle("VULNERABLE")
	}
	printf("\nThis device is %s.\n", status)
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
		status = SuccessStyle("+")
	} else {
		status = FailureStyle("+")
	}
	printf("[%s] %s\n", status, message)
}

func showSpinner(message string) {
	if haveSpinner() {
		killSpinner()
	}

	step = new(Spinner)
	step.Current = message
	step.Spinner = spinner.New(spinner.CharSets[9], 100*time.Millisecond, spinner.WithWriter(out))
	step.Spinner.Prefix = "["
	step.Spinner.Suffix = fmt.Sprintf("] %s", step.Current)
	step.Spinner.Start()
}
