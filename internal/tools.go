// +build tools

// dummy package to pull in build dependencies
// it is necessary for tools that can not be installed using the
// current go install pkg@version syntax, which is true for tools
// that have a replace directive inside their go.mod
package tools

import (
	_ "github.com/immune-gmbh/go-licenses"
)
