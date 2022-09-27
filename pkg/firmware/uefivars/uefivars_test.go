//go:build linux
// +build linux

package uefivars

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/immune-gmbh/agent/v3/pkg/api"
)

type scenario struct {
	Guid      uuid.UUID
	Variables []string
	Contents  [][]byte
	Tempdir   string
}

func (s *scenario) UEFIVariable(t *testing.T) api.UEFIVariable {
	if len(s.Variables) == 0 {
		t.Fatal("no UEFI vars in scenario")
	}

	return api.UEFIVariable{
		Vendor: s.Guid.String(),
		Name:   s.Variables[len(s.Variables)-1],
		Value:  (*api.Buffer)(&s.Contents[len(s.Variables)-1]),
	}
}

type WithoutCanary struct{}

func setupUefiVariables(t *testing.T, opts ...interface{}) scenario {
	tmpdir, err := os.MkdirTemp("", "agent-efi-test")
	if err != nil {
		t.Fatal(err)
	}
	oldEfivars := efivars
	efivars = tmpdir
	t.Cleanup(func() { efivars = oldEfivars; os.RemoveAll(tmpdir) })

	guid, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}

	includeCanary := true

	for _, opt := range opts {
		switch opt.(type) {
		case WithoutCanary:
			includeCanary = false
		}
	}

	if includeCanary {
		buf := []byte{0, 0, 0, 0}
		err := os.WriteFile(path.Join(tmpdir, "ConOut-8be4df61-93ca-11d2-aa0d-00e098032b8c"), buf, 0640)
		if err != nil {
			t.Fatal(err)
		}
	}

	return scenario{
		Guid:      guid,
		Variables: []string{},
		Tempdir:   tmpdir,
	}
}

type WithContents struct {
	Value []byte
}

func (s *scenario) setupUefiVariable(t *testing.T, name string, opts ...interface{}) {
	var buf []byte

	for _, opt := range opts {
		switch opt.(type) {
		case WithContents:
			buf = opt.(WithContents).Value
		}
	}

	s.Variables = append(s.Variables, name)
	s.Contents = append(s.Contents, buf)

	buf = append([]byte{0, 0, 0, 0}, buf...)
	err := os.WriteFile(path.Join(s.Tempdir, fmt.Sprintf("%s-%s", name, s.Guid)), buf, 0640)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadVar(t *testing.T) {
	buf := []byte{'t', 'e', 's', 't'}

	// scenario
	sc := setupUefiVariables(t)
	sc.setupUefiVariable(t, "TestVar", WithContents{Value: buf})
	uefiVar := sc.UEFIVariable(t)

	// test
	uefiVars := []api.UEFIVariable{uefiVar}
	err := ReportUEFIVariables(uefiVars)
	if err != nil {
		t.Error(err)
	}
	if uefiVars[0].Error != "" {
		t.Error(uefiVars[0].Error)
	}
	if !bytes.Equal(buf, *uefiVars[0].Value) {
		t.Errorf("wrong var contents. want: %x, got: %x", buf, *uefiVars[0].Value)
	}
}

func TestReadNonExistent(t *testing.T) {
	// scenario
	sc := setupUefiVariables(t)
	sc.setupUefiVariable(t, "TestVar")
	uefiVar1 := sc.UEFIVariable(t)

	// test
	uefiVar2 := api.UEFIVariable{
		Vendor: sc.Guid.String(),
		Name:   "FooVar",
	}
	uefiVars := []api.UEFIVariable{uefiVar1, uefiVar2}
	err := ReportUEFIVariables(uefiVars)
	if err != nil {
		t.Error(err)
	}
	if uefiVars[0].Error != "" {
		t.Error(uefiVars[0].Error)
	}
	if uefiVars[1].Error != api.NoResponse {
		t.Errorf("expected no-resp, got '%s'", uefiVars[1].Error)
	}
}

func TestHasVar(t *testing.T) {
	_ = setupUefiVariables(t)
	if !hasUEFIVariables() {
		t.Error("expected true")
	}
}

func TestHasNoVar(t *testing.T) {
	// scenario
	sc := setupUefiVariables(t, WithoutCanary{})
	sc.setupUefiVariable(t, "TestVar")
	uefiVar := sc.UEFIVariable(t)

	// test
	uefiVars := []api.UEFIVariable{uefiVar}
	err := ReportUEFIVariables(uefiVars)
	if err != nil {
		t.Error(err)
	}
	if uefiVars[0].Error != api.NotImplemented {
		t.Errorf("expected not-impl got '%s'", uefiVars[0].Error)
	}
}
