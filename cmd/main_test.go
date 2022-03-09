package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/gowebpki/jcs"
	test "github.com/immune-gmbh/agent/v3/internal/testing"
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
)

var originalArg0 string = os.Args[0]

func setArgs(args ...string) {
	os.Args = append([]string{originalArg0}, args...)
}

func TestMainValidArgs(t *testing.T) {
	if os.Getenv("SPAWN_EXEC_TEST") == "1" {
		setArgs("-h")
		main()
		return
	}

	// wrap run to intercept os.Exit
	cmd := exec.Command(os.Args[0], "-test.run=TestMainValidArgs")
	cmd.Env = append(os.Environ(), "SPAWN_EXEC_TEST=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		t.Fatalf("Running with valid arg (-h) but got invalid exit code: %v", e)
		return
	}
}

func TestMainInvalidArgs(t *testing.T) {
	if os.Getenv("SPAWN_EXEC_TEST") == "1" {
		setArgs("harryTEST")
		main()
		return
	}

	// wrap run to intercept os.Exit
	cmd := exec.Command(os.Args[0], "-test.run=TestMainInvalidArgs")
	cmd.Env = append(os.Environ(), "SPAWN_EXEC_TEST=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}

	t.Fatal("Running with invalid args but got successful exit")
}

var cfg string = `{"cpuid":[{"leaf_eax":"0","leaf_ecx":"0"},{"leaf_eax":"1","leaf_ecx":"0"},{"leaf_eax":"2147483650","leaf_ecx":"0"},{"leaf_eax":"2147483651","leaf_ecx":"0"},{"leaf_eax":"2147483652","leaf_ecx":"0"},{"leaf_eax":"7","leaf_ecx":"0"},{"leaf_eax":"18","leaf_ecx":"0"},{"leaf_eax":"18","leaf_ecx":"1"},{"leaf_eax":"18","leaf_ecx":"2"},{"leaf_eax":"18","leaf_ecx":"3"},{"leaf_eax":"18","leaf_ecx":"4"},{"leaf_eax":"18","leaf_ecx":"5"},{"leaf_eax":"18","leaf_ecx":"6"},{"leaf_eax":"18","leaf_ecx":"7"},{"leaf_eax":"18","leaf_ecx":"8"},{"leaf_eax":"18","leaf_ecx":"9"},{"leaf_eax":"2147483679","leaf_ecx":"0"}],"keys":{"aik":{"public":"ACMACwAFAHIAAAAQABgACwADABAAAAAA","label":"IMMUNE-GUARD-AIK-V2"}},"me":[{"guid":"8e6a6715-9abc-4043-88ef-9e39c6f63e0f","commands":[{"command":"/wIAAA=="},{"command":"AwIAAA=="}]},{"guid":"309dcde8-ccb1-4062-8f78-600115a34327","commands":[{"command":"HgAAAA=="}]}],"msrs":[{"msr":"158"},{"msr":"254"},{"msr":"498"},{"msr":"499"},{"msr":"58"},{"msr":"23"},{"msr":"3200"},{"msr":"3221291024"}],"pci":[{"bus":"0","device":"0","function":"0"},{"bus":"0","device":"22","function":"0"}],"pcr_bank":11,"pcrs":[0,1,2,3,4,5,6,7,8],"root":{"public":"ACMACwADAHIAAAAGAIAAQwAQAAMAEAAAAAA=","label":"IMMUNE-GUARD-ROOT-KEY-V2"},"sev":[{"command":1,"read_length":12}],"tpm2_nvram":[29425923,25165825,29425922,25165827,29425926,20971521],"tpm2_properties":[{"property":"261"},{"property":"262"},{"property":"263"},{"property":"264"},{"property":"265"},{"property":"257"},{"property":"258"},{"property":"259"},{"property":"260"}],"uefi":[{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"SetupMode"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"AuditMode"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"DeployedMode"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"SecureBoot"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"PK"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"PKDefault"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"KEK"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"KEKDefault"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"db"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"dbDefault"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"dbx"},{"vendor":"8be4df61-93ca-11d2-aa0d-00e098032b8c","name":"dbxDefault"}]}`
var fw string = `{"acpi":{},"cpuid":[],"event_log":{},"flash":{},"mac":{"addrs":null},"me":[],"memory":{},"msrs":[],"os":{"hostname":"example.com","name":"windows"},"pci":[],"sev":null,"smbios":{},"tpm2_nvram":null,"tpm2_properties":null,"txt":{},"uefi":[],"vtd":{}}`

func TestGen(t *testing.T) {
	var config api.Configuration
	err := json.Unmarshal([]byte(cfg), &config)
	if err != nil {
		t.Fatal(err)
	}

	sim := tcg.NewTCGAnchor(test.GetTpmSimulator(t))
	rootHandle, rootPub, err := sim.CreateAndLoadRoot("", "", &config.Root.Public)
	if err != nil {
		t.Fatal(err)
	}
	defer rootHandle.Flush(sim)

	rootName, err := api.ComputeName(tpm2.HandleEndorsement, rootPub)
	if err != nil {
		t.Fatal(err)
	}
	rootBuf, err := tpm2.Name(rootName).Encode()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("fpr: %x\n", rootBuf)

	keyAuth, err := tcg.GenerateAuthValue()
	if err != nil {
		t.Fatal(err)
	}
	key, priv, err := sim.CreateAndCertifyDeviceKey(rootHandle, "", config.Keys["aik"], keyAuth)
	if err != nil {
		t.Fatal(err)
	}
	aikBuf, err := key.Public.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("public: %x\n", aikBuf)
	name, err := api.ComputeName(rootName, key.Public)
	if err != nil {
		t.Fatal(err)
	}
	nameBuf, err := tpm2.Name(name).Encode()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("fpr: %x\n", nameBuf)
	aikHandle, err := sim.LoadDeviceKey(rootHandle, "", key.Public, priv)
	if err != nil {
		t.Fatal(err)
	}

	fwPropsJCS, err := jcs.Transform([]byte(fw))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("jcs", string(fwPropsJCS))
	fwPropsHash := sha256.Sum256(fwPropsJCS)

	// read PCRs
	pcrValues, err := sim.PCRValues(tpm2.Algorithm(config.PCRBank), config.PCRs)
	if err != nil {
		t.Fatal(err)
	}

	pcrBuf, err := json.Marshal(pcrValues)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("pcr: %s\n", string(pcrBuf))

	attest, sig, err := sim.Quote(aikHandle, keyAuth, fwPropsHash[:], tpm2.Algorithm(config.PCRBank), config.PCRs)
	if err != nil {
		t.Fatal(err)
	}

	if sig.ECC == nil && sig.RSA == nil {
		t.Error("sig it neither RSA nor ECC")
	}

	aikHandle.Flush(sim)

	fmt.Printf("quote: %#v\n", attest)
	fmt.Printf("sig: %#v\n", sig)
}
