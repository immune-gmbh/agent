package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"

	test "github.com/immune-gmbh/agent/v2/internal/testing"
)

func TestEncodeEmptyBuffer(t *testing.T) {
	buf1, err := json.Marshal(Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if string(buf1) != `""` {
		t.Fatalf("json serialization of empty Buffer is not the empty string")
	}
}

func TestDecodeEmptyBuffer(t *testing.T) {
	var buf1 Buffer
	err := json.Unmarshal([]byte(`""`), &buf1)
	if err != nil {
		t.Fatal(err)
	}

	if len(buf1) != 0 {
		t.Fatalf("an empty string does not deserialize to the empty buffer")
	}
}

func TestBufferPropTest(t *testing.T) {
	f := func(buf1 Buffer) bool {
		dat, err := json.Marshal(buf1)
		if err != nil {
			t.Fatal(err)
		}

		var buf2 Buffer
		err = json.Unmarshal(dat, &buf2)
		if err != nil {
			t.Fatal(err)
		}

		return bytes.Equal(buf1, buf2)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestQName(t *testing.T) {
	rng := rand.New(rand.NewSource(int64(os.Getpid())))
	root := PublicKey(GeneratePublic(rng))
	pub := PublicKey(GeneratePublic(rng))

	rootName, err := ComputeName(root)
	if err != nil {
		t.Fatal(err)
	}
	rootQN, err := ComputeName(tpm2.HandleEndorsement, root)
	if err != nil {
		t.Fatal(err)
	}

	pubName, err := ComputeName(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQN, err := ComputeName(tpm2.HandleEndorsement, root, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQNbuf, err := tpm2.Name(pubQN).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN2, err := ComputeName(rootQN, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQN2buf, err := tpm2.Name(pubQN2).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN3, err := ComputeName(tpm2.HandleEndorsement, rootName, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQN3buf, err := tpm2.Name(pubQN3).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN4, err := ComputeName(tpm2.HandleEndorsement, rootName, pubName)
	if err != nil {
		t.Fatal(err)
	}
	pubQN4buf, err := tpm2.Name(pubQN4).Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("QName(Handle, public, public) %x\n", pubQNbuf)
	fmt.Printf("QName(QN, public)             %x\n", pubQN2buf)
	fmt.Printf("QName(Handle, name, public)   %x\n", pubQN3buf)
	fmt.Printf("QName(Handle, name, name)     %x\n", pubQN4buf)

	if !reflect.DeepEqual(pubQNbuf, pubQN2buf) {
		t.Fatal("QName(Handle, public, public) != QName(QN, public)")
	}
	if !reflect.DeepEqual(pubQN2buf, pubQN3buf) {
		t.Fatal("QName(QN, public) != QName(Handle, name, public)")
	}
	if !reflect.DeepEqual(pubQN3buf, pubQN4buf) {
		t.Fatal("QName(Handle, name, public) != QName(Handle, name, name)")
	}
}

func TestQNameIntegration(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping integration test")
	}

	conn := test.GetTpmSimulator(t)
	defer tpm2tools.CheckedClose(t, conn)

	// TPM2_CreatePrimary: create the key
	rootTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw:  make([]byte, 256),
		},
	}
	parent, _, err := tpm2.CreatePrimary(conn, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", rootTemplate)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2.FlushContext(conn, parent)
	root, rootNameTpm, rootQNTpm, err := tpm2.ReadPublic(conn, parent)
	if err != nil {
		t.Fatal(err)
	}

	// TPM2_Create: create the key
	pubTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw:  make([]byte, 256),
		},
	}
	privBlob, pubBlob, _, _, _, err := tpm2.CreateKeyWithOutsideInfo(conn, parent, tpm2.PCRSelection{}, "", "", pubTemplate, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := tpm2.Load(conn, parent, "", pubBlob, privBlob)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2.FlushContext(conn, handle)

	pub, pubNameTpm, pubQNTpm, err := tpm2.ReadPublic(conn, handle)
	if err != nil {
		t.Fatal(err)
	}

	rootName, err := ComputeName(root)
	if err != nil {
		t.Fatal(err)
	}
	rootNameBuf, err := tpm2.Name(rootName).Encode()
	if err != nil {
		t.Fatal(err)
	}
	rootNameLib, err := root.Name()
	if err != nil {
		t.Fatal(err)
	}
	rootNameLibBuf, err := rootNameLib.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rootQN, err := ComputeName(tpm2.HandleEndorsement, root)
	if err != nil {
		t.Fatal(err)
	}
	rootQNbuf, err := tpm2.Name(rootQN).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubName, err := ComputeName(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubNameBuf, err := tpm2.Name(pubName).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubNameLib, err := pub.Name()
	if err != nil {
		t.Fatal(err)
	}
	pubNameLibBuf, err := pubNameLib.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN, err := ComputeName(tpm2.HandleEndorsement, root, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQNbuf, err := tpm2.Name(pubQN).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN2, err := ComputeName(rootQN, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQN2buf, err := tpm2.Name(pubQN2).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN3, err := ComputeName(tpm2.HandleEndorsement, rootName, pub)
	if err != nil {
		t.Fatal(err)
	}
	pubQN3buf, err := tpm2.Name(pubQN3).Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubQN4, err := ComputeName(tpm2.HandleEndorsement, rootName, pubName)
	if err != nil {
		t.Fatal(err)
	}
	pubQN4buf, err := tpm2.Name(pubQN4).Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("QName(Handle, public, public) %x\n", pubQNbuf[2:])
	fmt.Printf("QName(QN, public)             %x\n", pubQN2buf[2:])
	fmt.Printf("QName(Handle, name, public)   %x\n", pubQN3buf[2:])
	fmt.Printf("QName(Handle, name, name)     %x\n", pubQN4buf[2:])
	fmt.Printf("TPM 2.0 root QName            %x\n", rootQNTpm)
	fmt.Printf("TPM 2.0 pub QName             %x\n", pubQNTpm)
	fmt.Printf("TPM 2.0 root Name             %x\n", rootNameTpm)
	fmt.Printf("TPM 2.0 pub Name              %x\n", pubNameTpm)
	fmt.Printf("QName(root)                   %x\n", rootNameBuf[2:])
	fmt.Printf("QName(Handle, root)           %x\n", rootQNbuf[2:])
	fmt.Printf("QName(public)                 %x\n", pubNameBuf[2:])
	fmt.Printf("root.Name()                   %x\n", rootNameLibBuf[2:])
	fmt.Printf("public.Name()                 %x\n", pubNameLibBuf[2:])

	if !reflect.DeepEqual(pubQNbuf[2:], pubQN2buf[2:]) {
		t.Fatal("QName(Handle, public, public) != QName(QN, public)")
	}
	if !reflect.DeepEqual(pubQN2buf[2:], pubQN3buf[2:]) {
		t.Fatal("QName(QN, public) != QName(Handle, name, public)")
	}
	if !reflect.DeepEqual(pubQN3buf[2:], pubQN4buf[2:]) {
		t.Fatal("QName(Handle, name, public) != QName(Handle, name, name)")
	}
	if !reflect.DeepEqual(pubQNbuf[2:], pubQNTpm) {
		t.Fatal("TPM 2.0 pub QName != QName(Handle, public, public)")
	}
	if !reflect.DeepEqual(pubNameBuf[2:], pubNameTpm) {
		t.Fatal("TPM 2.0 pub Name != QName(public)")
	}
	if !reflect.DeepEqual(rootNameBuf[2:], rootNameTpm) {
		t.Fatal("TPM 2.0 root Name != QName(root)")
	}
}
