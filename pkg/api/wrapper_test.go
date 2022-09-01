package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
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
	rootBuf, err := hex.DecodeString("0001000b0003007200000006008000430010080000000000010086f53975de04199e635385004ba06809db8baa2fac7d9af566df0a70e67dd5dc1048b0f996cdfa2b656374787872b2aded8cae7e20465fce57b95643341a03108b35db71e2317f0d323792c06504c4a426d09de7e506f32f4faf2cf1f789324d8f05163f95fa2d55b20f50c7c24ae5fec52b69b89d618a210f9d50128fad6fdb44cf1fad6ade9f6e14dd15a1ffbf3936b10bc9ae446faf99364d484166c8744aab78c0a40071f62d7e08a0dacf2646eb3c3b89c0b87a6de0f982f89c5237b0ae265d6bd7cd44925d9e6a03a7d09d39ea400e01f4739fc262f74bfd911b012508c89adf22ebd3ee5fa8a128aabf0b196614863d934a8e3e9d1bf5147992af5d75")
	assert.NoError(t, err)
	root, err := tpm2.DecodePublic(rootBuf)
	assert.NoError(t, err)
	rootNameTpm, err := hex.DecodeString("000ba99340d46ecb291e26d14d6e90d59b3ab5f2bbc488d2b243dc1242057e104eaf")
	assert.NoError(t, err)
	rootQNTpm, err := hex.DecodeString("000bc893103fae3925c462b691d58c3f19dd3d139e001064a5ad904dccf495192f3e")
	assert.NoError(t, err)
	pubBuf, err := hex.DecodeString("0001000b00050072000000100016000b08000000000001009dd086df35339047f7710c24eeb8db5d0ea2ab4e608d524fe213cfe2c85727e5eeee8f7ce48dc87f1229288fa46d4dc7c4e166a05ccd610c61285527357ab7d320d501af475a971b3bd7fd18f1b131a14a9e2d2edf1448aa0f514ef7734e78933eb182f3b6a3e967fe7c8e51efc2969ec5d02e4d8ba7474f1fbccad1f77f9aa2c896ea39db5d76f9b8706d0cb495b4654fab705c2c7714c4f752907b5c48a5b55eff4047763db900d253c3b251bc90162cf3d726db0d561086a1c010ca222c49b5524f87af1b9f52e73eb2d668c97cfd9c0647a2cc82aeba0278b4a75f64d5e9c6f3bc29c90f63a4066ca476b869a09e01cb8bf90ea9bb8e809c46a3c4601901")
	assert.NoError(t, err)
	pub, err := tpm2.DecodePublic(pubBuf)
	assert.NoError(t, err)
	pubNameTpm, err := hex.DecodeString("000b6ec3b3e9780132e89771c8a39f27585644bb6923f94f15f9409cca116f98e394")
	assert.NoError(t, err)
	pubQNTpm, err := hex.DecodeString("000b0cee9e145c02d7944323cc2c036a5ad4cbff473b349872e56eab7e936cfa636f")
	assert.NoError(t, err)

	rootName, err := ComputeName(root)
	assert.NoError(t, err)
	rootNameBuf, err := tpm2.Name(rootName).Encode()
	assert.NoError(t, err)
	rootNameLib, err := root.Name()
	assert.NoError(t, err)
	rootNameLibBuf, err := rootNameLib.Encode()
	assert.NoError(t, err)
	rootQN, err := ComputeName(tpm2.HandleEndorsement, root)
	assert.NoError(t, err)
	rootQNbuf, err := tpm2.Name(rootQN).Encode()
	assert.NoError(t, err)
	pubName, err := ComputeName(pub)
	assert.NoError(t, err)
	pubNameBuf, err := tpm2.Name(pubName).Encode()
	assert.NoError(t, err)
	pubNameLib, err := pub.Name()
	assert.NoError(t, err)
	pubNameLibBuf, err := pubNameLib.Encode()
	assert.NoError(t, err)
	pubQN, err := ComputeName(tpm2.HandleEndorsement, root, pub)
	assert.NoError(t, err)
	pubQNbuf, err := tpm2.Name(pubQN).Encode()
	assert.NoError(t, err)
	pubQN2, err := ComputeName(rootQN, pub)
	assert.NoError(t, err)
	pubQN2buf, err := tpm2.Name(pubQN2).Encode()
	assert.NoError(t, err)
	pubQN3, err := ComputeName(tpm2.HandleEndorsement, rootName, pub)
	assert.NoError(t, err)
	pubQN3buf, err := tpm2.Name(pubQN3).Encode()
	assert.NoError(t, err)
	pubQN4, err := ComputeName(tpm2.HandleEndorsement, rootName, pubName)
	assert.NoError(t, err)
	pubQN4buf, err := tpm2.Name(pubQN4).Encode()
	assert.NoError(t, err)

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
