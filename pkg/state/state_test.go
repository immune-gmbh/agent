package state

/*
import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/immune-gmbh/guard/pkg/tpm"
	log "github.com/sirupsen/logrus"

	test "github.com/immune-gmbh/agent/internal/testing"
)

func StateTpmKeyGenerate(rand *rand.Rand) StateTpmKey {
	auth, err := tpm.GenerateAuthValue()
	if err != nil {
		panic(err)
	}
	cred, err := tpm.GenerateAuthValue()
	if err != nil {
		panic(err)
	}

	return StateTpmKey{
		Public:      tpm.TpmPublicKey(tpm.GeneratePublic(rand)),
		Private:     test.GenerateBytes(rand, 32, 64),
		Auth:        auth,
		Certificate: cred,
	}
}

func (State) Generate(rand *rand.Rand, size int) reflect.Value {
	var ekCert *tpm.Certificate
	if rand.Intn(1) == 1 {
		c := tpm.Certificate(tpm.GenerateCertificate(rand))
		ekCert = &c
	}

	s := State{
		Ty:                     ClientStateType,
		EndorsementKey:         tpm.TpmPublicKey(tpm.GeneratePublic(rand)),
		EndorsementCertificate: ekCert,
		RootKeyAuth:            test.GenerateBase64(rand, 0, 128),
		QuoteKey:               StateTpmKeyGenerate(rand),
	}

	return reflect.ValueOf(s)
}

func TestSerializinig(t *testing.T) {
	f := func(k State) bool {
		tmpDirNam := os.TempDir()
		tmpNam := fmt.Sprintf("%s/state", tmpDirNam)

		err := k.Store(tmpNam)
		if err != nil {
			log.Printf("Store failed: %s\n", err)
			return false
		}

		kk, err := LoadState(tmpNam)
		if err != nil {
			log.Printf("Load failed: %s\n", err)
			return false
		}

		if !reflect.DeepEqual(k.EndorsementCertificate, kk.EndorsementCertificate) {
			log.Printf("ek cert not the same after serialization\n")
			log.Printf("in: %#v\n", k.EndorsementCertificate)
			log.Printf("out: %#v\n", kk.EndorsementCertificate)
			return false
		}

		if !reflect.DeepEqual(k.QuoteKey, kk.QuoteKey) {
			log.Printf("quote key not the same after serialization\n")
			log.Printf("in: %#v\n", k.QuoteKey)
			log.Printf("out: %#v\n", kk.QuoteKey)
			return false
		}

		if !reflect.DeepEqual(k.EndorsementKey, kk.EndorsementKey) {
			log.Printf("ek key not the same after serialization\n")
			log.Printf("in: %#v\n", k.EndorsementKey)
			log.Printf("out: %#v\n", kk.EndorsementKey)
			return false
		}

		if !reflect.DeepEqual(k.RootKeyAuth, kk.RootKeyAuth) {
			log.Printf("ek key not the same after serialization\n")
			log.Printf("in: %#v\n", k.RootKeyAuth)
			log.Printf("out: %#v\n", kk.RootKeyAuth)
			return false
		}

		if !reflect.DeepEqual(k.Ty, kk.Ty) {
			log.Printf("ek key not the same after serialization\n")
			log.Printf("in: %#v\n", k.Ty)
			log.Printf("out: %#v\n", kk.Ty)
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}*/
