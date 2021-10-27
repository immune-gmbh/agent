module github.com/immune-gmbh/agent/v2

go 1.16

replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt v3.2.0+incompatible

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/alecthomas/kong v0.2.17
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e
	github.com/fearful-symmetry/gomsr v0.0.1
	github.com/google/go-cmp v0.5.4 // indirect
	github.com/google/go-licenses v0.0.0-20210816172045-3099c18c36e1 // indirect
	github.com/google/go-tpm v0.3.3-0.20210727055304-b3942ee5b15a
	github.com/google/go-tpm-tools v0.2.1
	github.com/google/jsonapi v1.0.0
	github.com/google/uuid v1.3.0
	github.com/gowebpki/jcs v0.0.0-20210215032300-680d9436c864
	github.com/immune-gmbh/go-licenses v0.0.0-20210907144141-dc373d0d1263 // indirect
	github.com/klauspost/compress v1.13.5
	github.com/shirou/gopsutil v3.21.8+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	golang.org/x/crypto v0.0.0-20191117063200-497ca9f6d64f
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
)
