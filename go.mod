module github.com/immune-gmbh/agent/v3

go 1.16

replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt v3.2.0+incompatible

replace github.com/google/go-tpm => github.com/immune-gmbh/go-tpm v0.3.4-0.20220310140359-93b752e22d71

replace github.com/google/go-tpm-tools => github.com/immune-gmbh/go-tpm-tools v0.3.5-0.20220310173717-20c83b9942a4

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/alecthomas/kong v0.2.18
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e
	github.com/fearful-symmetry/gomsr v0.0.1
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-licenses v0.0.0-20211006200916-ceb292363ec8 // indirect
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.4
	github.com/google/jsonapi v1.0.0
	github.com/google/uuid v1.3.0
	github.com/gowebpki/jcs v1.0.0
	github.com/immune-gmbh/go-licenses v0.0.0-20210907144141-dc373d0d1263
	github.com/klauspost/compress v1.13.6
	github.com/shirou/gopsutil v3.21.10+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	golang.org/x/sys v0.0.0-20211205182925-97ca703d548d
)
