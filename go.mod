module github.com/immune-gmbh/agent/v2

go 1.16

replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt v3.2.0+incompatible

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/alecthomas/kong v0.2.18
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e
	github.com/fearful-symmetry/gomsr v0.0.1
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-licenses v0.0.0-20211006200916-ceb292363ec8 // indirect
	github.com/google/go-tpm v0.3.3-0.20210727055304-b3942ee5b15a
	github.com/google/go-tpm-tools v0.3.1
	github.com/google/jsonapi v1.0.0
	github.com/google/uuid v1.3.0
	github.com/gowebpki/jcs v1.0.0
	github.com/immune-gmbh/go-licenses v0.0.0-20210907144141-dc373d0d1263
	github.com/klauspost/compress v1.13.6
	github.com/shirou/gopsutil v3.21.10+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	golang.org/x/sys v0.0.0-20211113001501-0c823b97ae02
	golang.org/x/tools v0.1.0 // indirect
	gopkg.in/airbrake/gobrake.v2 v2.0.9 // indirect
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2 // indirect
	gotest.tools/gotestsum v1.7.0 // indirect
)
