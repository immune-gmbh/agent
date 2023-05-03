// Keep in sync with agent/pkg/api/types.go
package api

import (
	"time"

	"github.com/google/uuid"
)

type FirmwareError string

const (
	NoError        FirmwareError = ""
	UnknownError   FirmwareError = "unkn"
	NoPermission   FirmwareError = "no-perm"
	NoResponse     FirmwareError = "no-resp"
	NotImplemented FirmwareError = "not-impl"
)

// /v2/info (apisrv)
type Info struct {
	APIVersion string `jsonapi:"attr,api_version" json:"api_version"`
}

// /v2/configuration (apisrv)
type KeyTemplate struct {
	Public PublicKey `json:"public"`
	Label  string    `json:"label"`
}

// /v2/configuration (apisrv)
type Configuration struct {
	Root            KeyTemplate            `jsonapi:"attr,root" json:"root"`
	Keys            map[string]KeyTemplate `jsonapi:"attr,keys" json:"keys"`
	PCRBank         uint16                 `jsonapi:"attr,pcr_bank" json:"pcr_bank"`
	PCRs            []int                  `jsonapi:"attr,pcrs" json:"pcrs"`
	UEFIVariables   []UEFIVariable         `jsonapi:"attr,uefi" json:"uefi"`
	MSRs            []MSR                  `jsonapi:"attr,msrs" json:"msrs"`
	CPUIDLeafs      []CPUIDLeaf            `jsonapi:"attr,cpuid" json:"cpuid"`
	TPM2NVRAM       []uint32               `jsonapi:"attr,tpm2_nvram" json:"tpm2_nvram,string"`
	SEV             []SEVCommand           `jsonapi:"attr,sev" json:"sev"`
	ME              []MEClientCommands     `jsonapi:"attr,me" json:"me"`
	TPM2Properties  []TPM2Property         `jsonapi:"attr,tpm2_properties" json:"tpm2_properties"`
	PCIConfigSpaces []PCIConfigSpace       `jsonapi:"attr,pci" json:"pci"`
}

// /v2/attest (apisrv)
type FirmwareProperties struct {
	UEFIVariables   []UEFIVariable     `json:"uefi,omitempty"`
	MSRs            []MSR              `json:"msrs,omitempty"`
	CPUIDLeafs      []CPUIDLeaf        `json:"cpuid,omitempty"`
	SEV             []SEVCommand       `json:"sev,omitempty"`
	ME              []MEClientCommands `json:"me,omitempty"`
	TPM2Properties  []TPM2Property     `json:"tpm2_properties,omitempty"`
	TPM2NVRAM       []TPM2NVIndex      `json:"tpm2_nvram,omitempty"`
	PCIConfigSpaces []PCIConfigSpace   `json:"pci,omitempty"`
	ACPI            ACPITables         `json:"acpi"`
	SMBIOS          HashBlob           `json:"smbios"`
	TXTPublicSpace  HashBlob           `json:"txt"`
	VTdRegisterSet  HashBlob           `json:"vtd"`
	Flash           HashBlob           `json:"flash"`
	TPM2EventLog    ErrorBuffer        `json:"event_log"`             // deprecated
	TPM2EventLogZ   *ErrorBuffer       `json:"event_log_z,omitempty"` // deprecated
	TPM2EventLogs   []HashBlob         `json:"event_logs,omitempty"`
	PCPQuoteKeys    map[string]Buffer  `json:"pcp_quote_keys,omitempty"` // windows only
	MACAddresses    MACAddresses       `json:"mac"`
	OS              OS                 `json:"os"`
	NICs            *NICList           `json:"nic,omitempty"`
	Memory          Memory             `json:"memory"`
	Agent           *Agent             `json:"agent,omitempty"`
	Devices         *Devices           `json:"devices,omitempty"`
	IMALog          *ErrorBuffer       `json:"ima_log,omitempty"`
	EPPInfo         *EPPInfo           `json:"epp_info,omitempty"`
	BootApps        *BootApps          `json:"boot_apps,omitempty"`
}

type BootApps struct {
	Images    map[string]HashBlob `json:"images,omitempty"` // path -> pe file
	ImagesErr FirmwareError       `json:"images_err,omitempty"`
}

type EPPInfo struct {
	AntimalwareProcesses    map[string]HashBlob `json:"antimalware_processes,omitempty"` // path -> exe file
	AntimalwareProcessesErr FirmwareError       `json:"antimalware_processes_err,omitempty"`
	EarlyLaunchDrivers      map[string]HashBlob `json:"early_launch_drivers,omitempty"` // path -> sys file
	EarlyLaunchDriversErr   FirmwareError       `json:"early_launch_drivers_err,omitempty"`
	ESET                    *ESETConfig         `json:"eset,omitempty"` // Linux only
}

type ESETConfig struct {
	Enabled           ErrorBuffer `json:"enabled"`
	ExcludedFiles     ErrorBuffer `json:"excluded_files"`
	ExcludedProcesses ErrorBuffer `json:"excluded_processes"`
}

type HashBlob struct {
	Sha256 Buffer        `json:"sha256,omitempty"` // hash of uncompressed data
	ZData  Buffer        `json:"z_data,omitempty"` // zstd compressed data, maybe omitted if data is assumed to be known
	Data   Buffer        `json:"data,omitempty"`   // deprecated: uncompressed data for backwards compatibility to ErrorBuffer
	Error  FirmwareError `json:"error,omitempty"`  // FirmwareErr*
}

type Devices struct {
	FWUPdVersion string                        `json:"fwupd_version"`
	Topology     []FWUPdDevice                 `json:"topology"`
	Releases     map[string][]FWUPdReleaseInfo `json:"releases,omitempty"`
}

type FWUPdDevice = map[string]interface{}
type FWUPdReleaseInfo = map[string]interface{}

type Agent struct {
	Release   string      `json:"release"`
	ImageSHA2 ErrorBuffer `json:"sha,omitempty"`
}

type NICList struct {
	List  []NIC         `json:"list,omitempty"`
	Error FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type NIC struct {
	Name  string        `json:"name,omitempty"`
	IPv4  []string      `json:"ipv4,omitempty"`
	IPv6  []string      `json:"ipv6,omitempty"`
	MAC   string        `json:"mac"`
	Error FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type OS struct {
	Hostname string        `json:"hostname"`
	Release  string        `json:"name"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type SEVCommand struct {
	Command    uint32        `json:"command"` // firmware.SEV*
	ReadLength uint32        `json:"read_length"`
	Response   *Buffer       `json:"response,omitempty"`
	Error      FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MEClientCommands struct {
	GUID     *uuid.UUID    `json:"guid,omitempty"`
	Address  string        `json:"address,omitempty"`
	Commands []MECommand   `json:"commands"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MECommand struct {
	Command  Buffer        `json:"command"`
	Response Buffer        `json:"response,omitempty"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type UEFIVariable struct {
	Vendor string        `json:"vendor"`
	Name   string        `json:"name"`
	Value  *Buffer       `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MSR struct {
	MSR    uint32        `json:"msr,string"`
	Values []uint64      `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type CPUIDLeaf struct {
	LeafEAX uint32        `json:"leaf_eax,string"`
	LeafECX uint32        `json:"leaf_ecx,string"`
	EAX     *uint32       `json:"eax,string,omitempty"`
	EBX     *uint32       `json:"ebx,string,omitempty"`
	ECX     *uint32       `json:"ecx,string,omitempty"`
	EDX     *uint32       `json:"edx,string,omitempty"`
	Error   FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type TPM2Property struct {
	Property uint32        `json:"property,string"`
	Value    *uint32       `json:"value,omitempty,string"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type TPM2NVIndex struct {
	Index  uint32        `json:"index,string"`
	Public *NVPublic     `json:"public,omitempty"`
	Value  *Buffer       `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type Memory struct {
	Values []MemoryRange `json:"values,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MemoryRange struct {
	Start    uint64 `json:"start,string"`
	Bytes    uint64 `json:"bytes,string"`
	Reserved bool   `json:"reserved"`
}

type ACPITables struct {
	Blobs map[string]HashBlob `json:"blobs,omitempty"`
	Error FirmwareError       `json:"error,omitempty"` // FirmwareErr*
}

type ErrorBuffer struct {
	Data  Buffer        `json:"data,omitempty"`
	Error FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MACAddresses struct {
	Addresses []string      `json:"addrs"`
	Error     FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type PCIConfigSpace struct {
	Bus      uint16        `json:"bus,string"`
	Device   uint16        `json:"device,string"`
	Function uint8         `json:"function,string"`
	Value    Buffer        `json:"value,omitempty"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

// /v2/enroll (apisrv)
type Enrollment struct {
	NameHint               string         `jsonapi:"attr,name_hint" json:"name_hint"`
	EndoresmentKey         PublicKey      `jsonapi:"attr,endoresment_key" json:"endoresment_key"`
	EndoresmentCertificate *Certificate   `jsonapi:"attr,endoresment_certificate" json:"endoresment_certificate"`
	Root                   PublicKey      `jsonapi:"attr,root" json:"root"`
	Keys                   map[string]Key `jsonapi:"attr,keys" json:"keys"`
	Cookie                 string         `jsonapi:"attr,cookie" json:"cookie"`
}

// /v2/enroll (apisrv)
type Key struct {
	Public                 PublicKey `json:"public"`
	CreationProof          Attest    `json:"certify_info"`
	CreationProofSignature Signature `json:"certify_signature"`
}

const EvidenceType = "evidence/1"

// /v2/attest (apisrv)
type Evidence struct {
	Type      string                       `jsonapi:"attr,type" json:"type"`
	Quote     *Attest                      `jsonapi:"attr,quote,omitempty" json:"quote,omitempty"`
	Signature *Signature                   `jsonapi:"attr,signature,omitempty" json:"signature,omitempty"`
	Algorithm string                       `jsonapi:"attr,algorithm" json:"algorithm"`
	PCRs      map[string]Buffer            `jsonapi:"attr,pcrs" json:"pcrs"`
	AllPCRs   map[string]map[string]Buffer `jsonapi:"attr,allpcrs" json:"allpcrs"`
	Firmware  FirmwareProperties           `jsonapi:"attr,firmware" json:"firmware"`
	Cookie    string                       `jsonapi:"attr,cookie" json:"cookie"`
}

// /v2/enroll (apisrv)
type EncryptedCredential struct {
	Name       string `jsonapi:"attr,name" json:"name"`
	KeyID      Buffer `jsonapi:"attr,key_id" json:"key_id"`
	Credential Buffer `jsonapi:"attr,credential" json:"credential"` // encrypted JWT
	Secret     Buffer `jsonapi:"attr,secret" json:"secret"`
	Nonce      Buffer `jsonapi:"attr,nonce" json:"nonce"`
}

// /v2/devices (apisrv)
type Appraisal struct {
	Id        string    `jsonapi:"primary,appraisals" json:"id"`
	Received  time.Time `jsonapi:"attr,received,rfc3339" json:"received"`
	Appraised time.Time `jsonapi:"attr,appraised,rfc3339" json:"appraised"`
	Expires   time.Time `jsonapi:"attr,expires,rfc3339" json:"expires"`
	Verdict   Verdict   `jsonapi:"attr,verdict" json:"verdict"`
	Report    Report    `jsonapi:"attr,report" json:"report"`
}

const VerdictType = "verdict/3"

const (
	Unsupported = "unsupported"
	Trusted     = "trusted"
	Vulnerable  = "vulnerable"
)

// /v2/devices (apisrv)
type Verdict struct {
	Type string `json:"type"`

	Result             string `json:"result"`
	SupplyChain        string `json:"supply_chain"`
	Configuration      string `json:"configuration"`
	Firmware           string `json:"firmware"`
	Bootloader         string `json:"bootloader"`
	OperatingSystem    string `json:"operating_system"`
	EndpointProtection string `json:"endpoint_protection"`
}

const ReportType = "report/2"

// /v2/devices (apisrv)
type Report struct {
	Type        string       `json:"type"`
	Values      ReportValues `json:"values"`
	Annotations []Annotation `json:"annotations"`
}

type ReportValues struct {
	Host   Host    `json:"host"`
	SMBIOS *SMBIOS `json:"smbios,omitempty"`
	UEFI   *UEFI   `json:"uefi,omitempty"`
	TPM    *TPM    `json:"tpm,omitempty"`
	ME     *ME     `json:"me,omitempty"`
	SGX    *SGX    `json:"sgx,omitempty"`
	TXT    *TXT    `json:"txt,omitempty"`
	SEV    *SEV    `json:"sev,omitempty"`
	NICs   []NIC   `json:"nics,omitempty"`
}

const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSUnknown = "unknown"
)

type CPUVendor string

const (
	IntelCPU CPUVendor = "GenuineIntel"
	AMDCPU   CPUVendor = "AuthenticAMD"
)

type Host struct {
	// Windows: <ProductName> <CurrentMajorVersionNumber>.<CurrentMinorVersionNumber> Build <CurrentBuild>
	// Linux: /etc/os-release PRETTY_NAME or lsb_release -d
	OSName    string    `json:"name"`
	Hostname  string    `json:"hostname"`
	OSType    string    `json:"type"` // OS*
	CPUVendor CPUVendor `json:"cpu_vendor"`
}

type SMBIOS struct {
	Manufacturer    string `json:"manufacturer"`
	Product         string `json:"product"`
	Serial          string `json:"serial,omitempty"`
	UUID            string `json:"uuid,omitempty"`
	BIOSReleaseDate string `json:"bios_release_date"`
	BIOSVendor      string `json:"bios_vendor"`
	BIOSVersion     string `json:"bios_version"`
}

const (
	EFICertificate = "certificate"
	EFIFingerprint = "fingerprint"
)

type EFISignature struct {
	Type        string     `json:"type"`              // EFIFingerprint or EFICertificate
	Subject     *string    `json:"subject,omitempty"` // certificate only
	Issuer      *string    `json:"issuer,omitempty"`  // certificate only
	Fingerprint string     `json:"fingerprint"`
	NotBefore   *time.Time `json:"not_before,omitempty,rfc3339"` // certificate only
	NotAfter    *time.Time `json:"not_after,omitempty,rfc3339"`  // certificate only
	Algorithm   *string    `json:"algorithm,omitempty"`          // certificate only
}

const (
	ModeSetup    = "setup"
	ModeAudit    = "audit"
	ModeUser     = "user"
	ModeDeployed = "deployed"
)

type UEFI struct {
	Mode          string          `json:"mode"` // Mode*
	SecureBoot    bool            `json:"secureboot"`
	PlatformKeys  *[]EFISignature `json:"platform_keys"`
	ExchangeKeys  *[]EFISignature `json:"exchange_keys"`
	PermittedKeys *[]EFISignature `json:"permitted_keys"`
	ForbiddenKeys *[]EFISignature `json:"forbidden_keys"`
}

type TPM struct {
	Manufacturer string            `json:"manufacturer"`
	VendorID     string            `json:"vendor_id"`
	SpecVersion  string            `json:"spec_version"`
	EventLog     []TPMEvent        `json:"eventlog"`
	PCR          map[string]string `json:"pcr"`
}

const (
	ICU        = "ICU"
	TXE        = "TXE"
	ConsumerME = "Consumer CSME"
	BusinessME = "Business CSME"
	LightME    = "Light ME"
	SPS        = "SPS"
	UnknownME  = "Unrecognized"
)

type ME struct {
	Features        []string `json:"features"`
	Variant         string   `json:"variant"` // constants above
	Version         []uint16 `json:"version"`
	RecoveryVersion []uint16 `json:"recovery_version"`
	FITCVersion     []uint16 `json:"fitc_version"`
	API             []uint   `json:"api_version,string"`
	MEUpdate        string   `json:"updatable"`
	ChipsetVersion  uint     `json:"chipset_version,string"`
	ChipID          uint     `json:"chip_id,string"`
	Manufacturer    string   `json:"manufacturer,omitempty"`
	Size            uint     `json:"size,string"`
	Signature       string   `json:"signature"`
}

type SGX struct {
	Version          uint               `json:"version"`
	Enabled          bool               `json:"enabled"`
	FLC              bool               `json:"flc"`
	KSS              bool               `json:"kss"`
	MaxEnclaveSize32 uint               `json:"enclave_size_32"`
	MaxEnclaveSize64 uint               `json:"enclave_size_64"`
	EPC              []EnclavePageCache `json:"epc"`
}

type TXT struct {
	Ready bool `json:"ready"`
}

type SEV struct {
	Enabled bool   `json:"enabled"`
	Version []uint `json:"version"`
	SME     bool   `json:"sme"`
	ES      bool   `json:"es"`
	VTE     bool   `json:"vte"`
	SNP     bool   `json:"snp"`
	VMPL    bool   `json:"vmpl"`
	Guests  uint   `json:"guests"`
	MinASID uint   `json:"min_asid"`
}

// /v2/devices (apisrv)
type TPMEvent struct {
	PCR       uint   `json:"pcr"`
	Value     string `json:"value"`
	Algorithm uint   `json:"algorithm"`
	Note      string `json:"note"`
}

// /v2/devices (apisrv)
type EnclavePageCache struct {
	Base          uint64 `json:"base"`
	Size          uint64 `json:"size"`
	CIRProtection bool   `json:"cir_protection"`
}

// /v2/devices (apisrv)
type Annotation struct {
	Id       AnnotationID `json:"id"`
	Expected string       `json:"expected,omitempty"`
	Path     string       `json:"path"`
	Fatal    bool         `json:"fatal"`
}

type AnnotationID string
