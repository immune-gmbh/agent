package tui

import "io"

type UIState uint32

const (
	StCollectFirmwareInfo UIState = iota
	StQuotePCR
	StSendEvidence
	StAttestationSuccess
	StAttestationRunning
	StAttestationFailed
	StSelectTASuccess
	StSelectTAFailed
	StCreateKeys
	StEnrollKeys
	StEnrollSuccess
	StEnrollFailed
	StNoRoot
	StDeviceVulnerable
	StDeviceTrusted
	StChainAllGood
	StChainFailSupplyChain
	StChainFailConfiguration
	StChainFailFirmware
	StChainFailBootloader
	StChainFailOperatingSystem
	StChainFailEndpointProtection
)

// SetUIState globally sets the state and thus choses the view that should render
func SetUIState(state UIState) {
	if Out != io.Discard {
		switch state {
		case StCollectFirmwareInfo:
			showSpinner("Compile device security report")
		case StQuotePCR:
			completeLastStep(true)
			showSpinner("Sign device security report")
		case StSendEvidence:
			completeLastStep(true)
			showSpinner("Send report to immune Guard cloud")
		case StAttestationSuccess:
			showStepDone("Attestation successful", true)
		case StAttestationRunning:
			showStepDone("Attestation still in progress, results will be online soon", true)
		case StAttestationFailed:
			showStepDone("Attestation failed", false)
		case StSelectTASuccess:
			showStepDone("Secure trust anchor found", true)
		case StSelectTAFailed:
			showStepDone("No secure trust anchor found", false)
			printf("\nPlease check your BIOS/UEFI/BMC settings to enable a TPM if applicable.\nIn case your system has no TPM you can enable an insecure dummy TPM with the --notpm switch.\n\n    If you are unsure what to do, contact us via support@immu.ne.\n\n")
		case StCreateKeys:
			showSpinner("Generate keys")
		case StEnrollKeys:
			completeLastStep(true)
			showSpinner("Enroll device")
		case StEnrollSuccess:
			showStepDone("Enrollment successful", true)
		case StEnrollFailed:
			showStepDone("Enrollment failed", false)
		case StNoRoot:
			showStepDone("Program executed without root / administrator rights, aborting...", false)
		case StDeviceVulnerable:
			showTrust(false)
		case StDeviceTrusted:
			showTrust(true)
		case StChainAllGood:
			showTrustChain(0xFF)
		case StChainFailSupplyChain:
			showTrustChain(0)
		case StChainFailConfiguration:
			showTrustChain(1)
		case StChainFailFirmware:
			showTrustChain(2)
		case StChainFailBootloader:
			showTrustChain(3)
		case StChainFailOperatingSystem:
			showTrustChain(4)
		case StChainFailEndpointProtection:
			showTrustChain(5)
		}
	}
}
