package tui

import "io"

type UIState uint32

const (
	StCollectFirmwareInfo UIState = iota
	StQuotePCR
	StSendEvidence
	StAttestationSuccess
	StAttestationFailed
	StCreateKeys
	StEnrollKeys
	StEnrollSuccess
	StEnrollFailed
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
			showSpinner("Compile platform security report")
		case StQuotePCR:
			completeLastStep(true)
			showSpinner("Sign platform security report")
		case StSendEvidence:
			completeLastStep(true)
			showSpinner("Send report to immune Guard cloud")
		case StAttestationSuccess:
			showStepDone("Attestation successful", true)
		case StAttestationFailed:
			showStepDone("Attestation failed", false)
		case StCreateKeys:
			showSpinner("Generate keys")
		case StEnrollKeys:
			completeLastStep(true)
			showSpinner("Enroll device")
		case StEnrollSuccess:
			showStepDone("Enrollment successful", true)
		case StEnrollFailed:
			showStepDone("Enrollment failed", false)
		case StDeviceVulnerable:
			showTrust(false)
		case StDeviceTrusted:
			showTrust(true)
		case StChainAllGood:
			showTrustChain(-1)
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
