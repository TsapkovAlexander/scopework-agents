package hoststate_test

import (
	"regexp"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

// Коды отказа — стабильные строки контракта (ADR-0093, решение 7): их пишет
// в базу SQL, показывает web и берёт агент. Переименование константы молча
// ломает разбор на платформе, поэтому строки выписаны здесь буквально (повтор
// кода ловит компилятор: ключи литерала — константы), а форма совпадает с
// проверкой `deploy_record_agent_signing`.
func TestReasonCodesMatchContract(t *testing.T) {
	codes := map[hoststate.Reason]string{
		hoststate.ReasonEnvelopeMalformed:    "envelope_malformed",
		hoststate.ReasonSignatureInvalid:     "signature_invalid",
		hoststate.ReasonCertInvalid:          "cert_invalid",
		hoststate.ReasonCertNotFromRoot:      "cert_not_from_root",
		hoststate.ReasonCertNotYetValid:      "cert_not_yet_valid",
		hoststate.ReasonCertExpired:          "cert_expired",
		hoststate.ReasonCertValidityTooLong:  "cert_validity_too_long",
		hoststate.ReasonCertPurpose:          "cert_purpose",
		hoststate.ReasonCertSuperseded:       "cert_superseded",
		hoststate.ReasonUnsupportedContent:   "unsupported_content",
		hoststate.ReasonPayloadMalformed:     "payload_malformed",
		hoststate.ReasonStateMalformed:       "state_malformed",
		hoststate.ReasonFingerprintMismatch:  "fingerprint_mismatch",
		hoststate.ReasonSeqRollback:          "seq_rollback",
		hoststate.ReasonSecretsMismatch:      "secrets_mismatch",
		hoststate.ReasonGrantInvalid:         "grant_invalid",
		hoststate.ReasonTrustRootsInvalid:    "trust_roots_invalid",
		hoststate.ReasonLatchUnreadable:      "latch_unreadable",
		hoststate.ReasonLatchWriteFailed:     "latch_write_failed",
		hoststate.ReasonNoBundle:             "no_bundle",
		hoststate.ReasonSignerUnavailable:    "signer_unavailable",
		hoststate.ReasonSignerRefused:        "signer_refused",
		hoststate.ReasonSignerNotConfigured:  "signer_not_configured",
		hoststate.ReasonProtocolIncompatible: "protocol_incompatible",
	}
	form := regexp.MustCompile(`^[a-z_]{1,64}$`)
	for reason, want := range codes {
		if string(reason) != want {
			t.Errorf("код %q, в контракте %q", reason, want)
		}
		if !form.MatchString(string(reason)) {
			t.Errorf("код %q не по форме доклада", reason)
		}
	}
}
