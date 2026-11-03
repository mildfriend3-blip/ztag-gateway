package ztag.authz

import rego.v1

# Unit tests for the authorisation policy. Run with: opa test policies -v
# These are the executable half of the threat model: each test is one attack
# the gateway must refuse.

good_input := {
	"subject": "user-1001",
	"service": "web",
	"scopes": ["orders.read"],
	"amr": ["pwd", "otp"],
	"route": "/api/orders",
	"method": "GET",
	"device": {"id": "d-7712", "hash": "abc", "trust": 90, "bound": true},
	"token_ttl_s": 300,
}

test_admits_legitimate_request if {
	decision := data.ztag.authz.decision with input as good_input
	decision.allow == true
	decision.reason == "admitted"
}

test_denies_unknown_route if {
	bad := object.union(good_input, {"route": "/api/internal/debug"})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "unknown_route"
}

test_denies_lateral_movement if {
	# A reporting service holding a perfectly valid token must not reach orders.
	bad := object.union(good_input, {"service": "reporting"})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "service_not_allowed"
}

test_denies_missing_scope if {
	bad := object.union(good_input, {"scopes": ["reports.read"]})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "missing_scope"
}

test_denies_stolen_token_on_unmanaged_device if {
	# Session takeover: token replayed from a device with poor posture.
	bad := object.union(good_input, {"device": {"id": "d-9999", "hash": "zzz", "trust": 20, "bound": false}})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false

	# Both signals fire for a replayed token: the fingerprint no longer matches
	# the bound device id, and the new device's posture is below the floor.
	decision.reason in {"device_trust_too_low", "device_not_bound"}
}

test_denies_unbound_device_when_required if {
	bad := object.union(good_input, {"device": {"id": "d-7712", "hash": "abc", "trust": 90, "bound": false}})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "device_not_bound"
}

test_denies_payments_without_mfa if {
	bad := object.union(good_input, {
		"route": "/api/payments",
		"method": "POST",
		"scopes": ["payments.write"],
		"amr": ["pwd"],
	})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "mfa_required"
	decision.step_up == true
}

test_denies_wrong_method if {
	bad := object.union(good_input, {"method": "DELETE"})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "method_not_allowed"
}

test_denies_overlong_token if {
	bad := object.union(good_input, {"token_ttl_s": 86400})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "token_ttl_too_long"
}

test_denies_missing_subject if {
	bad := object.union(good_input, {"subject": ""})
	decision := data.ztag.authz.decision with input as bad
	decision.allow == false
	decision.reason == "missing_subject"
}
