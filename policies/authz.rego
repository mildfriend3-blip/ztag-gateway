package ztag.authz

import rego.v1

# ---------------------------------------------------------------------------
# Zero-trust authorisation policy.
#
# The data plane has already proved *who* the caller is (signature, lifetime,
# audience, device binding, revocation). This policy decides whether that proven
# identity may reach this route, from this service, on this device, right now.
#
# Everything is data-driven: the route table and the service mesh rules live in
# data.json so security review is a diff, not a code change.
# ---------------------------------------------------------------------------

default min_trust := 50

min_trust := data.ztag.min_trust if data.ztag.min_trust

route_cfg := data.ztag.routes[input.route]

deny_reasons contains "unknown_route" if not route_cfg

deny_reasons contains "missing_subject" if input.subject == ""

# ---- service segmentation -------------------------------------------------
# A token issued to service X may only call routes that list X. This is the
# control-plane half of microsegmentation: even with a valid token, a
# compromised "reporting" service cannot reach "payments".
deny_reasons contains "service_not_allowed" if {
	route_cfg
	not input.service in object.get(route_cfg, "allowed_services", [])
}

deny_reasons contains "missing_service" if {
	route_cfg
	input.service == ""
}

# ---- scope ----------------------------------------------------------------
deny_reasons contains "missing_scope" if {
	route_cfg
	some scope in object.get(route_cfg, "scopes", [])
	not scope in object.get(input, "scopes", [])
	not "*" in object.get(input, "scopes", [])
}

# ---- device posture -------------------------------------------------------
deny_reasons contains "device_trust_too_low" if input.device.trust < min_trust

deny_reasons contains "device_not_bound" if {
	route_cfg
	object.get(route_cfg, "require_device_binding", false)
	not input.device.bound
}

# ---- step-up authentication ----------------------------------------------
# Sensitive routes demand a token minted after a second factor.
deny_reasons contains "mfa_required" if {
	route_cfg
	object.get(route_cfg, "require_mfa", false)
	not "mfa" in object.get(input, "amr", [])
	not "otp" in object.get(input, "amr", [])
	not "webauthn" in object.get(input, "amr", [])
}

# ---- method restriction ---------------------------------------------------
deny_reasons contains "method_not_allowed" if {
	route_cfg
	allowed := object.get(route_cfg, "methods", [])
	count(allowed) > 0
	not input.method in allowed
}

# ---- short-lived tokens only ---------------------------------------------
# A token with an implausibly long remaining life means the issuer is not
# honouring the short-TTL contract; refuse rather than trust it.
deny_reasons contains "token_ttl_too_long" if input.token_ttl_s > data.ztag.max_token_ttl_s

# ---- decision -------------------------------------------------------------
# default keeps the verdict total: a rule set with no matching case must deny,
# never return "undefined", so a typo can never become an implicit allow.
default allow := false

allow if count(deny_reasons) == 0

reason := "admitted" if count(deny_reasons) == 0

reason := sort(deny_reasons)[0] if count(deny_reasons) > 0

# step_up asks the client to re-authenticate instead of hard-denying. It is
# surfaced for routes that allow a degraded but authenticated experience.
default step_up := false

step_up if {
	count(deny_reasons) > 0
	some r in deny_reasons
	r == "mfa_required"
}

decision := {
	"allow": allow,
	"reason": reason,
	"step_up": step_up,
}
