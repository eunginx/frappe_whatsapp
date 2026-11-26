"""Webhook — rewired for Interakt.

Interakt relays Meta's WhatsApp events to us as POSTs signed with
HMAC-SHA256 (`Interakt-Signature: sha256=<hex>`) using the shared secret
configured in the Interakt dashboard, which we store on the WhatsApp
Account's `webhook_verify_token`.

Event types handled:
  - `message_received`            → creates an Incoming WhatsApp Message
  - `message_api_*`/`message_campaign_*` → delivery/read/failed status
    updates on the matching Outgoing WhatsApp Message
  - `message_template_status_update`   → template approval status

The Meta-shaped GET verify (hub.challenge) is kept — Interakt never
calls it, but it keeps the endpoint dual-compatible.
"""
import frappe
import hmac
import json
from hashlib import sha256
from werkzeug.wrappers import Response

_CONTENT_TYPES = {
	"Text": "text",
	"Image": "image",
	"Audio": "audio",
	"Video": "video",
	"Document": "document",
	"Button": "button",
	"Interactive": "button",
	"Location": "location",
}


@frappe.whitelist(allow_guest=True)
def webhook():
	"""Interakt webhook."""
	if frappe.request.method == "GET":
		return get()
	return post()


def get():
	"""Get."""
	hub_challenge = frappe.form_dict.get("hub.challenge")
	verify_token = frappe.form_dict.get("hub.verify_token")
	webhook_verify_token = frappe.db.get_value(
		'WhatsApp Account',
		{"webhook_verify_token": verify_token},
		'webhook_verify_token'
	)
	if not webhook_verify_token:
		frappe.throw("No matching WhatsApp account")

	if frappe.form_dict.get("hub.verify_token") != webhook_verify_token:
		frappe.throw("Verify token does not match")

	return Response(hub_challenge, status=200)

def post():
	"""Handle an Interakt webhook delivery."""
	payload_bytes = frappe.request.get_data()
	signature = frappe.request.headers.get("Interakt-Signature") or ""
	whatsapp_account = _verify_signature(payload_bytes, signature)
	if not whatsapp_account:
		frappe.response.http_status_code = 401
		return {"ok": False, "error": "Invalid signature"}

	try:
		data = json.loads(payload_bytes.decode("utf-8"))
	except Exception:
		frappe.response.http_status_code = 400
		return {"ok": False, "error": "Invalid JSON"}

	frappe.get_doc({
		"doctype": "WhatsApp Notification Log",
		"template": "Webhook",
		"meta_data": json.dumps(data)
	}).insert(ignore_permissions=True)

	frappe.set_user("Administrator")

	event_type = data.get("type") or ""
	event_data = data.get("data") or {}
	if event_type == "message_received":
		_handle_received(event_data, whatsapp_account)
	elif event_type.startswith(("message_api_", "message_campaign_")):
		_handle_message_status(event_data)
	elif event_type == "message_template_status_update":
		_handle_template_status(event_data)
	# account_alerts / account_update / template_performance_metrics etc.
	# are already captured in the Notification Log above for review.
	return {"ok": True}


def _verify_signature(payload_bytes, signature):
	"""Return the WhatsApp Account whose `webhook_verify_token` produced
	this `Interakt-Signature`, else None."""
	if not payload_bytes or not signature.startswith("sha256="):
		return None
	for account in frappe.get_all(
		"WhatsApp Account", fields=["name", "webhook_verify_token"]
	):
		secret = account.get("webhook_verify_token")
		if not secret:
			continue
		expected = "sha256=" + hmac.new(
			secret.encode("utf-8"), payload_bytes, sha256
		).hexdigest()
		if hmac.compare_digest(expected, signature):
			return frappe.get_doc("WhatsApp Account", account.name)
	return None


def _handle_received(data, whatsapp_account):
	"""Insert an Incoming WhatsApp Message for `message_received`."""
	customer = data.get("customer") or {}
	message = data.get("message") or {}
	message_id = message.get("id")
	if message_id and frappe.db.exists(
		"WhatsApp Message", {"message_id": message_id, "type": "Incoming"}
	):
		return  # duplicate delivery

	traits = customer.get("traits") or {}
	frappe.get_doc({
		"doctype": "WhatsApp Message",
		"type": "Incoming",
		"from": customer.get("channel_phone_number") or "",
		"message": message.get("message") or message.get("media_url") or "",
		"message_id": message_id,
		"content_type": _CONTENT_TYPES.get(
			message.get("message_content_type"), "text"
		),
		"attach": message.get("media_url") or "",
		"profile_name": traits.get("name") or traits.get("Name"),
		"whatsapp_account": whatsapp_account.name,
	}).insert(ignore_permissions=True)


def _handle_message_status(data):
	"""Apply Sent/Delivered/Read/Failed from `message_api_*` /
	`message_campaign_*` events to the matching Outgoing message."""
	message = data.get("message") or {}
	status = (message.get("message_status") or "").lower()
	if not status:
		return

	name = frappe.db.get_value(
		"WhatsApp Message", {"message_id": message.get("id")}, "name"
	)
	if not name:
		# callbackData echoes the WhatsApp Message docname set at send time
		callback_data = message.get("callback_data")
		if callback_data and frappe.db.exists("WhatsApp Message", callback_data):
			name = callback_data
	if not name:
		return

	doc = frappe.get_doc("WhatsApp Message", name)
	doc.status = status
	if not doc.message_id and message.get("id"):
		doc.message_id = message.get("id")
	doc.save(ignore_permissions=True)


def _handle_template_status(data):
	"""Apply template approval status to matching WhatsApp Templates rows.

	Interakt's payload fields for template alerts vary — match on any of
	the likely name/status keys; raw payloads stay in the Notification Log.
	"""
	template_name = (
		data.get("message_template_name")
		or data.get("template_name")
		or data.get("name")
	)
	status = (
		data.get("message_template_status")
		or data.get("status")
		or data.get("event")
	)
	if template_name and status:
		frappe.db.set_value(
			"WhatsApp Templates",
			{"actual_name": template_name},
			"status",
			str(status).lower(),
		)
