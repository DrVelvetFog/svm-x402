#!/usr/bin/env python3
"""Bind an SVM `upto` settlement to a recomputable SEP-2828 receipt per the
Settlement-Receipt Binding extension (x402-foundation/x402#2666), straight from
what the upto-svm facilitator emits.

Input: sample-settle-output.json — the `settle()` SettleResponse plus the
requirements/voucher it settled against. Swap in a real devnet run to anchor it.

    pip install rfc8785 cryptography
    python emit.py                 # writes keys/, svm/step0, svm/step1, expected.json
    python _check_independent.py   # the pinned independent checker -> exit 0, all green

Mapping to upto-svm `settle`:
  settleResponse.transaction  -> step1 executed settlement id (settle_and_finalize + distribute)
  settleResponse.amount       -> actual metered amount
  requirements.maxAmount      -> authorized ceiling (signed); refund = ceiling - actual
  voucher                     -> step0 in-progress assertion (operator voucher)

The two #2666 normative points, shown as a passing test on SVM:
  - step0 binds the voucher (assertion); step1 binds the FINALIZED net-balance-change.
  - amount/ceiling are NOT in the join key, so a receipt against the 5.00 ceiling
    binds to a 1.20 settlement.

The receipt is signed with a fresh THROWAWAY key (keys/es256_public.pem) only to
exercise the checker end-to-end; a production receipt is signed by the SEP-2828 issuer.
"""
import json, hashlib
from pathlib import Path
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
ACTION_KEYS = ("agentId", "actionType", "scope", "timestampMs", "seq", "terminal")
DECISION_BLOCKS = ("version", "alg", "backLink", "decisionDerived", "issuerAsserted")
jcs = lambda o: rfc8785.dumps(o)
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()

src = json.loads((HERE / "sample-settle-output.json").read_text())
sr, req, vou, act = src["settleResponse"], src["requirements"], src["voucher"], src["action"]
ceiling, actual = req["maxAmount"], sr["amount"]
refunded = str(int(ceiling) - int(actual))

priv = ec.generate_private_key(ec.SECP256R1())
(HERE / "keys").mkdir(exist_ok=True)
(HERE / "keys" / "es256_public.pem").write_bytes(priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def sign(o):
    der = priv.sign(jcs(o), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()

COMMON = {"rail": "svm", "scheme": "upto", "network": sr["network"], "asset": req["asset"],
          "decimals": req["decimals"], "payTo": req["payTo"], "payer": sr["payer"],
          "channelId": src["channelId"], "authorizedCeiling": ceiling}
STEP0 = {**COMMON, "assertedFrom": "operator-voucher", "status": "in-progress",
         "amount": vou["cumulativeAmount"], "voucher": dict(vou)}
STEP1 = {**COMMON, "assertedFrom": "net-balance-change-to-payTo", "status": "finalized",
         "amount": actual, "refunded": refunded, "transaction": sr["transaction"],
         "verifiedBy": "facilitator://svm-upto"}

def settlement(seq, terminal, block):
    rec = {"actionType": act["actionType"], "agentId": act["agentId"],
           "schema": "x402.settlement.svm/v0", "scope": act["scope"], "seq": seq,
           "settlement": block, "terminal": terminal, "timestampMs": act["timestampMs"]}
    rec["actionRef"] = sha(jcs({k: rec[k] for k in ACTION_KEYS}))
    return rec

def receipt(stl, nonce, anonce):
    r = {"version": 1, "alg": "ES256",
         "backLink": {"attestationDigest": sha(("attest|" + anonce).encode()),
                      "attestationNonce": anonce},
         "decisionDerived": {"decidedAt": "2026-06-24T12:00:00Z", "decision": "allow",
             "evidenceRef": {"canonicalization": "JCS", "digest": sha(jcs(stl)),
                 "ref": "x402:action_ref/" + stl["actionRef"], "schema": stl["schema"]},
             "policyId": "policy:x402-upto/1",
             "reason": "agent metered usage within the authorized ceiling",
             "riskScore": "0.10", "thresholdAllow": "0.30", "thresholdBlock": "0.80"},
         "issuerAsserted": {"alg": "ES256", "iat": "2026-06-24T12:00:00Z",
             "iss": "issuer://demo-sep2828", "nonce": nonce, "secretVersion": "v1",
             "sub": act["agentId"]}}
    r["signature"] = sign({k: r[k] for k in DECISION_BLOCKS})
    return r

s0, s1 = settlement(0, False, STEP0), settlement(1, True, STEP1)
r0, r1 = receipt(s0, "d-svm-0", "x402-svm-0"), receipt(s1, "d-svm-1", "x402-svm-1")

def w(rel, obj):
    p = HERE / rel; p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

w("svm/step0/settlement.json", s0); w("svm/step0/receipt.json", r0)
w("svm/step1/settlement.json", s1); w("svm/step1/receipt.json", r1)
w("expected.json", {"svm": {"lifecycle_distinguishes_terminal": True,
    "step0": {"action_ref_recomputes": True, "receipt_signature_ok": True, "settlement_binding_resolves": True},
    "step1": {"action_ref_recomputes": True, "receipt_signature_ok": True, "settlement_binding_resolves": True}}})
print(f"emitted svm/upto vector from settle output: ceiling {ceiling} actual {actual} "
      f"refunded {refunded} (decimals {req['decimals']})")
print(f"  step0 binds the voucher (in-progress) | step1 binds {sr['transaction'][:16]}... (finalized)")
print("  next: python _check_independent.py")
