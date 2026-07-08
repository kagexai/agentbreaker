"""Multimodal attack synthesis: text-in-image injection (+ QR when available)."""

from __future__ import annotations

import base64

import pytest

from agentbreaker import multimodal as M


def test_backends_status_reports_pil():
    st = M.backends_status()
    assert "pil" in st and "qrcode" in st
    assert st["attacks_available"] >= (1 if st["pil"] else 0)


@pytest.mark.skipif(not M.pil_available(), reason="PIL not installed")
def test_text_overlay_produces_valid_png():
    attacks = M.image_attacks()
    overlay = [a for a in attacks if a.technique == "image_text_overlay"]
    assert overlay, "expected a text-overlay image attack when PIL is present"
    a = overlay[0]
    raw = base64.b64decode(a.media_b64)
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"     # valid PNG signature
    assert a.carrier_prompt and a.media_type == "image/png"


@pytest.mark.skipif(not M.pil_available(), reason="PIL not installed")
def test_media_item_bridge_to_target():
    a = M.image_attacks()[0]
    mi = a.to_media_item()
    assert mi.type == "image/png" and mi.data == a.media_b64


def test_qr_graceful_when_absent():
    # make_qr returns None (not an error) when the qrcode lib is missing
    result = M.make_qr("hello")
    if M.qrcode_available():
        assert result and base64.b64decode(result)[:8] == b"\x89PNG\r\n\x1a\n"
    else:
        assert result is None


def test_canary_is_stable():
    assert M.canary_marker() == "IMG-CANARY-OK"
    assert M.canary_marker() in M._INJECTION_TEXT
