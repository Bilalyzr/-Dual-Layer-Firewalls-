"""
EPIC G tests — multi-modal fusion + online baseline adaptation.
"""
import pytest

from engine.biometric.fusion import fuse, FusionInput
from engine.biometric.online import AdaptiveBaseline, update_on_genuine, get_adaptive_baseline


def test_fuse_single_modality():
    r = fuse(FusionInput(keystroke_p_genuine=0.9))
    assert r["trust_score"] == 90.0
    assert r["modalities"] == ["keystroke"]


def test_fuse_multi_modal():
    r = fuse(FusionInput(keystroke_p_genuine=0.9, mouse_score=0.8, session_trust=0.7))
    assert 70 < r["trust_score"] < 90
    assert set(r["modalities"]) == {"keystroke", "mouse", "session"}


def test_fuse_missing_modality_redistributes_weight():
    r = fuse(FusionInput(keystroke_p_genuine=1.0, mouse_score=0.0))
    # without session, keystroke+mouse split; keystroke weight 0.6/(0.6+0.3)=0.667
    assert 30 < r["trust_score"] < 70


def test_fuse_no_signals_returns_default():
    r = fuse(FusionInput())
    assert r["trust_score"] == 100.0


def test_fuse_clamps_bounds():
    r = fuse(FusionInput(keystroke_p_genuine=5.0))  # out of range
    assert r["trust_score"] <= 100.0


def test_adaptive_baseline_updates_on_genuine():
    b = AdaptiveBaseline(dwell_mean=90.0, dwell_std=20.0, flight_mean=40.0, flight_std=25.0)
    b.update([100, 102, 98], [50, 52, 48])
    # mean should move slightly toward 100
    assert 90 < b.dwell_mean < 100
    assert b.n_updates == 1


def test_adaptive_baseline_is_conservative():
    """A single batch shouldn't drastically move the baseline (alpha=0.05)."""
    b = AdaptiveBaseline(dwell_mean=90.0, dwell_std=20.0, flight_mean=40.0, flight_std=25.0)
    b.update([200, 210, 205], [150, 155, 148])
    # even an anomalous batch only nudges 5% toward 200 → ~95ish, not ~200
    assert b.dwell_mean < 100


def test_update_on_genuine_helper():
    snap = update_on_genuine("epicG-user", [92, 93, 91], [41, 42, 40])
    assert "dwell_mean" in snap
    assert snap["n_updates"] >= 1
