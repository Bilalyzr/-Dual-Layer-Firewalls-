"""
EPIC G — Transformer sequence model for keystroke dynamics.

Replaces the LSTM with a lightweight Transformer encoder (self-attention
captures long-range temporal dependencies the LSTM's recurrence approximates
poorly). Same embed_dim contract as the LSTM so the ensemble + scorer need no
changes — drop-in replacement selected by USE_TRANSFORMER=true.

Architecture: 2 Transformer encoder layers (nhead=2, dim_feedforward=64) over a
linear projection of (dwell, flight) → 16-d embedding. ~15K params, CPU-trainable.
"""
from __future__ import annotations
from pathlib import Path
import os

import torch
import torch.nn as nn

EMBED_DIM = 16  # same as the LSTM so the ensemble feature size is unchanged
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "biometric_transformer.pt"


class KeystrokeTransformer(nn.Module):
    def __init__(self, input_size: int = 2, d_model: int = 32, nhead: int = 2,
                 num_layers: int = 2, embed_dim: int = EMBED_DIM):
        super().__init__()
        self.proj_in = nn.Linear(input_size, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=64, batch_first=True, dropout=0.1
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.proj_out = nn.Linear(d_model, embed_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, input_size)
        h = self.proj_in(x)
        h = self.encoder(h)
        # mean-pool over the sequence (unlike LSTM's last-state, attention has no
        # privileged last position)
        pooled = h.mean(dim=1)
        return self.proj_out(pooled)


def use_transformer() -> bool:
    return os.getenv("USE_TRANSFORMER", "false").lower() == "true" and MODEL_PATH.exists()


_model: KeystrokeTransformer | None = None
_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def get_model() -> KeystrokeTransformer:
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"transformer artifact not found at {MODEL_PATH}. "
                "Train with USE_TRANSFORMER=true python -m engine.biometric.train_biometric"
            )
        m = KeystrokeTransformer()
        m.load_state_dict(torch.load(MODEL_PATH, map_location=_device, weights_only=True))
        m.to(_device)
        m.eval()
        _model = m
    return _model


@torch.no_grad()
def embed_batch(seqs) -> "numpy.ndarray":
    """Embed (N, seq_len, 2) sequences → (N, EMBED_DIM). Drop-in for lstm_model.embed_batch."""
    import numpy as np

    m = get_model()
    x = torch.from_numpy(seqs.astype("float32")).to(_device)
    return m(x).cpu().numpy().astype("float32")
