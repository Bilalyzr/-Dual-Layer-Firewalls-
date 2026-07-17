"""
Lightweight LSTM for keystroke-dynamics embeddings (Req 3.2).

Takes a (batch, seq_len, 2) normalized [dwell, flight] tensor and emits a fixed-
size embedding (the last hidden state). The embedding is concatenated with
hand-crafted stats and fed to the ensemble — the LSTM is NOT the final
classifier, it's a temporal feature extractor.

Design goals (per "lightweight models" choice):
  - trains in seconds on CPU
  - ~10K params
  - no GPU dependency
"""
from __future__ import annotations
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

EMBED_DIM = 16  # output embedding dimensionality (last hidden state)
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "biometric_lstm.pt"


class KeystrokeLSTM(nn.Module):
    def __init__(self, input_size: int = 2, hidden_size: int = 32, num_layers: int = 2, embed_dim: int = EMBED_DIM):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0,
        )
        self.proj = nn.Linear(hidden_size, embed_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, input_size)
        out, (h_n, _) = self.lstm(x)  # h_n: (num_layers, batch, hidden)
        last = h_n[-1]                # (batch, hidden) — final layer's hidden state
        return self.proj(last)        # (batch, embed_dim)


# --------------------------------------------------------------------------- #
# Singleton loader
# --------------------------------------------------------------------------- #
_model: KeystrokeLSTM | None = None
_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def get_model() -> KeystrokeLSTM:
    """Lazy-load the trained LSTM singleton."""
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"biometric LSTM artifact not found at {MODEL_PATH}. "
                "Run: python -m engine.biometric.train_biometric"
            )
        m = KeystrokeLSTM()
        state = torch.load(MODEL_PATH, map_location=_device, weights_only=True)
        m.load_state_dict(state)
        m.to(_device)
        m.eval()
        _model = m
    return _model


def model_ready() -> bool:
    return MODEL_PATH.exists()


@torch.no_grad()
def embed_batch(seqs: np.ndarray) -> np.ndarray:
    """
    Embed a batch of sequences.

    seqs: (N, seq_len, 2) normalized float32
    returns: (N, EMBED_DIM) float32 embeddings
    """
    m = get_model()
    x = torch.from_numpy(seqs.astype(np.float32)).to(_device)
    emb = m(x)
    return emb.cpu().numpy().astype(np.float32)
