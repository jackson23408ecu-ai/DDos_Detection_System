#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path
from typing import Dict, List

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dl.service.infer import DLInference


class PredictRequest(BaseModel):
    seq: List[Dict]


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def create_app(model_path: Path, scaler_path: Path) -> FastAPI:
    app = FastAPI(title="DL Inference Service")
    infer = DLInference(model_path, scaler_path)

    @app.get("/health")
    def health():
        return {"ok": True, "model_version": infer.model_version}

    @app.post("/predict")
    def predict(req: PredictRequest):
        try:
            result = infer.predict(req.seq)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"internal_error: {e}")
        return result

    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="dl/config.yaml")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    svc_cfg = cfg.get("service", {})
    host = str(svc_cfg.get("host", "0.0.0.0"))
    port = int(svc_cfg.get("port", 8001))
    model_path = Path(svc_cfg.get("model_path", "models/dl_model.pt"))
    scaler_path = Path(svc_cfg.get("scaler_path", "models/dl_scaler.json"))
    if not model_path.is_absolute():
        model_path = ROOT / model_path
    if not scaler_path.is_absolute():
        scaler_path = ROOT / scaler_path

    app = create_app(model_path, scaler_path)

    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
