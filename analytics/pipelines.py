# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import GradientBoostingRegressor, IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, mean_absolute_error, roc_auc_score
from sklearn.model_selection import train_test_split

from analytics.config import drift_threshold, models_storage_dir
from analytics.dataset_builder import build_training_dataset
from analytics.feature_store import materialize_features
from analytics.model_registry import (
    get_latest_prediction,
    get_production_model,
    register_model,
    store_prediction,
    upsert_tenant_summary,
)
from analytics.db import session_scope
from sqlalchemy import text


CLASSIFICATION_TASKS = {
    "next_step_prediction",
    "control_effectiveness",
    "detection_coverage",
    "remediation_priority",
}
REGRESSION_TASKS = {
    "path_success_probability",
    "operator_efficiency_score",
    "residual_risk",
    "attack_probability_forecast",
    "risk_projection",
    "defense_improvement_projection",
}
ANOMALY_TASKS = {"baseline_behavior"}


def _task_algorithm(task_name: str):
    if task_name in CLASSIFICATION_TASKS:
        return "RandomForestClassifier", RandomForestClassifier(n_estimators=250, random_state=42)
    if task_name in REGRESSION_TASKS:
        return "GradientBoostingRegressor", GradientBoostingRegressor(random_state=42)
    if task_name in ANOMALY_TASKS:
        return "IsolationForest", IsolationForest(random_state=42, contamination=0.1)
    return "RandomForestClassifier", RandomForestClassifier(n_estimators=200, random_state=42)


def _artifact_dir(tenant_id: str, task_name: str, version: str) -> Path:
    d = models_storage_dir() / tenant_id / task_name / version
    d.mkdir(parents=True, exist_ok=True)
    return d


def train_model(task_name: str, tenant_id: str) -> dict[str, Any]:
    # 1) load dataset (materialize first for reproducibility snapshot).
    materialize_features(tenant_id=tenant_id, window="30d")
    df, dataset_hash, _dataset_path = build_training_dataset(tenant_id=tenant_id, task_name=task_name)
    if df.empty:
        raise ValueError("no training data available")

    feature_cols = [c for c in df.columns if c not in {"entity_id", "label", "task_name", "tenant_id", "cutoff_ts"}]
    X = df[feature_cols].astype(float)
    y = df["label"].astype(float)

    # 2) split train/test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    algo_name, model = _task_algorithm(task_name)

    # 3) train model
    if algo_name == "RandomForestClassifier":
        y_train_cls = (y_train > y_train.median()).astype(int)
        y_test_cls = (y_test > y_test.median()).astype(int)
        model.fit(X_train, y_train_cls)
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": float(accuracy_score(y_test_cls, y_pred)),
            "samples_train": int(len(X_train)),
            "samples_test": int(len(X_test)),
        }
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_test)[:, 1]
            try:
                metrics["roc_auc"] = float(roc_auc_score(y_test_cls, proba))
            except Exception:
                pass
    elif algo_name == "GradientBoostingRegressor":
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        metrics = {
            "mae": float(mean_absolute_error(y_test, y_pred)),
            "samples_train": int(len(X_train)),
            "samples_test": int(len(X_test)),
        }
    else:  # IsolationForest
        model.fit(X_train)
        scores = model.decision_function(X_test)
        metrics = {
            "decision_score_mean": float(np.mean(scores)),
            "samples_train": int(len(X_train)),
            "samples_test": int(len(X_test)),
        }

    # 4) evaluate metrics done above

    # 5) compute SHAP
    background = X_train.sample(min(128, len(X_train)), random_state=42)
    explain_sample = X_test.sample(min(64, len(X_test)), random_state=42)
    if algo_name in {"RandomForestClassifier", "GradientBoostingRegressor"}:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(explain_sample)
    else:
        # IsolationForest has no native tree shap in many setups.
        explainer = shap.Explainer(model.decision_function, background)
        shap_values = explainer(explain_sample)

    # 6) store model artifact
    version = datetime.now(timezone.utc).strftime("%Y.%m.%d.%H%M%S")
    out_dir = _artifact_dir(tenant_id, task_name, version)
    model_path = out_dir / "model.pkl"
    metrics_path = out_dir / "metrics.json"
    features_path = out_dir / "features.json"
    explainer_path = out_dir / "explainer.pkl"
    shap_path = out_dir / "shap_summary.json"
    joblib.dump(model, model_path)
    with metrics_path.open("w", encoding="utf-8") as h:
        json.dump(metrics, h, indent=2, sort_keys=True)
    with features_path.open("w", encoding="utf-8") as h:
        json.dump({"feature_names": feature_cols}, h, indent=2, sort_keys=True)
    with explainer_path.open("wb") as h:
        pickle.dump(explainer, h)
    if isinstance(shap_values, list):
        arr = np.array(shap_values[0])
    elif hasattr(shap_values, "values"):
        arr = np.array(shap_values.values)
    else:
        arr = np.array(shap_values)
    shap_importance = {feature_cols[i]: float(np.mean(np.abs(arr[:, i]))) for i in range(arr.shape[1])}
    with shap_path.open("w", encoding="utf-8") as h:
        json.dump({"global_importance": shap_importance}, h, indent=2, sort_keys=True)

    # 7) register model
    model_id = register_model(
        tenant_id=tenant_id,
        task=task_name,
        version=version,
        dataset_hash=dataset_hash,
        algorithm=algo_name,
        hyperparameters=model.get_params(deep=False),
        metrics=metrics,
        stage="experimental",
    )
    return {
        "model_id": model_id,
        "task": task_name,
        "tenant_id": tenant_id,
        "version": version,
        "dataset_hash": dataset_hash,
        "artifact_dir": str(out_dir),
    }


def _load_artifacts(tenant_id: str, task: str, version: str):
    base = _artifact_dir(tenant_id, task, version)
    model = joblib.load(base / "model.pkl")
    with (base / "features.json").open("r", encoding="utf-8") as h:
        feature_meta = json.load(h)
    with (base / "explainer.pkl").open("rb") as h:
        explainer = pickle.load(h)
    return model, feature_meta.get("feature_names", []), explainer


def run_inference(task: str, tenant_id: str, entity_id: str) -> dict[str, Any]:
    # 1) load production model
    model_meta = get_production_model(tenant_id, task)
    if not model_meta:
        raise ValueError("no production model available")
    model, feature_names, explainer = _load_artifacts(tenant_id, task, str(model_meta["version"]))

    # 2) fetch point-in-time features
    with session_scope() as db:
        rows = db.execute(
            text(
                """SELECT feature_name, value
                   FROM analytics.features
                   WHERE entity_id=:entity_id
                     AND ts <= :cutoff
                   ORDER BY ts DESC"""
            ),
            {"entity_id": entity_id, "cutoff": datetime.now(timezone.utc)},
        ).mappings().all()
    vector = {name: 0.0 for name in feature_names}
    for r in rows:
        fn = str(r["feature_name"])
        if fn in vector and vector[fn] == 0.0:
            vector[fn] = float(r["value"] or 0.0)
    x = pd.DataFrame([vector], columns=feature_names)

    # 3) predict
    if hasattr(model, "predict_proba"):
        p = float(model.predict_proba(x)[0][1])
        prediction = {"score": p, "confidence": max(0.5, abs(p - 0.5) * 2.0)}
    else:
        p = float(model.predict(x)[0])
        prediction = {"score": p, "confidence": 0.7}

    # 4) compute SHAP explanation
    if hasattr(explainer, "shap_values"):
        sv = explainer.shap_values(x)
        if isinstance(sv, list):
            vals = np.array(sv[0][0])
        else:
            vals = np.array(sv[0])
    else:
        e = explainer(x)
        vals = np.array(e.values[0])
    ranked = sorted(
        [{"feature": feature_names[i], "impact": float(vals[i])} for i in range(len(feature_names))],
        key=lambda z: abs(z["impact"]),
        reverse=True,
    )[:5]

    # 5) store prediction
    explanation = {"top_factors": ranked}
    pred_id = store_prediction(
        tenant_id=tenant_id,
        model_id=int(model_meta["id"]),
        entity_id=entity_id,
        prediction=prediction,
        explanation=explanation,
    )
    health = monitor_model_health(tenant_id=tenant_id, model_id=int(model_meta["id"]))
    return {
        "prediction_id": pred_id,
        "model_id": int(model_meta["id"]),
        "model_version": str(model_meta["version"]),
        "score": prediction["score"],
        "confidence": prediction["confidence"],
        "explanation": explanation,
        "model_health": health,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def tenant_security_summary(tenant_id: str) -> dict[str, Any]:
    with session_scope() as db:
        risk_rows = db.execute(
            text(
                """SELECT prediction, explanation, created_at, m.version AS model_version
                   FROM analytics.predictions p
                   JOIN analytics.models m ON m.id=p.model_id
                   WHERE p.tenant_id=:tenant_id
                     AND m.task IN ('control_effectiveness','residual_risk','detection_coverage')
                   ORDER BY p.created_at DESC
                   LIMIT 100"""
            ),
            {"tenant_id": tenant_id},
        ).mappings().all()
    if not risk_rows:
        summary = {
            "security_posture": {"score": 0.0, "confidence": 0.0},
            "trend": {"direction": "stable", "delta": 0.0},
            "maturity_level": "baseline",
            "model_version": "n/a",
        }
        upsert_tenant_summary(
            tenant_id=tenant_id,
            security_posture=summary["security_posture"],
            trend=summary["trend"],
            maturity_level=summary["maturity_level"],
            generated_by_model_version=summary["model_version"],
        )
        return summary

    scores = [float((r["prediction"] or {}).get("score", 0.0)) for r in risk_rows]
    score = float(np.mean(scores))
    confidence = float(np.clip(np.std(scores) * -1 + 1, 0.5, 0.95))
    delta = 0.0
    if len(scores) > 1:
        delta = scores[0] - scores[-1]
    direction = "improving" if delta < 0 else "worsening" if delta > 0 else "stable"
    maturity = "advanced" if score < 0.35 else "intermediate" if score < 0.65 else "developing"
    model_version = str(risk_rows[0]["model_version"])

    summary = {
        "security_posture": {"score": score, "confidence": confidence},
        "trend": {"direction": direction, "delta": delta},
        "maturity_level": maturity,
        "model_version": model_version,
    }
    upsert_tenant_summary(
        tenant_id=tenant_id,
        security_posture=summary["security_posture"],
        trend=summary["trend"],
        maturity_level=summary["maturity_level"],
        generated_by_model_version=model_version,
    )
    return summary


def monitor_model_health(tenant_id: str, model_id: int) -> dict[str, Any]:
    with session_scope() as db:
        pred_vals = [
            float((r[0] or {}).get("score", 0.0))
            for r in db.execute(
                text("SELECT prediction FROM analytics.predictions WHERE tenant_id=:tenant_id AND model_id=:model_id"),
                {"tenant_id": tenant_id, "model_id": model_id},
            ).all()
        ]
        feat_vals = [
            float(r[0] or 0.0)
            for r in db.execute(
                text(
                    """SELECT f.value
                       FROM analytics.features f
                       JOIN analytics.models m ON m.tenant_id=:tenant_id
                       WHERE m.id=:model_id
                       LIMIT 1000"""
                ),
                {"tenant_id": tenant_id, "model_id": model_id},
            ).all()
        ]
        feature_drift = float(np.std(feat_vals)) if feat_vals else 0.0
        prediction_drift = float(np.std(pred_vals)) if pred_vals else 0.0
        threshold = drift_threshold()
        alert = feature_drift > threshold or prediction_drift > threshold
        db.execute(
            text(
                """INSERT INTO analytics.model_health
                   (tenant_id, model_id, feature_drift_score, prediction_drift_score, alert_triggered, details)
                   VALUES (:tenant_id, :model_id, :feature_drift_score, :prediction_drift_score, :alert_triggered, CAST(:details AS JSONB))"""
            ),
            {
                "tenant_id": tenant_id,
                "model_id": model_id,
                "feature_drift_score": feature_drift,
                "prediction_drift_score": prediction_drift,
                "alert_triggered": alert,
                "details": json.dumps({"threshold": threshold}, default=str),
            },
        )
    return {
        "feature_drift_score": feature_drift,
        "prediction_drift_score": prediction_drift,
        "alert_triggered": alert,
    }
