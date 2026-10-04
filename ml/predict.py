"""Load the optional ML model; return a predict function or None if not trained."""
import os, joblib

MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "phish_model.joblib")


def load_predictor():
    if not os.path.exists(MODEL):
        return None
    model = joblib.load(MODEL)
    return lambda text: float(model.predict_proba([text])[0][1])  # P(phishing)
