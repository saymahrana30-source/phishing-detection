"""Train an OPTIONAL TF-IDF + Logistic Regression model and evaluate it."""
import os, json
import pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "phishing_email_dataset.csv")
MODEL = os.path.join(ROOT, "models", "phish_model.joblib")
REPORT = os.path.join(ROOT, "reports", "ml_evaluation.json")
df = pd.read_csv(DATA).fillna("")

# Convert Arrow/Pandas columns to normal Python lists
X = (df["subject"].astype(str) + " " + df["body"].astype(str)).tolist()
y = df["label"].astype(str).tolist()

# Stratify keeps the phishing/legit ratio equal in train and test
Xtr, Xte, ytr, yte = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=2, stop_words="english"),
                      LogisticRegression(max_iter=1000))
model.fit(Xtr, ytr)
pred = model.predict(Xte)

cm = confusion_matrix(yte, pred).tolist()
rep = classification_report(yte, pred, target_names=["legitimate", "phishing"], output_dict=True)
print(classification_report(yte, pred, target_names=["legitimate", "phishing"]))
print("Confusion matrix [[TN, FP], [FN, TP]]:", cm)
with open(REPORT, "w") as f:
    json.dump({"confusion_matrix": cm, "report": rep}, f, indent=2)
joblib.dump(model, MODEL)
print("Saved model ->", MODEL)
print("NOTE: scores are high because the dataset is small and synthetic. Real data is far messier.")
