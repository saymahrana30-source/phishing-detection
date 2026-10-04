# Execution + GitHub + Resume cheat-sheet

## Run (12 steps)
1. open folder terminal in `phishing-detector/`
2. `python3 -m venv venv`  3. activate it  4. `pip install -r requirements.txt`
5. `python data/generate_dataset.py`  6. `python ml/train_model.py`
7. `python -m unittest discover -s tests -v` (expect OK)  8. `python app.py`
9. Open http://127.0.0.1:5000  10. Click "Load legitimate sample" -> Analyze (expect SAFE)
11. Click "Load phishing sample" -> Analyze (expect HIGH RISK)  12. Open Dashboard + History tabs

## GitHub
` gitinit && git add . && git commit -m "Phishing detection dashboard"` then create a repo and push.
Commit in small steps (analyzers, engine, ML, dashboard, tests). Add 3-4 screenshots to `screenshots/`
and embed them in the README. Topics: cybersecurity, phishing, flask, machine-learning, soc.

## Resume bullet
Built a Flask + scikit-learn phishing detection dashboard with explainable rule-based scoring
(sender, URL, content, attachment analysis), hybrid ML, SQLite history and analytics charts;
validated with 10 automated tests.

## Interview Q&A
- Why not only ML? Rules are explainable and work without data; ML catches wording rules miss.
- Why is accuracy ~100%? Small synthetic data - not a real-world claim.
- What are false positives? Safe emails flagged; costly because users stop trusting alerts.
- How would you improve it? SPF/DKIM/DMARC, real datasets, domain age, feedback loop.
- How is it secure? Input limits, parameterized SQL, textContent rendering, no URL fetching, localhost only.
