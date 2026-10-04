"""Run with:  python -m unittest discover -s tests -v"""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

from services.risk_engine import analyze_email, classify
from services.url_analyzer import analyze_url
from services.attachment_analyzer import analyze_attachment
from services.sender_analyzer import analyze_sender
from services.content_analyzer import analyze_content

LEGIT = ('"Priya" <priya@university.example.edu>', "Project update",
         "Hi Sam, notes attached. See https://university.example.edu/course Thanks")
PHISH = ('"PayPal Security" <support@paypa1-secure-login.example.xyz>', "URGENT: Verify your account now!!!",
         "Dear customer, unauthorized activity. Confirm your password immediately: http://198.51.100.7/secure/login/verify")


class EngineTests(unittest.TestCase):
    def test_legit_is_safe(self):
        self.assertIn(analyze_email(*LEGIT)["classification"], ("SAFE", "LOW RISK"))

    def test_phish_is_high_risk(self):
        r = analyze_email(*PHISH, attachment="invoice.pdf.exe")
        self.assertEqual(r["classification"], "HIGH RISK / LIKELY PHISHING")
        self.assertGreaterEqual(r["risk_score"], 60)

    def test_url_checks(self):
        names = lambda u: [f["indicator"] for f in analyze_url(u)["findings"]]
        self.assertEqual(names("https://shop.example.com/orders"), [])
        self.assertIn("Raw IP address URL", names("http://198.51.100.7/x"))
        self.assertIn("Non-HTTPS link", names("http://example.com"))
        self.assertIn("Excessive subdomains", names("https://a.b.c.d.example.com"))
        self.assertIn("Suspicious keywords in URL", names("https://example.com/login/verify"))

    def test_attachments(self):
        self.assertEqual(analyze_attachment("report.pdf"), [])
        self.assertEqual(analyze_attachment("setup.exe")[0]["indicator"], "Executable attachment")
        self.assertEqual(analyze_attachment("invoice.pdf.exe")[0]["indicator"], "Double file extension")

    def test_invalid_sender(self):
        self.assertEqual(analyze_sender("not-an-email")["findings"][0]["indicator"], "Invalid sender address")

    def test_empty_inputs_do_not_crash(self):
        names = [f["indicator"] for f in analyze_content("", "")["findings"]]
        self.assertIn("Empty subject", names)
        analyze_email("", "", "")  # must not raise

    def test_score_boundaries(self):
        self.assertEqual(classify(14), "SAFE"); self.assertEqual(classify(15), "LOW RISK")
        self.assertEqual(classify(35), "SUSPICIOUS"); self.assertEqual(classify(60), "HIGH RISK / LIKELY PHISHING")

    def test_no_url_ok(self):
        self.assertEqual(analyze_email("a@example.com", "Hi", "Lunch?")["urls"], [])


class ApiDbTests(unittest.TestCase):
    def setUp(self):
        import app as appmod
        self.c = appmod.app.test_client()

    def test_validation(self):
        self.assertEqual(self.c.post("/api/analyze", json={}).status_code, 400)

    def test_save_and_history(self):
        r = self.c.post("/api/analyze", json={"sender": PHISH[0], "subject": PHISH[1], "body": PHISH[2]})
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(len(self.c.get("/api/history").get_json()), 1)
        self.assertGreaterEqual(self.c.get("/api/stats").get_json()["total"], 1)


if __name__ == "__main__":
    unittest.main()
