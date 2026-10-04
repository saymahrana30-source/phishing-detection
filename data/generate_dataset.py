"""Generate a SYNTHETIC email dataset (fictional brands/domains only, no real data)."""
import csv, random, os

random.seed(42)
OUT = os.path.join(os.path.dirname(__file__), "phishing_email_dataset.csv")

PHISH_SUBJECTS = ["URGENT: Verify your account now", "Your account will be suspended", "Payment failed - update billing",
                  "Security alert: unauthorized activity", "Congratulations! You have won a prize",
                  "Final notice: confirm your identity", "Invoice attached - immediate action"]
PHISH_BODIES = [
    "Dear customer, we detected unauthorized activity. Verify your account immediately: http://secure-login-verify.example.test/signin or your account will be suspended.",
    "Your payment failed. Update your billing details within 24 hours at http://198.51.100.7/billing/confirm to avoid legal action.",
    "Congratulations! You have won a free gift. Claim your prize now, send your bank details and password to confirm.",
    "FINAL NOTICE: confirm your identity and enter your password at http://acc0unt-update.example.xyz/login. Act now!!!",
    "Dear user, please buy gift cards and send the codes right away. This is urgent and confidential.",
    "Security code required. Sign in to verify your account: http://bit.ly/fake-demo-link or it will be permanently locked.",
]
SAFE_SUBJECTS = ["Team meeting notes", "Lunch on Friday?", "Project update for week 12", "Your order has shipped",
                 "Class schedule change", "Monthly newsletter", "Re: Question about the assignment"]
SAFE_BODIES = [
    "Hi Priya, attaching the notes from today's meeting. Let me know if I missed anything. Thanks, Sam",
    "Hello team, the project demo is moved to Thursday at 3 PM in room 204. See you there.",
    "Hi, your order #4821 has shipped and should arrive in 3 days. Track it at https://shop.example.com/orders/4821.",
    "Hey, are you free for lunch on Friday? There's a new place near campus.",
    "Dear students, the lecture on Monday is rescheduled to Wednesday. Slides are on the course page https://university.example.edu/course.",
    "Hi Alex, thanks for the quick review. I'll merge the changes tomorrow morning.",
]
NOISE = ["", " Thanks.", " Regards.", " Please reply.", " Have a good day."]


def make(rows, subjects, bodies, label, n):
    for _ in range(n):
        rows.append([random.choice(subjects), random.choice(bodies) + random.choice(NOISE), label])


if __name__ == "__main__":
    rows = []
    make(rows, PHISH_SUBJECTS, PHISH_BODIES, 1, 300)
    make(rows, SAFE_SUBJECTS, SAFE_BODIES, 0, 300)
    random.shuffle(rows)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subject", "body", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} synthetic emails to {OUT}")
