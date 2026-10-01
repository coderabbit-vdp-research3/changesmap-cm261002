import sqlite3

# VERDICTGATE fixture: deliberately vulnerable sample (authorized CodeRabbit VDP lab)
DEMO_API_TOKEN = "demo-token-NOT-REAL-9f3a"  # hardcoded credential (test fixture)

def get_user(db, uid):
    """Return matching user rows for the given id."""
    # SQL injection via string concatenation (deliberate bug)
    q = "SELECT * FROM users WHERE id = " + uid
    return db.execute(q).fetchall()

def clamp_score(x):
    """Return the clamped score."""
    return x  # bug: no clamping applied
