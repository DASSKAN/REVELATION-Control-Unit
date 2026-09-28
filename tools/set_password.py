"""
Change an operator password or add a user.

    python tools/set_password.py supervisor
    python tools/set_password.py priya --role OPERATOR --name "ASI Priya"
Roles: VIEWER (watch only), OPERATOR (runs, dispatch, messages), SUPERVISOR (+ security settings, demos, device keys)
Restart the Control Unit afterwards.
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from control_unit import config  # noqa: E402
from control_unit.security import ROLES, Security  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("username")
ap.add_argument("--role", choices=list(ROLES))
ap.add_argument("--name")
a = ap.parse_args()
sec = Security(os.path.dirname(os.path.abspath(config.DB_PATH)), log=lambda *_: None)
u = sec.users.get(a.username.lower(), {})
pw = getpass.getpass(f"New password for {a.username}: ")
if len(pw) < 8 or pw != getpass.getpass("Repeat: "):
    sys.exit("Passwords must match and be at least 8 characters.")
sec.set_user(a.username.lower(), pw, a.role or u.get("role", "OPERATOR"), a.name or u.get("name", a.username))
print(f"Saved {a.username} ({a.role or u.get('role', 'OPERATOR')}). Restart the Control Unit.")
