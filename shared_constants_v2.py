"""
shared_constants_v2.py
======================
Corrected constants for the MemAE-inversion fix.  Re-exports everything from
shared_constants.py unchanged, then OVERRIDES ATTACK_WINDOWS_LNX to add the
14th window (T1548.003 sudo privilege escalation) that was historically dropped.

The T1548.003 timestamps come from attack_log.txt (see
investigate_t1548003_contamination.py).  We apply the same -60s/+60s buffer the
other windows use.  Phase is 'NOVEL' (it is an unseen-at-train technique).

Import with:  from shared_constants_v2 import *      (gets ATTACK_WINDOWS_LNX_V2)
or specifically:  from shared_constants_v2 import ATTACK_WINDOWS_LNX_V2
"""

from datetime import timedelta

from shared_constants import *            # noqa: F401,F403  (re-export all)
from shared_constants import ATTACK_WINDOWS_LNX as _ORIG_WINDOWS
from shared_features import _parse_iso

# T1548.003 logged run (attack_log.txt): START 2026-05-25T14:33:42Z END 17:59:31Z
_T1548_START = "2026-05-25T14:33:42Z"
_T1548_END = "2026-05-25T17:59:31Z"


def _buffer(iso, secs):
    dt = _parse_iso(iso) + timedelta(seconds=secs)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# same -60/+60 buffer convention as the original windows
_T1548_WINDOW = ("T1548.003", "NOVEL",
                 _buffer(_T1548_START, -60), _buffer(_T1548_END, +60))

# 14-window corrected list (insert T1548.003 in chronological position)
ATTACK_WINDOWS_LNX_V2 = list(_ORIG_WINDOWS) + [_T1548_WINDOW]
ATTACK_WINDOWS_LNX_V2.sort(key=lambda w: _parse_iso(w[2]))

# also expose under the canonical name for code that does `from ... import *`
ATTACK_WINDOWS_LNX = ATTACK_WINDOWS_LNX_V2     # noqa: F811
