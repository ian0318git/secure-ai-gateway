"""Response protection (M4): scan, validate, restore (DESIGN §17).

Everything here runs inside the trusted environment (T-I03): no raw
value, no token value, and no restored text ever leaves through logs
or report surfaces.
"""

from secure_ai_gateway.response.guard import ResponseGuard, ResponseOutcome

__all__ = ["ResponseGuard", "ResponseOutcome"]
