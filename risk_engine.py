"""
risk_engine.py
==============
Quantitative core of the Extreme Value Risk Analytics Platform.

Conventions
-----------
* Input  : 1-D array of daily SIMPLE returns r_t  (so r_t > -1).
* Loss   : L_t = -r_t   (a positive number is a loss).
* VaR    : returned as a POSITIVE fraction of portfolio value
           (0.0260 means "with probability `confidence` the 1-day loss
           will not exceed 2.60 %").

Two estimators are implemented:

1. Gaussian (variance-covariance) VaR
       VaR_c = -(mu + sigma * z_{1-c}) = -mu + sigma * z_c ,   z_c = Phi^{-1}(c)

2. EVT / Hill VaR (Peaks-over-Threshold with a Pareto tail)
   Let L_(1) >= L_(2) >= ... >= L_(n) be the descending order statistics of
   the losses and k the number of upper order statistics (the "tail size").

       Hill estimator :  xi_hat = (1/k) * SUM_{i=1..k} ln( L_(i) / L_(k+1) )
       Tail index     :  alpha  = 1 / xi_hat
       Weissman VaR   :  VaR_c  = L_(k+1) * ( (n/k) * (1 - c) ) ** (-xi_hat)

   The Weissman quantile extrapolates the fitted Pareto tail
   P(L > x) ~ (k/n) * (x / L_(k+1))^(-1/xi) beyond the threshold u = L_(k+1).
   It is only valid when (1 - c) <= k/n, i.e. the requested quantile lies
   inside the modelled tail.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence, Union

import numpy as np
from scipy.stats import norm

ArrayLike = Union[Sequence[float], np.ndarray]

MIN_OBSERVATIONS = 200   # below this the sample variance / tail fit is unreliable
MIN_TAIL_K = 10          # Hill estimator is meaningless with fewer than ~10 exceedances


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _validate_returns(returns: ArrayLike) -> np.ndarray:
    """Coerce to a 1-D float64 array and reject non-finite / impossible values."""
    arr = np.asarray(returns, dtype=np.float64)
    if arr.ndim != 1:
        raise ValueError("returns must be a 1-D array of daily returns.")
    if arr.size == 0:
        raise ValueError("returns is empty.")
    if not np.all(np.isfinite(arr)):
        raise ValueError("returns contains NaN or infinite values.")
    if np.any(arr <= -1.0):
        raise ValueError("simple returns must be strictly greater than -1 (-100 %).")
    return arr


def _validate_confidence(confidence: float) -> None:
    if not (0.0 < confidence < 1.0):
        raise ValueError("confidence must lie strictly between 0 and 1.")


# --------------------------------------------------------------------------- #
# 1. Traditional Gaussian VaR
# --------------------------------------------------------------------------- #
def gaussian_var(returns: ArrayLike, confidence: float = 0.99) -> float:
    """
    One-day Gaussian VaR (positive loss fraction).

        VaR_c = -mu + sigma * Phi^{-1}(c)

    mu    : sample mean of the returns
    sigma : unbiased sample standard deviation (ddof = 1)
    """
    _validate_confidence(confidence)
    r = _validate_returns(returns)
    if r.size < 2:
        raise ValueError("at least 2 observations are required to estimate sigma.")

    mu = float(np.mean(r))
    sigma = float(np.std(r, ddof=1))
    z_c = float(norm.ppf(confidence))          # Phi^{-1}(c)
    return -mu + sigma * z_c


# --------------------------------------------------------------------------- #
# 2. Hill estimator + EVT (Weissman) VaR
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class HillResult:
    """Output of the Hill estimator and the resulting EVT VaR."""
    xi: float            # tail index xi_hat (>= 0 by construction); larger = heavier tail
    threshold: float     # u = L_(k+1), the (k+1)-th largest loss
    k: int               # number of exceedances used in the Hill sum
    n: int               # sample size
    confidence: float    # VaR confidence level c
    var: float           # EVT (Hill/Weissman) VaR, positive loss fraction

    @property
    def tail_index(self) -> Optional[float]:
        """alpha = 1/xi (Pareto tail exponent). None when xi == 0 (no heavy tail)."""
        return (1.0 / self.xi) if self.xi > 0.0 else None


def hill_var(
    returns: ArrayLike,
    confidence: float = 0.99,
    tail_fraction: float = 0.05,
) -> HillResult:
    """
    Estimate the tail index xi with the Hill estimator on the worst
    `tail_fraction` of losses, then compute the EVT VaR via the Weissman estimator.

        k      = floor(tail_fraction * n)
        u      = L_(k+1)
        xi_hat = (1/k) * SUM_{i=1..k} ln(L_(i) / u)
        VaR_c  = u * ((n/k) * (1 - c)) ** (-xi_hat)

    The k exceedances are exactly the rows exposed by the SQL view
    `vw_ExtremeLosses` (FLOOR(5% * n) worst returns per asset).
    """
    _validate_confidence(confidence)
    if not (0.0 < tail_fraction <= 0.5):
        raise ValueError("tail_fraction must lie in (0, 0.5].")

    r = _validate_returns(returns)
    n = int(r.size)
    k = int(math.floor(tail_fraction * n))

    if n < MIN_OBSERVATIONS:
        raise ValueError(f"need at least {MIN_OBSERVATIONS} observations, got {n}.")
    if k < MIN_TAIL_K:
        raise ValueError(f"tail size k={k} is below the minimum of {MIN_TAIL_K}.")
    if (1.0 - confidence) > k / n:
        raise ValueError(
            "confidence is too low for tail extrapolation: require "
            f"1 - confidence <= k/n = {k / n:.4f}."
        )

    losses = -r
    desc = np.sort(losses)[::-1]       # L_(1) >= L_(2) >= ... >= L_(n)

    u = float(desc[k])                 # zero-based index k  ==  (k+1)-th largest loss
    if u <= 0.0:
        raise ValueError(
            "threshold loss L_(k+1) is not positive; the sample has too few "
            "losses for the Hill estimator (log of non-positive numbers)."
        )

    exceedances = desc[:k]                         # L_(1) .. L_(k)  (all >= u > 0)
    xi_hat = float(np.mean(np.log(exceedances / u)))

    var = u * ((n / k) * (1.0 - confidence)) ** (-xi_hat)
    return HillResult(xi=xi_hat, threshold=u, k=k, n=n, confidence=confidence, var=float(var))


# --------------------------------------------------------------------------- #
# Self-test: heavy-tailed data (Student-t, 3 d.o.f., true xi = 1/3) where the
# Gaussian model must underestimate tail risk.
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    from scipy.stats import t as student_t

    rng = np.random.default_rng(42)
    DOF, DAILY_VOL, N = 3, 0.01, 2520                      # ~10 years of trading days
    scale = DAILY_VOL / math.sqrt(DOF / (DOF - 2))         # so that Std[r] = 1 %
    sample = scale * rng.standard_t(DOF, size=N)

    print(f"{'conf':>7} {'Gaussian':>10} {'Hill/EVT':>10} {'True':>10}   xi_hat")
    for c in (0.99, 0.995, 0.999):
        g = gaussian_var(sample, c)
        h = hill_var(sample, c)
        true_var = scale * float(student_t.ppf(c, DOF))
        print(f"{c:>7.3f} {g:>10.4%} {h.var:>10.4%} {true_var:>10.4%}   {h.xi:.3f}")
