"""Pure Python statistical and signal processing primitives.

The detection engine relies on a handful of mathematical building blocks:
Shannon entropy for randomness, a discrete Fourier transform for periodic
command and control beacons, robust z scores for volumetric outliers,
Benford's law for numeric manipulation and simple rarity scoring for long
tail stacking. Everything here is dependency free so the engine runs on a
plain Python install.
"""

from __future__ import annotations

import cmath
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence

# --------------------------------------------------------------------------
# Entropy and string randomness
# --------------------------------------------------------------------------

_VOWELS = set("aeiouyAEIOUY")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")


def shannon_entropy(value: str | bytes) -> float:
    """Return the Shannon entropy of a string in bits per symbol."""
    if not value:
        return 0.0
    if isinstance(value, bytes):
        symbols: Sequence = value
    else:
        symbols = value
    counts = Counter(symbols)
    total = float(len(symbols))
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def normalised_entropy(value: str) -> float:
    """Entropy scaled to the 0..1 range using the alphabet actually used."""
    if not value:
        return 0.0
    distinct = len(set(value))
    if distinct <= 1:
        return 0.0
    return shannon_entropy(value) / math.log2(distinct)


def consonant_ratio(value: str) -> float:
    """Share of alphabetic characters that are consonants.

    Domain generation algorithms typically produce consonant heavy labels.
    """
    letters = [c for c in value if c.isalpha()]
    if not letters:
        return 0.0
    consonants = [c for c in letters if c not in _VOWELS]
    return len(consonants) / len(letters)


def digit_ratio(value: str) -> float:
    if not value:
        return 0.0
    return sum(1 for c in value if c.isdigit()) / len(value)


def longest_consonant_run(value: str) -> int:
    best = current = 0
    for char in value:
        if char.isalpha() and char not in _VOWELS:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def looks_hex(value: str) -> bool:
    return bool(value) and len(value) >= 8 and bool(_HEX_RE.match(value))


def looks_base64(value: str) -> bool:
    if not _B64_RE.match(value or ""):
        return False
    # Reject values that are only words or hyphenated identifiers.
    return shannon_entropy(value) >= 3.2


def dga_score(label: str) -> float:
    """Heuristic 0..1 score that a DNS label is algorithmically generated."""
    label = (label or "").strip().lower()
    if len(label) < 7:
        return 0.0
    score = 0.0
    entropy = shannon_entropy(label)
    if entropy >= 3.6:
        score += 0.35
    elif entropy >= 3.2:
        score += 0.22
    elif entropy >= 2.9:
        score += 0.10
    cons = consonant_ratio(label)
    if cons >= 0.8:
        score += 0.25
    elif cons >= 0.7:
        score += 0.15
    run = longest_consonant_run(label)
    if run >= 5:
        score += 0.2
    elif run >= 4:
        score += 0.1
    digits = digit_ratio(label)
    if 0.15 <= digits <= 0.6:
        score += 0.12
    if len(label) >= 16:
        score += 0.12
    elif len(label) >= 12:
        score += 0.06
    if looks_hex(label) and len(label) >= 16:
        score += 0.15
    return round(min(score, 1.0), 3)


# --------------------------------------------------------------------------
# Discrete Fourier transform and beacon detection
# --------------------------------------------------------------------------


def _next_power_of_two(value: int) -> int:
    power = 1
    while power < value:
        power <<= 1
    return power


def fft(samples: Sequence[float]) -> list[complex]:
    """Iterative radix 2 Cooley Tukey FFT with automatic zero padding."""
    n = len(samples)
    if n == 0:
        return []
    size = _next_power_of_two(n)
    data = [complex(x, 0.0) for x in samples] + [0j] * (size - n)

    # Bit reversal permutation.
    bits = size.bit_length() - 1
    for i in range(size):
        j = int(f"{i:0{bits}b}"[::-1], 2) if bits else 0
        if j > i:
            data[i], data[j] = data[j], data[i]

    length = 2
    while length <= size:
        angle = -2.0 * math.pi / length
        step = cmath.exp(1j * angle)
        for start in range(0, size, length):
            w = 1 + 0j
            half = length // 2
            for offset in range(half):
                a = data[start + offset]
                b = data[start + offset + half] * w
                data[start + offset] = a + b
                data[start + offset + half] = a - b
                w *= step
        length <<= 1
    return data


def power_spectrum(samples: Sequence[float]) -> list[float]:
    """Magnitude squared spectrum of the real input, positive frequencies."""
    spectrum = fft(samples)
    half = len(spectrum) // 2
    return [abs(value) ** 2 for value in spectrum[:half]]


def bin_timestamps(epochs: Sequence[float], bin_seconds: float) -> tuple[list[float], float]:
    """Bucket epoch seconds into a fixed width histogram."""
    if not epochs or bin_seconds <= 0:
        return [], 0.0
    start = min(epochs)
    end = max(epochs)
    span = max(end - start, bin_seconds)
    count = int(span // bin_seconds) + 1
    count = max(count, 2)
    series = [0.0] * count
    for epoch in epochs:
        index = int((epoch - start) // bin_seconds)
        if 0 <= index < count:
            series[index] += 1.0
    return series, start


def dominant_frequency(samples: Sequence[float], bin_seconds: float) -> dict[str, float]:
    """Find the strongest periodic component of a binned time series.

    Returns the period in seconds, the spectral power ratio of the dominant
    peak against the mean spectrum and the peak index.
    """
    if len(samples) < 8:
        return {"period_seconds": 0.0, "power_ratio": 0.0, "peak_index": 0.0}
    mean = sum(samples) / len(samples)
    centred = [value - mean for value in samples]
    spectrum = power_spectrum(centred)
    if len(spectrum) < 3:
        return {"period_seconds": 0.0, "power_ratio": 0.0, "peak_index": 0.0}
    usable = spectrum[1:]
    total = sum(usable)
    if total <= 0:
        return {"period_seconds": 0.0, "power_ratio": 0.0, "peak_index": 0.0}
    peak_value = max(usable)
    peak_index = usable.index(peak_value) + 1
    mean_power = total / len(usable)
    ratio = peak_value / mean_power if mean_power else 0.0
    size = _next_power_of_two(len(samples))
    period_bins = size / peak_index if peak_index else 0.0
    return {
        "period_seconds": round(period_bins * bin_seconds, 2),
        "power_ratio": round(ratio, 3),
        "peak_index": float(peak_index),
    }


def interval_regularity(epochs: Sequence[float]) -> dict[str, float]:
    """Classic beacon metrics based on the inter arrival times."""
    ordered = sorted(epochs)
    if len(ordered) < 4:
        return {
            "count": float(len(ordered)),
            "mean_interval": 0.0,
            "stdev": 0.0,
            "coefficient_of_variation": 1.0,
            "jitter_ratio": 1.0,
            "mad": 0.0,
        }
    deltas = [b - a for a, b in zip(ordered, ordered[1:]) if b - a >= 0]
    deltas = [d for d in deltas if d > 0]
    if len(deltas) < 3:
        return {
            "count": float(len(ordered)),
            "mean_interval": 0.0,
            "stdev": 0.0,
            "coefficient_of_variation": 1.0,
            "jitter_ratio": 1.0,
            "mad": 0.0,
        }
    mean = sum(deltas) / len(deltas)
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    stdev = math.sqrt(variance)
    median = sorted(deltas)[len(deltas) // 2]
    mad = sorted(abs(d - median) for d in deltas)[len(deltas) // 2]
    cv = stdev / mean if mean else 1.0
    jitter = mad / median if median else 1.0
    return {
        "count": float(len(ordered)),
        "mean_interval": round(mean, 2),
        "median_interval": round(median, 2),
        "stdev": round(stdev, 3),
        "coefficient_of_variation": round(cv, 4),
        "jitter_ratio": round(jitter, 4),
        "mad": round(mad, 3),
    }


def beacon_score(epochs: Sequence[float]) -> dict[str, float]:
    """Combine interval regularity and spectral analysis into one score."""
    metrics = interval_regularity(epochs)
    count = int(metrics["count"])
    if count < 6:
        metrics["beacon_score"] = 0.0
        metrics["period_seconds"] = 0.0
        metrics["power_ratio"] = 0.0
        return metrics
    mean_interval = metrics.get("median_interval") or metrics["mean_interval"]
    bin_seconds = max(mean_interval / 4.0, 1.0) if mean_interval else 60.0
    series, _ = bin_timestamps(list(epochs), bin_seconds)
    spectral = dominant_frequency(series, bin_seconds)
    metrics.update(spectral)

    cv = metrics["coefficient_of_variation"]
    jitter = metrics["jitter_ratio"]
    regularity = max(0.0, 1.0 - min(cv, 1.0))
    stability = max(0.0, 1.0 - min(jitter, 1.0))
    spectral_strength = min(spectral["power_ratio"] / 12.0, 1.0)
    volume = min(count / 40.0, 1.0)
    score = 0.4 * regularity + 0.25 * stability + 0.25 * spectral_strength + 0.10 * volume
    metrics["beacon_score"] = round(min(score, 1.0), 3)
    return metrics


# --------------------------------------------------------------------------
# Outliers, rarity and Benford's law
# --------------------------------------------------------------------------


def mean_stdev(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    if len(values) == 1:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return mean, math.sqrt(variance)


def zscores(values: Sequence[float]) -> list[float]:
    mean, stdev = mean_stdev(values)
    if stdev == 0:
        return [0.0] * len(values)
    return [(v - mean) / stdev for v in values]


def modified_zscores(values: Sequence[float]) -> list[float]:
    """Median absolute deviation based z scores, robust to heavy outliers."""
    if not values:
        return []
    ordered = sorted(values)
    median = ordered[len(ordered) // 2]
    deviations = sorted(abs(v - median) for v in values)
    mad = deviations[len(deviations) // 2]
    if mad == 0:
        # Iglewicz and Hoaglin recommend the mean absolute deviation when the
        # median absolute deviation collapses to zero, which happens whenever
        # most of the population shares one value.
        mean_ad = sum(abs(v - median) for v in values) / len(values)
        if mean_ad > 0:
            return [0.7979 * (v - median) / mean_ad for v in values]
        mean, stdev = mean_stdev(values)
        if stdev == 0:
            return [0.0] * len(values)
        return [(v - mean) / stdev for v in values]
    return [0.6745 * (v - median) / mad for v in values]


def rarity_scores(counter: Counter) -> dict[str, float]:
    """Map each key to a 0..1 rarity score using its share of the population."""
    total = sum(counter.values())
    if total <= 0:
        return {}
    scores: dict[str, float] = {}
    for key, count in counter.items():
        share = count / total
        scores[key] = round(max(0.0, 1.0 - math.log10(1 + count * 9) / math.log10(1 + total * 9)) * (1 - share), 4)
    return scores


BENFORD_EXPECTED = [math.log10(1 + 1 / d) for d in range(1, 10)]


def benford_chi_square(values: Iterable[float]) -> dict[str, float]:
    """Chi square statistic of the leading digit distribution against Benford."""
    digits = Counter()
    total = 0
    for value in values:
        try:
            magnitude = abs(float(value))
        except (TypeError, ValueError):
            continue
        if magnitude < 1:
            continue
        leading = int(str(int(magnitude))[0])
        if 1 <= leading <= 9:
            digits[leading] += 1
            total += 1
    if total < 50:
        return {"chi_square": 0.0, "sample_size": float(total), "deviation": 0.0}
    chi = 0.0
    max_dev = 0.0
    for index, expected_ratio in enumerate(BENFORD_EXPECTED, start=1):
        expected = expected_ratio * total
        observed = digits.get(index, 0)
        chi += (observed - expected) ** 2 / expected
        max_dev = max(max_dev, abs(observed / total - expected_ratio))
    return {
        "chi_square": round(chi, 3),
        "sample_size": float(total),
        "deviation": round(max_dev, 4),
        "critical_value_p01": 20.09,
    }


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def gini_coefficient(values: Sequence[float]) -> float:
    """Concentration measure, useful for spotting a single dominant talker."""
    cleaned = [v for v in values if v >= 0]
    if not cleaned or sum(cleaned) == 0:
        return 0.0
    ordered = sorted(cleaned)
    n = len(ordered)
    cumulative = sum((index + 1) * value for index, value in enumerate(ordered))
    return round((2 * cumulative) / (n * sum(ordered)) - (n + 1) / n, 4)
