"""The mathematical primitives behind the statistical detections."""

from __future__ import annotations

import math
import random

import pytest

from app.engine.stats_math import (
    beacon_score,
    benford_chi_square,
    bin_timestamps,
    consonant_ratio,
    dga_score,
    dominant_frequency,
    fft,
    gini_coefficient,
    interval_regularity,
    looks_base64,
    modified_zscores,
    normalised_entropy,
    percentile,
    power_spectrum,
    shannon_entropy,
    zscores,
)


class TestEntropy:
    def test_empty_string_has_no_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string_has_no_entropy(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_two_symbols_give_one_bit(self):
        assert shannon_entropy("abababab") == pytest.approx(1.0)

    def test_random_hex_scores_higher_than_a_word(self):
        assert shannon_entropy("9f3a7c1e8b2d40a6") > shannon_entropy("administrator")

    def test_base64_payload_is_high_entropy(self):
        payload = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQA"
        assert shannon_entropy(payload) > 3.5

    def test_normalised_entropy_is_bounded(self):
        for value in ("abc", "aabbcc", "the quick brown fox", "9f3a7c1e"):
            assert 0.0 <= normalised_entropy(value) <= 1.0

    def test_bytes_are_supported(self):
        assert shannon_entropy(b"\x00\x01\x02\x03") == pytest.approx(2.0)


class TestDga:
    def test_common_domains_score_low(self):
        for label in ("google", "microsoft", "outlook", "cloudflare", "wikipedia"):
            assert dga_score(label) < 0.55, label

    def test_generated_labels_score_high(self):
        for label in ("kq3v9zxlwmnbrtd", "xzqvbnmwrtlkjhg", "pwzkxmvbnqrtylw"):
            assert dga_score(label) >= 0.6, label

    def test_short_labels_are_ignored(self):
        assert dga_score("abc") == 0.0

    def test_consonant_ratio(self):
        assert consonant_ratio("bcdfg") == 1.0
        assert consonant_ratio("aeiou") == 0.0
        assert consonant_ratio("") == 0.0

    def test_base64_detection(self):
        assert looks_base64("SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==")
        assert not looks_base64("hello")


class TestFourier:
    def test_fft_of_a_pure_tone_peaks_at_its_frequency(self):
        size = 64
        cycles = 8
        samples = [math.sin(2 * math.pi * cycles * index / size) for index in range(size)]
        spectrum = power_spectrum(samples)
        assert spectrum.index(max(spectrum)) == cycles

    def test_fft_matches_the_naive_transform(self):
        random.seed(3)
        samples = [random.uniform(-1, 1) for _ in range(16)]
        fast = fft(samples)
        for k in range(16):
            slow = sum(
                samples[n] * complex(math.cos(-2 * math.pi * k * n / 16), math.sin(-2 * math.pi * k * n / 16))
                for n in range(16)
            )
            assert abs(fast[k] - slow) < 1e-9

    def test_fft_pads_to_a_power_of_two(self):
        assert len(fft([1.0] * 5)) == 8

    def test_binning_produces_a_series(self):
        base = 1_700_000_000
        series, start = bin_timestamps([base + index * 30 for index in range(20)], 30)
        assert start == base
        assert sum(series) == 20

    def test_dominant_frequency_finds_the_period(self):
        # Ten bins per cycle at six seconds a bin is a sixty second period.
        series = [1.0 + math.sin(2 * math.pi * index / 10) for index in range(160)]
        result = dominant_frequency(series, bin_seconds=6.0)
        assert result["period_seconds"] == pytest.approx(60.0, rel=0.15)
        assert result["power_ratio"] > 5

    def test_jittered_check_ins_recover_the_fundamental(self):
        # A real beacon carries jitter, which suppresses the harmonics that a
        # perfect impulse train would leave with identical power.
        random.seed(4)
        series = [0.0] * 200
        for cycle in range(20):
            index = int(cycle * 10 + random.uniform(-1.2, 1.2))
            if 0 <= index < len(series):
                series[index] += 1.0
        result = dominant_frequency(series, bin_seconds=6.0)
        assert result["period_seconds"] == pytest.approx(60.0, rel=0.25)


class TestBeaconScoring:
    def test_regular_traffic_scores_high(self):
        random.seed(5)
        base = 1_700_000_000
        epochs = [base + index * 60 + random.uniform(-1.5, 1.5) for index in range(60)]
        metrics = beacon_score(epochs)
        assert metrics["beacon_score"] > 0.85
        assert metrics["period_seconds"] == pytest.approx(60, rel=0.2)
        assert metrics["coefficient_of_variation"] < 0.1

    def test_random_traffic_scores_low(self):
        random.seed(6)
        base = 1_700_000_000
        epochs = sorted(base + random.uniform(0, 7200) for _ in range(60))
        assert beacon_score(epochs)["beacon_score"] < 0.6

    def test_short_series_is_not_scored(self):
        assert beacon_score([1_700_000_000, 1_700_000_060])["beacon_score"] == 0.0

    def test_interval_regularity_handles_duplicates(self):
        metrics = interval_regularity([100.0] * 10)
        assert metrics["coefficient_of_variation"] == 1.0


class TestOutliers:
    def test_zscores_of_a_flat_series_are_zero(self):
        assert zscores([5, 5, 5, 5]) == [0.0, 0.0, 0.0, 0.0]

    def test_modified_zscore_flags_an_extreme_value(self):
        scores = modified_zscores([10, 11, 9, 10, 12, 10, 400])
        assert scores[-1] > 20
        assert all(abs(score) < 5 for score in scores[:-1])

    def test_percentile_bounds(self):
        values = list(range(1, 101))
        assert percentile(values, 50) == pytest.approx(50, abs=1)
        assert percentile(values, 100) == 100
        assert percentile([], 50) == 0.0

    def test_gini_of_equal_values_is_zero(self):
        assert gini_coefficient([10, 10, 10, 10]) == pytest.approx(0.0, abs=0.01)

    def test_gini_of_a_concentrated_series_is_high(self):
        assert gini_coefficient([1, 1, 1, 1, 1000]) > 0.7


class TestBenford:
    def test_log_uniform_data_follows_benford(self):
        random.seed(9)
        values = [10 ** random.uniform(1, 6) for _ in range(3000)]
        result = benford_chi_square(values)
        assert result["chi_square"] < result["critical_value_p01"]

    def test_fixed_chunk_sizes_break_benford(self):
        values = [50000 + (index % 3) for index in range(500)]
        result = benford_chi_square(values)
        assert result["chi_square"] > result["critical_value_p01"]

    def test_small_samples_are_not_scored(self):
        assert benford_chi_square([100, 200, 300])["chi_square"] == 0.0
