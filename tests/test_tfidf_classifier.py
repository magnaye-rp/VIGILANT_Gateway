#!/usr/bin/env python3
"""
Unit tests for VigilantTFIDFClassifier

Tests cover:
  - Vectorizer configuration (stop_words, ngram_range)
  - Centroid matrix pre-computation shape and type
  - URL keyword-based classification (Educational, Productive, Distracting, Harmful)
  - SNI domain name classification
  - HTML content sample classification
  - Edge cases (empty / whitespace input)
  - Truncation safety for large inputs
  - Similarity scores return structure

Usage:
    python -m pytest tests/test_tfidf_classifier.py -v
    or
    python tests/test_tfidf_classifier.py
"""

import sys
import time
import unittest
from pathlib import Path

# ─── Path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Guard against missing heavy dependencies (spacy model, mitmproxy) so that
# running tests in a minimal CI environment surfaces a clear skip message
# rather than an obscure ImportError.
try:
    from vigilant_addon import (
        VigilantTFIDFClassifier,
        CATEGORY_KEYWORDS,
        SAMPLE_PREFIX_BYTES,
        TfidfVectorizer,
    )
    if TfidfVectorizer is None:
        raise ImportError("sklearn TfidfVectorizer is not installed")
    import numpy as np
    IMPORT_OK = True
    IMPORT_ERROR = None
except Exception as exc:  # noqa: BLE001
    IMPORT_OK = False
    IMPORT_ERROR = str(exc)


# ─── Base mixin so every test class auto-skips on import failure ──────────────
class _RequiresImport:
    def setUp(self):  # noqa: N802 (unittest naming)
        if not IMPORT_OK:
            self.skipTest(
                f"vigilant_addon could not be imported: {IMPORT_ERROR}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Vectorizer Configuration
# ══════════════════════════════════════════════════════════════════════════════
class TestVectorizerConfig(_RequiresImport, unittest.TestCase):
    """Verify TfidfVectorizer is configured with the required parameters."""

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def test_vectorizer_stop_words_english(self):
        """TfidfVectorizer must use stop_words='english'."""
        self.assertEqual(
            self.clf.vectorizer.stop_words,
            "english",
            "stop_words should be 'english'",
        )

    def test_vectorizer_ngram_range(self):
        """TfidfVectorizer must use ngram_range=(1, 2) for unigrams and bigrams."""
        self.assertEqual(
            self.clf.vectorizer.ngram_range,
            (1, 2),
            "ngram_range should be (1, 2)",
        )


# ══════════════════════════════════════════════════════════════════════════════
# 2. Centroid Matrix Pre-computation
# ══════════════════════════════════════════════════════════════════════════════
class TestCentroidMatrix(_RequiresImport, unittest.TestCase):
    """Verify centroids are pre-stacked into a 2-D matrix at init time."""

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)
        self.n_categories = len(CATEGORY_KEYWORDS)

    def test_centroid_matrix_is_ndarray(self):
        """centroid_matrix must be a numpy ndarray, not None."""
        self.assertIsInstance(
            self.clf.centroid_matrix,
            np.ndarray,
            "centroid_matrix should be a numpy ndarray after init",
        )

    def test_centroid_matrix_is_2d(self):
        """centroid_matrix must be 2-D (n_categories × vocab_size)."""
        self.assertEqual(
            self.clf.centroid_matrix.ndim,
            2,
            "centroid_matrix should be a 2-D array",
        )

    def test_centroid_matrix_row_count(self):
        """centroid_matrix must have one row per category."""
        self.assertEqual(
            self.clf.centroid_matrix.shape[0],
            self.n_categories,
            f"centroid_matrix should have {self.n_categories} rows (one per category)",
        )

    def test_category_names_length(self):
        """category_names list length must equal number of categories."""
        self.assertEqual(
            len(self.clf.category_names),
            self.n_categories,
            "category_names should have one entry per category",
        )

    def test_centroid_matrix_vocab_matches_vectorizer(self):
        """centroid_matrix column count must equal the fitted vocabulary size."""
        vocab_size = len(self.clf.vectorizer.vocabulary_)
        self.assertEqual(
            self.clf.centroid_matrix.shape[1],
            vocab_size,
            "centroid_matrix columns should match vectorizer vocabulary size",
        )

    def test_category_centroids_dict_consistent(self):
        """Legacy category_centroids dict must contain the same categories."""
        self.assertSetEqual(
            set(self.clf.category_centroids.keys()),
            set(self.clf.category_names),
            "category_centroids dict should contain all category_names entries",
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. URL Keyword Classification
# ══════════════════════════════════════════════════════════════════════════════
class TestURLClassification(_RequiresImport, unittest.TestCase):
    """Verify classification of URL-derived texts using category-representative keywords."""

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def _classify(self, text, threshold=0.05):
        category, scores = self.clf.classify(text, threshold=threshold)
        return category, scores

    def test_educational_url_keywords(self):
        """URL text dense with educational keywords should classify as Educational."""
        text = "learn study research science history tutorial course university education academic"
        category, scores = self._classify(text)
        self.assertEqual(
            category,
            "Educational",
            f"Expected 'Educational', got '{category}'. Scores: {scores}",
        )

    def test_productive_url_keywords(self):
        """URL text dense with productive keywords should classify as Productive."""
        text = "work project report deadline meeting productivity business office task career"
        category, scores = self._classify(text)
        self.assertEqual(
            category,
            "Productive",
            f"Expected 'Productive', got '{category}'. Scores: {scores}",
        )

    def test_distracting_url_keywords(self):
        """URL text dense with distracting keywords should classify as Distracting."""
        text = "viral trending meme gossip celebrity shocking unbelievable scroll feed reels"
        category, scores = self._classify(text)
        self.assertEqual(
            category,
            "Distracting",
            f"Expected 'Distracting', got '{category}'. Scores: {scores}",
        )

    def test_harmful_url_keywords(self):
        """URL text dense with harmful keywords should classify as Harmful."""
        text = "hate violence abuse threat illegal exploit dangerous extremist"
        category, scores = self._classify(text)
        self.assertEqual(
            category,
            "Harmful",
            f"Expected 'Harmful', got '{category}'. Scores: {scores}",
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. SNI Domain Name Classification
# ══════════════════════════════════════════════════════════════════════════════
class TestSNIClassification(_RequiresImport, unittest.TestCase):
    """
    SNI domains are converted to space-separated tokens before classify().
    Tests verify the classifier does not raise and returns expected categories
    for well-known domain patterns, using low thresholds matching log_to_dashboard.
    """

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def _domain_text(self, sni: str) -> str:
        """Replicate the domain_text transform used in log_to_dashboard."""
        return sni.replace(".", " ").replace("-", " ")

    def test_sni_does_not_raise(self):
        """classify() must not raise for any domain-derived text."""
        for sni in ["khanacademy.org", "tiktok.com", "github.com", "google.com"]:
            try:
                self.clf.classify(self._domain_text(sni), threshold=0.05)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"classify() raised {exc!r} for SNI '{sni}'")

    def test_sni_tiktok_distracting(self):
        """'tiktok com' should resolve to Distracting (tiktok is in CATEGORY_KEYWORDS)."""
        text = self._domain_text("tiktok.com")  # "tiktok com"
        category, scores = self.clf.classify(text, threshold=0.05)
        self.assertEqual(
            category,
            "Distracting",
            f"'tiktok.com' SNI should classify as 'Distracting'. Scores: {scores}",
        )

    def test_sni_returns_tuple(self):
        """classify() must return a 2-tuple for any SNI text."""
        result = self.clf.classify(self._domain_text("example.com"), threshold=0.05)
        self.assertIsInstance(result, tuple, "classify() should return a tuple")
        self.assertEqual(len(result), 2, "classify() tuple should have 2 elements")

    def test_sni_scores_are_floats(self):
        """All similarity scores in the returned dict must be floats."""
        _, scores = self.clf.classify(self._domain_text("example.com"), threshold=0.05)
        for cat, score in scores.items():
            self.assertIsInstance(
                score, float,
                f"Score for category '{cat}' should be a float, got {type(score)}",
            )


# ══════════════════════════════════════════════════════════════════════════════
# 5. HTML Content Classification
# ══════════════════════════════════════════════════════════════════════════════
class TestHTMLContentClassification(_RequiresImport, unittest.TestCase):
    """
    HTML bodies are stripped of tags before classify() is called.
    Tests use pre-stripped plain-text paragraphs representative of each class.
    """

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def test_html_educational_content(self):
        """A passage rich in academic terms should classify as Educational."""
        text = (
            "This lecture explores the hypothesis behind quantum theory. "
            "Students are encouraged to research the academic journal articles "
            "and conduct their own experiments. The university course covers "
            "advanced topics in science and history with textbook analysis."
        )
        category, scores = self.clf.classify(text, threshold=0.05)
        self.assertEqual(
            category,
            "Educational",
            f"Academic passage should classify as 'Educational'. Scores: {scores}",
        )

    def test_html_distracting_content(self):
        """A passage rich in distraction terms should classify as Distracting."""
        text = (
            "You won't believe this viral trending meme that's shocking everyone. "
            "Celebrity gossip is unbelievable this week on the feed. "
            "Scroll through the latest reels, shorts, and tiktok influencer content "
            "for entertainment and funny lol wtf moments."
        )
        category, scores = self.clf.classify(text, threshold=0.05)
        self.assertEqual(
            category,
            "Distracting",
            f"Distraction passage should classify as 'Distracting'. Scores: {scores}",
        )

    def test_html_productive_content(self):
        """A passage rich in professional terms should classify as Productive."""
        text = (
            "The quarterly business report highlights project deadlines and budget "
            "targets. The team meeting covered office productivity initiatives and "
            "professional development. Finance and career planning were also discussed "
            "alongside code deployment and repository management."
        )
        category, scores = self.clf.classify(text, threshold=0.05)
        self.assertEqual(
            category,
            "Productive",
            f"Professional passage should classify as 'Productive'. Scores: {scores}",
        )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Edge Cases
# ══════════════════════════════════════════════════════════════════════════════
class TestEdgeCases(_RequiresImport, unittest.TestCase):
    """Verify robust handling of degenerate inputs."""

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def test_empty_string_returns_none(self):
        """Empty string should return (None, {})."""
        category, scores = self.clf.classify("")
        self.assertIsNone(category, "Empty string should yield category=None")
        self.assertEqual(scores, {}, "Empty string should yield empty scores dict")

    def test_whitespace_only_returns_none(self):
        """Whitespace-only string should return (None, {})."""
        category, scores = self.clf.classify("   \t\n   ")
        self.assertIsNone(category, "Whitespace-only string should yield category=None")
        self.assertEqual(scores, {}, "Whitespace-only string should yield empty scores dict")

    def test_none_input_returns_none(self):
        """None input should return (None, {}) without raising."""
        try:
            category, scores = self.clf.classify(None)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"classify(None) raised {exc!r}, expected (None, {{}})")
        self.assertIsNone(category)
        self.assertEqual(scores, {})

    def test_numeric_string_does_not_raise(self):
        """A string of only digits should not raise."""
        try:
            self.clf.classify("123456789")
        except Exception as exc:  # noqa: BLE001
            self.fail(f"classify('123456789') raised {exc!r}")

    def test_similarity_scores_all_categories_present(self):
        """Scores dict must contain a key for every category when text is classifiable."""
        text = "learn study research science tutorial"
        _, scores = self.clf.classify(text, threshold=0.0)
        for cat in CATEGORY_KEYWORDS:
            self.assertIn(cat, scores, f"Scores dict should include key '{cat}'")

    def test_similarity_scores_values_in_range(self):
        """All similarity scores must be in [0.0, 1.0]."""
        text = "learn study research science tutorial"
        _, scores = self.clf.classify(text, threshold=0.0)
        for cat, score in scores.items():
            self.assertGreaterEqual(score, 0.0, f"Score for '{cat}' < 0.0")
            self.assertLessEqual(score, 1.0, f"Score for '{cat}' > 1.0")


# ══════════════════════════════════════════════════════════════════════════════
# 7. Truncation Safety
# ══════════════════════════════════════════════════════════════════════════════
class TestTruncationSafety(_RequiresImport, unittest.TestCase):
    """
    Verify that SAMPLE_PREFIX_BYTES truncation prevents latency spikes.
    A 1 MB input must complete within a reasonable wall-clock budget and must
    not raise an exception.
    """

    MAX_ALLOWED_SECONDS = 5.0  # generous budget; warm classifier should be well under 1 s

    def setUp(self):
        super().setUp()
        self.clf = VigilantTFIDFClassifier(CATEGORY_KEYWORDS)

    def test_large_input_does_not_raise(self):
        """A 1 MB string must not raise during classify()."""
        large_text = "learn study research science tutorial course " * (
            (1024 * 1024) // len("learn study research science tutorial course ")
        )
        try:
            self.clf.classify(large_text, threshold=0.1)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"classify() raised {exc!r} on a 1 MB input")

    def test_large_input_completes_within_time_budget(self):
        """A 1 MB string must complete within MAX_ALLOWED_SECONDS."""
        large_text = "viral trending meme gossip celebrity scroll feed reels " * (
            (1024 * 1024) // len("viral trending meme gossip celebrity scroll feed reels ")
        )
        start = time.monotonic()
        self.clf.classify(large_text, threshold=0.1)
        elapsed = time.monotonic() - start
        self.assertLess(
            elapsed,
            self.MAX_ALLOWED_SECONDS,
            f"classify() took {elapsed:.3f}s on a 1 MB input (limit: {self.MAX_ALLOWED_SECONDS}s). "
            "Truncation may not be working correctly.",
        )

    def test_input_exceeding_sample_prefix_bytes_is_truncated(self):
        """
        Verify that text longer than SAMPLE_PREFIX_BYTES is actually truncated
        by confirming the classifier sees only the prefix (not the appended suffix).
        We append a unique suffix of Harmful keywords beyond the cap and verify
        the result is NOT driven by those suffix keywords.
        """
        # Build a safe prefix (Educational) that exactly fills the cap
        filler_word = "learn "
        prefix = filler_word * (SAMPLE_PREFIX_BYTES // len(filler_word) + 1)
        prefix = prefix[:SAMPLE_PREFIX_BYTES]  # exactly at cap

        # Append Harmful keywords past the cap (should be invisible to classify)
        suffix = " hate violence abuse threat illegal exploit dangerous extremist " * 200
        full_text = prefix + suffix

        self.assertGreater(
            len(full_text),
            SAMPLE_PREFIX_BYTES,
            "Test setup error: full_text should exceed SAMPLE_PREFIX_BYTES",
        )

        category, _ = self.clf.classify(full_text, threshold=0.05)
        # The result should be Educational (from the prefix), NOT Harmful (from the suffix)
        self.assertNotEqual(
            category,
            "Harmful",
            "Truncation failed: Harmful suffix keywords beyond SAMPLE_PREFIX_BYTES "
            "are influencing the classification result.",
        )


# ─── Runner ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromModule(
        sys.modules[__name__]
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print("TEST SUMMARY — VigilantTFIDFClassifier")
    print("=" * 70)
    print(f"Tests run : {result.testsRun}")
    print(f"Passed    : {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures  : {len(result.failures)}")
    print(f"Errors    : {len(result.errors)}")
    print(f"Skipped   : {len(result.skipped)}")
    print("=" * 70)

    sys.exit(0 if result.wasSuccessful() else 1)
