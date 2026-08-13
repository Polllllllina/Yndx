"""Small standard-library TF-IDF prototype matcher.

``PrototypeMatcher`` is opt-in when directly constructed.  The starter runtime
intentionally constructs an enabled matcher and wraps it in
``PrototypeDetector`` as a second deterministic detection layer.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from math import log, sqrt
from re import findall, finditer
from typing import Final, TypeAlias

from guardrail.normalization import normalize_text


@dataclass(frozen=True, slots=True)
class LabeledPrototype:
    label: str
    text: str

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("prototype label must not be empty")
        if not self.text:
            raise ValueError("prototype text must not be empty")


@dataclass(frozen=True, slots=True)
class PrototypeMatch:
    nearest_attack_label: str
    nearest_attack_similarity: float
    nearest_benign_label: str
    nearest_benign_similarity: float
    margin: float

    @property
    def attack_label(self) -> str:
        return self.nearest_attack_label

    @property
    def attack_similarity(self) -> float:
        return self.nearest_attack_similarity

    @property
    def benign_label(self) -> str:
        return self.nearest_benign_label

    @property
    def benign_similarity(self) -> float:
        return self.nearest_benign_similarity


PrototypeItems: TypeAlias = Iterable[
    LabeledPrototype | tuple[str, str]
]
PrototypeInput: TypeAlias = (
    Mapping[str, str | Sequence[str]] | PrototypeItems
)
Vector: TypeAlias = dict[str, float]

MAX_NORMALIZED_QUERY_LENGTH: Final = 65_536


def _coerce_prototypes(prototypes: PrototypeInput) -> tuple[LabeledPrototype, ...]:
    if isinstance(prototypes, Mapping):
        items: list[LabeledPrototype] = []
        for label, texts in prototypes.items():
            values = (texts,) if isinstance(texts, str) else texts
            items.extend(LabeledPrototype(label, text) for text in values)
        return tuple(items)
    return tuple(
        item
        if isinstance(item, LabeledPrototype)
        else LabeledPrototype(item[0], item[1])
        for item in prototypes
    )


def _normalized_features(normalized: str) -> Counter[str]:
    features: Counter[str] = Counter()
    for size in range(3, 6):
        features.update(
            f"char:{size}:{normalized[index:index + size]}"
            for index in range(len(normalized) - size + 1)
        )
    words = findall(r"\w+", normalized)
    for size in range(1, 3):
        features.update(
            f"word:{size}:{' '.join(words[index:index + size])}"
            for index in range(len(words) - size + 1)
        )
    return features


def _features(text: str) -> Counter[str]:
    normalized = normalize_text(text).control_stripped
    return _normalized_features(normalized)


def _vector(features: Counter[str], idf: Mapping[str, float]) -> Vector:
    return {
        feature: count * idf[feature]
        for feature, count in features.items()
        if feature in idf
    }


def _vocabulary_vector(
    normalized: str,
    idf: Mapping[str, float],
) -> Vector:
    """Count an over-budget query without retaining out-of-vocabulary features."""
    features: Counter[str] = Counter()
    for size in range(3, 6):
        for index in range(len(normalized) - size + 1):
            feature = f"char:{size}:{normalized[index:index + size]}"
            if feature in idf:
                features[feature] += 1
    for match in finditer(r"\w+", normalized):
        feature = f"word:1:{match.group()}"
        if feature in idf:
            features[feature] += 1
    previous_word: str | None = None
    for match in finditer(r"\w+", normalized):
        word = match.group()
        if previous_word is not None:
            feature = f"word:2:{previous_word} {word}"
            if feature in idf:
                features[feature] += 1
        previous_word = word
    return _vector(features, idf)


def _cosine(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    left_norm = sqrt(sum(value * value for value in left.values()))
    right_norm = sqrt(sum(value * value for value in right.values()))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    dot = sum(
        value * right.get(feature, 0.0)
        for feature, value in left.items()
    )
    return min(1.0, max(0.0, dot / (left_norm * right_norm)))


class PrototypeMatcher:
    """Rank nearest attack and benign prototypes with cosine similarity."""

    def __init__(
        self,
        attack_prototypes: PrototypeInput = (),
        benign_prototypes: PrototypeInput = (),
        *,
        enabled: bool = False,
    ) -> None:
        self.enabled = enabled
        self._attack = _coerce_prototypes(attack_prototypes)
        self._benign = _coerce_prototypes(benign_prototypes)

        all_prototypes = self._attack + self._benign
        document_features = tuple(
            _features(prototype.text) for prototype in all_prototypes
        )
        document_count = len(document_features)

        document_frequency: Counter[str] = Counter()
        for features in document_features:
            document_frequency.update(features.keys())

        self._idf = {
            feature: log(
                (1 + document_count) / (1 + frequency)
            ) + 1.0
            for feature, frequency in document_frequency.items()
        }

        vectors = tuple(
            _vector(features, self._idf) for features in document_features
        )

        attack_count = len(self._attack)
        self._attack_vectors = tuple(
            zip(self._attack, vectors[:attack_count], strict=True)
        )
        self._benign_vectors = tuple(
            zip(self._benign, vectors[attack_count:], strict=True)
        )

        if enabled:
            self._require_both_classes()

    @property
    def attack_labels(self) -> tuple[str, ...]:
        return tuple(prototype.label for prototype in self._attack)

    def _require_both_classes(self) -> None:
        if not self._attack or not self._benign:
            raise ValueError(
                "enabled matcher requires attack and benign prototypes"
            )

    def _nearest(
        self,
        query: Mapping[str, float],
        prototypes: tuple[tuple[LabeledPrototype, Vector], ...],
    ) -> tuple[str, float]:
        prototype, vector = prototypes[0]
        best_label = prototype.label
        best_similarity = _cosine(query, vector)

        for prototype, vector in prototypes[1:]:
            similarity = _cosine(query, vector)
            if similarity > best_similarity:
                best_label = prototype.label
                best_similarity = similarity

        return best_label, best_similarity

    def match(self, text: str) -> PrototypeMatch | None:
        if not self.enabled:
            return None
        self._require_both_classes()

        normalized = normalize_text(text).control_stripped
        query = (
            _vocabulary_vector(normalized, self._idf)
            if len(normalized) > MAX_NORMALIZED_QUERY_LENGTH
            else _vector(_normalized_features(normalized), self._idf)
        )

        attack_label, attack_similarity = self._nearest(
            query, self._attack_vectors
        )
        benign_label, benign_similarity = self._nearest(
            query, self._benign_vectors
        )

        return PrototypeMatch(
            nearest_attack_label=attack_label,
            nearest_attack_similarity=attack_similarity,
            nearest_benign_label=benign_label,
            nearest_benign_similarity=benign_similarity,
            margin=attack_similarity - benign_similarity,
        )