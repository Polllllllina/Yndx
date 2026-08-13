"""Reusable bounded string types for shared contracts."""

from typing import Annotated, TypeAlias

from pydantic import StringConstraints


NonEmptyString: TypeAlias = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=128)
]
MessageText: TypeAlias = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=4096)
]
EvidenceText: TypeAlias = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=8192)
]
PolicyVersion: TypeAlias = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=64)
]
