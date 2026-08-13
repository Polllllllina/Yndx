"""Base configuration shared by all wire-contract models."""

from pydantic import BaseModel, ConfigDict


class ContractModel(BaseModel):
    """Reject undeclared wire fields for every shared contract."""

    model_config = ConfigDict(extra="forbid")
