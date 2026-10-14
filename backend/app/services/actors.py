"""Who is performing an action, for authorization and audit."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

from app.core.security import Role

ActorType = Literal["user", "system", "cli"]


@dataclass(frozen=True)
class Actor:
    actor_type: ActorType
    user_id: uuid.UUID | None = None
    label: str | None = None


CLI_ACTOR = Actor("cli", label="cli")
SYSTEM_ACTOR = Actor("system", label="system")


@dataclass(frozen=True)
class Principal:
    """An authenticated API user bound to one session."""

    user_id: uuid.UUID
    username: str
    role: Role
    session_id: uuid.UUID

    @property
    def actor(self) -> Actor:
        return Actor("user", user_id=self.user_id, label=self.username)
