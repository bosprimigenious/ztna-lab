"""Session state shared by the local control and gateway planes."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from threading import Lock

from .ipam import VirtualIPPool
from .policy import DevicePosture


@dataclass
class Session:
    session_id: str
    subject: str
    posture: DevicePosture
    virtual_ip: str
    lease_generation: int
    expires_at: float
    absolute_expires_at: float
    last_seen: float
    revoked: bool = False


class SessionStore:
    def __init__(
        self,
        ip_pool: VirtualIPPool,
        ttl_seconds: int = 300,
        absolute_ttl_seconds: int = 3_600,
        idle_seconds: int = 120,
    ) -> None:
        if not (30 <= ttl_seconds <= 3_600):
            raise ValueError("session TTL out of range")
        if not (ttl_seconds <= absolute_ttl_seconds <= 86_400):
            raise ValueError("absolute session TTL out of range")
        if not (15 <= idle_seconds <= ttl_seconds):
            raise ValueError("session idle timeout out of range")
        self.ip_pool = ip_pool
        self.ttl_seconds = ttl_seconds
        self.absolute_ttl_seconds = absolute_ttl_seconds
        self.idle_seconds = idle_seconds
        self._sessions: dict[str, Session] = {}
        self._lease_generation = 0
        self._lock = Lock()

    def create(self, subject: str, posture: DevicePosture) -> Session:
        # Reclaim leases even when an expired session has not been looked up.
        self.scavenge()
        now = time.time()
        session_id = secrets.token_urlsafe(18)
        virtual_ip = self.ip_pool.allocate(session_id)
        with self._lock:
            self._lease_generation += 1
            session = Session(
                session_id=session_id,
                subject=subject,
                posture=posture,
                virtual_ip=virtual_ip,
                lease_generation=self._lease_generation,
                expires_at=now + self.ttl_seconds,
                absolute_expires_at=now + self.absolute_ttl_seconds,
                last_seen=now,
            )
            self._sessions[session_id] = session
        return session

    def get_active(self, session_id: str) -> Session | None:
        now = time.time()
        release = False
        with self._lock:
            session = self._sessions.get(session_id)
            if (
                session is None
                or session.revoked
                or session.expires_at < now
                or session.absolute_expires_at < now
                or session.last_seen + self.idle_seconds < now
            ):
                if session is not None:
                    session.revoked = True
                    self._sessions.pop(session_id, None)
                    release = True
        if release:
            self.ip_pool.release(session_id)
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return None
            return session

    def heartbeat(self, session_id: str) -> Session | None:
        now = time.time()
        release = False
        with self._lock:
            session = self._sessions.get(session_id)
            if (
                session is None
                or session.revoked
                or session.expires_at < now
                or session.absolute_expires_at < now
                or session.last_seen + self.idle_seconds < now
            ):
                if session is not None:
                    session.revoked = True
                    self._sessions.pop(session_id, None)
                    release = True
            else:
                session.last_seen = now
                session.expires_at = min(now + self.ttl_seconds, session.absolute_expires_at)
        if release:
            self.ip_pool.release(session_id)
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return None
            return session

    def revoke(self, session_id: str) -> bool:
        release = False
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return False
            session.revoked = True
            release = True
        if release:
            self.ip_pool.release(session_id)
        return True

    def scavenge(self) -> int:
        """Expire idle/absolute sessions and return the number reclaimed."""

        now = time.time()
        reclaimed_ids: list[str] = []
        with self._lock:
            for session_id, session in list(self._sessions.items()):
                if (
                    not session.revoked
                    and session.expires_at >= now
                    and session.absolute_expires_at >= now
                    and session.last_seen + self.idle_seconds >= now
                ):
                    continue
                if not session.revoked:
                    session.revoked = True
                    reclaimed_ids.append(session_id)
                self._sessions.pop(session_id, None)
        for session_id in reclaimed_ids:
            self.ip_pool.release(session_id)
        return len(reclaimed_ids)
