"""
Copyright 2025 NW-Diff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.

Integration tests for Docker deployment with HTTPS and Basic Authentication.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_exists() -> None:
    """Verify Dockerfile exists in repository root."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    assert dockerfile.exists(), "Dockerfile should exist in repository root"
    assert dockerfile.is_file(), "Dockerfile should be a regular file"


def test_docker_compose_exists() -> None:
    """Verify docker-compose.yml exists in repository root."""
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    assert compose_file.exists(), "docker-compose.yml should exist in repository root"
    assert compose_file.is_file(), "docker-compose.yml should be a regular file"


def test_nginx_config_exists() -> None:
    """Verify nginx configuration exists."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    assert nginx_conf.exists(), "nginx.conf should exist in docker directory"
    assert nginx_conf.is_file(), "nginx.conf should be a regular file"


def test_helper_scripts_exist() -> None:
    """Verify helper scripts exist and are executable."""
    scripts_dir = PROJECT_ROOT / "scripts"
    assert scripts_dir.exists(), "scripts directory should exist"

    mk_htpasswd = scripts_dir / "mk-htpasswd.sh"
    assert mk_htpasswd.exists(), "mk-htpasswd.sh should exist"
    assert mk_htpasswd.stat().st_mode & 0o111, "mk-htpasswd.sh should be executable"

    mk_certs = scripts_dir / "mk-certs.sh"
    assert mk_certs.exists(), "mk-certs.sh should exist"
    assert mk_certs.stat().st_mode & 0o111, "mk-certs.sh should be executable"


def test_env_example_exists() -> None:
    """Verify .env.example exists."""
    env_example = PROJECT_ROOT / ".env.example"
    assert env_example.exists(), ".env.example should exist in repository root"
    assert env_example.is_file(), ".env.example should be a regular file"


def test_dockerfile_has_license_header() -> None:
    """Verify Dockerfile contains proper license header."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    assert "Apache-2.0" in content, "Dockerfile should have Apache-2.0 license"
    assert (
        "SPDX-License-Identifier" in content
    ), "Dockerfile should have SPDX identifier"


def test_dockerfile_has_llm_attribution() -> None:
    """Verify Dockerfile contains LLM attribution comment."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    assert "Large Language Model" in content, "Dockerfile should have LLM attribution"


def test_docker_compose_has_license_header() -> None:
    """Verify docker-compose.yml contains proper license header."""
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    content = compose_file.read_text(encoding="utf-8")
    assert "Apache-2.0" in content, "docker-compose.yml should have Apache-2.0 license"
    assert (
        "SPDX-License-Identifier" in content
    ), "docker-compose.yml should have SPDX identifier"


def test_nginx_conf_has_license_header() -> None:
    """Verify nginx.conf contains proper license header."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    content = nginx_conf.read_text(encoding="utf-8")
    assert "Apache-2.0" in content, "nginx.conf should have Apache-2.0 license"
    assert (
        "SPDX-License-Identifier" in content
    ), "nginx.conf should have SPDX identifier"


def test_nginx_conf_has_basic_auth_config() -> None:
    """Verify nginx.conf contains Basic Authentication configuration."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    content = nginx_conf.read_text(encoding="utf-8")
    assert "auth_basic" in content, "nginx.conf should have auth_basic directive"
    assert (
        "auth_basic_user_file" in content
    ), "nginx.conf should have auth_basic_user_file directive"
    assert ".htpasswd" in content, "nginx.conf should reference .htpasswd file"


def test_nginx_conf_has_tls_config() -> None:
    """Verify nginx.conf contains TLS/SSL configuration."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    content = nginx_conf.read_text(encoding="utf-8")
    assert "ssl_certificate" in content, "nginx.conf should have ssl_certificate"
    assert (
        "ssl_certificate_key" in content
    ), "nginx.conf should have ssl_certificate_key"
    assert "listen 443 ssl" in content, "nginx.conf should listen on port 443 with SSL"
    assert (
        "TLSv1.2" in content or "TLSv1.3" in content
    ), "nginx.conf should specify TLS versions"


def test_nginx_conf_has_http_to_https_redirect() -> None:
    """Verify nginx.conf redirects HTTP to HTTPS."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    content = nginx_conf.read_text(encoding="utf-8")
    assert "listen 80" in content, "nginx.conf should listen on port 80"
    assert "return 301 https://" in content, "nginx.conf should redirect HTTP to HTTPS"


def test_nginx_conf_has_security_headers() -> None:
    """Verify nginx.conf includes security headers."""
    nginx_conf = PROJECT_ROOT / "docker" / "nginx.conf"
    content = nginx_conf.read_text(encoding="utf-8")
    assert "X-Frame-Options" in content, "nginx.conf should set X-Frame-Options header"
    assert (
        "X-Content-Type-Options" in content
    ), "nginx.conf should set X-Content-Type-Options header"
    assert (
        "X-XSS-Protection" in content
    ), "nginx.conf should set X-XSS-Protection header"


def test_dockerfile_uses_non_root_user() -> None:
    """Verify Dockerfile creates and uses a non-root user."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    assert (
        "useradd" in content or "adduser" in content
    ), "Dockerfile should create a user"
    assert "USER" in content, "Dockerfile should switch to non-root user"


def test_dockerfile_multi_stage_build() -> None:
    """Verify Dockerfile uses multi-stage build for efficiency."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    assert "FROM" in content, "Dockerfile should have FROM instructions"
    # Count FROM instructions to verify multi-stage
    from_count = content.count("FROM ")
    assert from_count >= 2, "Dockerfile should use multi-stage build"


def test_dockerfile_has_healthcheck() -> None:
    """Verify Dockerfile includes health check."""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    content = dockerfile.read_text(encoding="utf-8")
    assert "HEALTHCHECK" in content, "Dockerfile should have HEALTHCHECK instruction"


def test_docker_compose_has_volumes() -> None:
    """Verify docker-compose.yml defines persistent volumes."""
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    content = compose_file.read_text(encoding="utf-8")
    assert "volumes:" in content, "docker-compose.yml should define volumes"
    assert "nw-diff-logs" in content, "docker-compose.yml should have logs volume"


def test_docker_compose_has_networks() -> None:
    """Verify docker-compose.yml defines networks."""
    compose_file = PROJECT_ROOT / "docker-compose.yml"
    content = compose_file.read_text(encoding="utf-8")
    assert "networks:" in content, "docker-compose.yml should define networks"


@pytest.mark.skipif(
    subprocess.run(["which", "docker"], capture_output=True, check=False).returncode
    != 0,
    reason="Docker not available",
)
def test_dockerfile_builds_successfully() -> None:
    """Test that Dockerfile builds successfully.

    In CI environments with SSL interception, the build may require
    SKIP_PIP_SSL_VERIFY=1 to bypass certificate verification.
    """
    # Try building without SSL workaround first
    result = subprocess.run(
        ["docker", "build", "-t", "nw-diff:test", "."],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    # If build failed due to SSL issues, retry with workaround
    if result.returncode != 0 and "SSL" in result.stderr:
        result = subprocess.run(
            [
                "docker",
                "build",
                "--build-arg",
                "SKIP_PIP_SSL_VERIFY=1",
                "-t",
                "nw-diff:test",
                ".",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    assert result.returncode == 0, f"Docker build failed: {result.stderr}"


def test_gitignore_excludes_docker_secrets() -> None:
    """Verify .gitignore excludes Docker secrets and generated files."""
    gitignore = PROJECT_ROOT / ".gitignore"
    content = gitignore.read_text(encoding="utf-8")
    assert ".htpasswd" in content, ".gitignore should exclude .htpasswd file"
    assert (
        "certs" in content or "docker/certs" in content
    ), ".gitignore should exclude certificate directory"
