#!/usr/bin/env bash
# Bootstrap the project-nginx-otel sibling-checkout layout.
#
# ngx-otel-rust depends on three sibling repos at fixed paths relative to
# its parent directory:
#
#   project-nginx-otel/
#   ├── ngx-otel-rust/   ← the crate (this repo)
#   ├── ngx-rust/        ← F5 fork, branch ngx-otel-rust-deadlock-fix
#   │                      (path = "../ngx-rust" in Cargo.toml)
#   └── nginx/           ← nginx source, used by make build
#
# This script ensures the two siblings exist, are on the right branches,
# and are up to date.  Safe to re-run.
#
# Typical first-run flow on a fresh machine:
#
#   mkdir -p ~/project-nginx-otel && cd ~/project-nginx-otel
#   git clone git@github.com:CVanF5/ngx-otel-rust.git
#   bash ngx-otel-rust/scripts/bootstrap-layout.sh
#   cd ngx-otel-rust
#   make build              # sanity-check the crate compiles
#   bash tests/integration/run_grpc_smoke.sh
#
# Linux-only targets (require Docker):
#   make tsan-test          # sub-item 3.1 gate
#
# Environment overrides:
#   SKIP_DOCKER_PULL=1      skip the optional `docker pull` warm-up
#   BRANCH_ngx_rust=...     override the ngx-rust branch (default
#                           ngx-otel-rust-deadlock-fix)
#   BRANCH_nginx=...        override the nginx branch (default master)

set -euo pipefail

# Resolve the project root (parent of ngx-otel-rust).  This script lives at
# ngx-otel-rust/scripts/bootstrap-layout.sh, so the root is two levels up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

cd "${ROOT}"

# ── helpers ─────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass() { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }

# clone_or_pull <name> <url> <branch>
# Clones the repo if missing; otherwise fetches updates and fast-forwards.
clone_or_pull() {
    local name="$1" url="$2" branch="$3"
    if [[ -d "${name}/.git" ]]; then
        info "${name}: fetching updates (branch ${branch})"
        git -C "${name}" fetch --all --tags --prune
        # Switch to the target branch if not already on it.
        local current
        current="$(git -C "${name}" rev-parse --abbrev-ref HEAD)"
        if [[ "${current}" != "${branch}" ]]; then
            info "${name}: switching ${current} -> ${branch}"
            git -C "${name}" checkout "${branch}"
        fi
        # Fast-forward only.  Refuse to merge / rebase silently.
        if ! git -C "${name}" pull --ff-only 2>&1; then
            fail "${name}: pull --ff-only failed.  Local branch has diverged from origin.
       Resolve manually before re-running bootstrap."
            return 1
        fi
        pass "${name}: up to date (HEAD $(git -C "${name}" rev-parse --short HEAD))"
    else
        info "${name}: cloning ${url} (branch ${branch})"
        git clone -b "${branch}" "${url}" "${name}"
        pass "${name}: cloned at HEAD $(git -C "${name}" rev-parse --short HEAD)"
    fi
}

# ── pre-flight ──────────────────────────────────────────────────────────────

if ! command -v git >/dev/null 2>&1; then
    fail "git is not installed"
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo / rust toolchain is not installed.

  Install with:
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
"
    exit 1
fi

# ── sibling repos ───────────────────────────────────────────────────────────

# ngx-otel-rust is the script's host — verify rather than clone (already cloned).
if [[ ! -d "${ROOT}/ngx-otel-rust/.git" ]]; then
    fail "ngx-otel-rust not found at ${ROOT}/ngx-otel-rust.

  This script lives inside ngx-otel-rust; expected layout:
    ${ROOT}/
    ├── ngx-otel-rust/      (this script's parent)
    ├── ngx-rust/           (to be cloned)
    └── nginx/              (to be cloned)
"
    exit 1
fi
pass "ngx-otel-rust: present at ${ROOT}/ngx-otel-rust"

# ngx-rust: F5 fork on ngx-otel-rust-deadlock-fix branch.
# Cargo.toml consumes it via `path = "../ngx-rust"`.
clone_or_pull "ngx-rust" \
    "git@github.com:CVanF5/ngx-rust.git" \
    "${BRANCH_ngx_rust:-ngx-otel-rust-deadlock-fix}"

# nginx: CVanF5 fork tracks upstream.  make build uses this checkout's
# auto/configure to produce objs/nginx.
clone_or_pull "nginx" \
    "git@github.com:CVanF5/nginx.git" \
    "${BRANCH_nginx:-master}"

# ── docker images ───────────────────────────────────────────────────────────

if [[ "${SKIP_DOCKER_PULL:-0}" != "1" ]]; then
    if command -v docker >/dev/null 2>&1; then
        info "docker: pulling otel collector image (used by test-harness)"
        docker pull otel/opentelemetry-collector-contrib:latest >/dev/null 2>&1 \
            && pass "docker: collector image ready" \
            || info "docker: collector pull failed (non-fatal; will retry on first test)"
    else
        info "docker: not installed — collector + TSAN substrate will be unavailable.
        Install with: apt install docker.io  (Debian / Ubuntu)"
    fi
fi

# ── next steps ──────────────────────────────────────────────────────────────

echo ""
pass "Layout ready at ${ROOT}"
echo ""
echo "Next steps:"
echo "  cd ${ROOT}/ngx-otel-rust"
echo "  make build                                   # compile sanity"
echo "  bash tests/integration/run_grpc_smoke.sh     # unary gRPC regression gate"
echo "  bash tests/integration/run_grpc_bidi_smoke.sh  # bidi gRPC regression gate"
echo ""
echo "Linux-only (Docker required):"
echo "  make tsan-test                               # Phase 1.2 Item 3.1 gate"
echo ""
