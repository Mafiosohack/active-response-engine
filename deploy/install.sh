#!/bin/sh
# Installs the Active Response Engine as a systemd service.
#
#   sudo sh deploy/install.sh        (run from the project folder, on the router VM)
#
# Safe to run again after updating the code: it replaces the code and the unit
# file, and keeps config.yaml, the API token and ips.db exactly as they are.
# It never starts or enables the service; the last lines it prints say how.
set -eu

PREFIX=/opt/are
ETC_DIR=/etc/are
STATE_DIR=/var/lib/are
ENV_FILE=$ETC_DIR/are.env
UNIT_FILE=/etc/systemd/system/are.service
WRAPPER=/usr/local/bin/are
MIN_PYTHON="3.10"

SRC=$(cd "$(dirname "$0")/.." && pwd)

fail() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run this as root: sudo sh deploy/install.sh"
[ -f "$SRC/pyproject.toml" ] && [ -d "$SRC/are" ] || fail "$SRC does not look like the project folder"
command -v python3 >/dev/null || fail "python3 is not installed"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || fail "python3 is $(python3 -V 2>&1); version $MIN_PYTHON or newer is needed"
python3 -c 'import ensurepip, venv' 2>/dev/null \
    || fail "the python venv module is missing: apt install python3-venv"
command -v systemctl >/dev/null || fail "systemd is not available on this machine"
command -v nft >/dev/null || echo "warning: nft is not installed (apt install nftables); only the dry_run driver will work"

echo "==> code into $PREFIX"
install -d -m 0755 "$PREFIX" "$PREFIX/data"
rm -rf "$PREFIX/are"
cp -R "$SRC/are" "$PREFIX/are"
find "$PREFIX/are" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m 0644 "$SRC/pyproject.toml" "$SRC/requirements.txt" "$SRC/README.md" "$PREFIX/"
# The pinned ATT&CK / D3FEND files, if they came across with the project.
for f in "$SRC"/data/*.json; do
    if [ -f "$f" ]; then install -m 0644 "$f" "$PREFIX/data/"; fi
done

echo "==> config"
if [ -f "$PREFIX/config.yaml" ]; then
    echo "    kept the existing $PREFIX/config.yaml"
else
    install -m 0644 "$SRC/config.yaml" "$PREFIX/config.yaml"
    # The service may only write under $STATE_DIR, so the decision log has to live there.
    sed -i "s|^  db_path: ips\.db |  db_path: $STATE_DIR/ips.db |" "$PREFIX/config.yaml"
    grep -q "^  db_path: $STATE_DIR/ips.db " "$PREFIX/config.yaml" \
        || echo "    warning: set engine.db_path to $STATE_DIR/ips.db in $PREFIX/config.yaml by hand"
    echo "    installed $PREFIX/config.yaml (still needs network.* and adapters.nids.db_path)"
fi

echo "==> python environment"
[ -x "$PREFIX/venv/bin/python" ] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
# Runtime dependencies come from pyproject.toml; requirements.txt also carries the test tools.
"$PREFIX/venv/bin/pip" install --quiet --editable "$PREFIX"

echo "==> API token"
install -d -m 0750 "$ETC_DIR"
if [ -f "$ENV_FILE" ]; then
    echo "    kept the existing $ENV_FILE"
else
    ( umask 077
      printf 'ARE_API_TOKEN=%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" > "$ENV_FILE" )
    echo "    wrote a new random token to $ENV_FILE (readable by root only)"
fi
chmod 0600 "$ENV_FILE"

echo "==> state directory $STATE_DIR"
install -d -m 0700 "$STATE_DIR"

echo "==> the 'are' command"
cat > "$WRAPPER" <<EOF
#!/bin/sh
# Runs the engine's command line with the installed config and API token.
set -a
[ -r $ENV_FILE ] && . $ENV_FILE
set +a
exec $PREFIX/venv/bin/are --config $PREFIX/config.yaml "\$@"
EOF
chmod 0755 "$WRAPPER"

echo "==> systemd unit"
install -m 0644 "$SRC/deploy/are.service" "$UNIT_FILE"
systemctl daemon-reload

cat <<EOF

Installed. Nothing is running yet. Next:

  1. sudoedit $PREFIX/config.yaml      fill in network.* and adapters.nids.db_path
  2. sudo are fetch-data               only if $PREFIX/data is empty
  3. sudo are check                    validates config and pinned data
  4. sudo systemctl enable --now are   starts it now and on every boot (dry_run driver)
  5. sudo journalctl -u are -f         watch what it decides
     sudo are status | decisions | unblock <ip>

To enforce later: run 'sudo are check --nft', set engine.driver: nftables in
config.yaml, then 'sudo systemctl restart are'.
To remove: systemctl disable --now are; nft delete table inet are;
rm -rf $PREFIX $ETC_DIR $STATE_DIR $UNIT_FILE $WRAPPER
EOF
