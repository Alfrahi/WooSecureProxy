#!/usr/bin/env bash
# Builds an installable release zip with a prefixed vendor/ tree.
#
# Steps: clean copy -> composer --no-dev -> php-scoper prefix -> zip.
# Requires: composer, zip, php, curl (if the php-scoper phar is missing).
#
# Usage: bin/build-release.sh [version]
set -euo pipefail

PLUGIN_SLUG="woo-secure-proxy"
VERSION="${1:-$(git -C "$(dirname "$0")/.." describe --tags --always 2>/dev/null || echo 'dev')}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
DIST_DIR="${ROOT}/dist"
SCOPER="${ROOT}/tools/php-scoper.phar"
WORK="${BUILD_DIR}/${PLUGIN_SLUG}"

trap 'rm -rf "${BUILD_DIR}"' EXIT

mkdir -p "${WORK}" "${DIST_DIR}"

# 1. Copy the runtime file set (no tests, no dev tooling, no git state).
cp "${ROOT}/woo-secure-proxy.php" "${ROOT}/uninstall.php" \
   "${ROOT}/README.md" "${ROOT}/LICENSE" "${ROOT}/composer.json" \
   "${ROOT}/composer.lock" "${WORK}/"
cp -r "${ROOT}/src" "${WORK}/"

# 2. Production-only dependencies, from the committed lock file.
composer install --working-dir="${WORK}" --no-dev --no-interaction \
  --prefer-dist --optimize-autoloader --quiet

# 3. Prefix the vendored dependencies (see docs/DEPENDENCIES.md).
if [ ! -f "${SCOPER}" ]; then
	mkdir -p "${ROOT}/tools"
	curl -fsSL -o "${SCOPER}" \
	  https://github.com/humbug/php-scoper/releases/latest/download/php-scoper.phar
fi
php "${SCOPER}" add-prefix \
  --working-dir="${WORK}" \
  --config="${ROOT}/scoper.inc.php" \
  --output-dir="${WORK}/scoped" \
  --force --quiet
mv "${WORK}/scoped/vendor" "${WORK}/vendor"
rm -rf "${WORK}/scoped"

# 4. Re-dump the autoloader inside the scoped tree.
composer dump-autoload --working-dir="${WORK}" --no-dev --optimize --quiet

# 5. Zip it.
cd "${BUILD_DIR}"
zip -qr "${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip" "${PLUGIN_SLUG}"
echo "Built ${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip"
