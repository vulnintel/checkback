#!/usr/bin/env bash
# Clean-room E2E: npm pack → install the tarball in fresh node:<v>-slim images → run e2e.mjs
# with the network (no consent, local rules only) and with --network none (consent, lookups fail soft).
# Usage: bash docker/e2e/run.sh            (Node 20 and 22)
#        E2E_NODE_VERSIONS="22" bash docker/e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
pack=docker/e2e/.pack
rm -rf "$pack" && mkdir -p "$pack"
pnpm build
npm pack --silent --pack-destination "$pack" >/dev/null
mv "$pack"/checkback-*.tgz "$pack/checkback.tgz"

status=0
for v in ${E2E_NODE_VERSIONS:-20 22}; do
  tag="checkback-e2e:node$v"
  echo "::group::build node:$v-slim"
  docker build --pull --build-arg "NODE_IMAGE=node:$v-slim" -t "$tag" docker/e2e
  echo "::endgroup::"
  echo "== node $v · network on, no consent"
  docker run --rm "$tag" online || status=1
  echo "== node $v · --network none, consent given"
  docker run --rm --network none "$tag" offline || status=1
done
exit $status
