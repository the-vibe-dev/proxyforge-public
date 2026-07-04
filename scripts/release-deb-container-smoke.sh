#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--inside-container" ]]; then
  artifact="${2:-/release/proxyforge_${PROXYFORGE_VERSION:-0.1.0-alpha.1}_amd64.deb}"
  gui_smoke="0"
  browser_trust_smoke="0"
  for arg in "${@:3}"; do
    case "${arg}" in
      --gui)
        gui_smoke="1"
        ;;
      --browser-trust)
        browser_trust_smoke="1"
        ;;
    esac
  done
  export DEBIAN_FRONTEND=noninteractive

  apt-get update -qq
  apt-get install -y --no-install-recommends "${artifact}"
  if [[ "${gui_smoke}" == "1" ]]; then
    apt-get install -y --no-install-recommends xvfb xauth
  fi
  if [[ "${browser_trust_smoke}" == "1" ]]; then
    apt-get install -y --no-install-recommends chromium libnss3-tools
  fi
  test -x /opt/ProxyForge/proxyforge
  ELECTRON_RUN_AS_NODE=1 /opt/ProxyForge/proxyforge -e 'console.log(JSON.stringify({electron:process.versions.electron,node:process.version,platform:process.platform,arch:process.arch}))'
  if [[ "${gui_smoke}" == "1" ]]; then
    gui_output="$(PROXYFORGE_RELEASE_SMOKE=1 xvfb-run -a /opt/ProxyForge/proxyforge --no-sandbox 2>&1)"
    printf '%s\n' "${gui_output}"
    if [[ "${gui_output}" != *"PROXYFORGE_RELEASE_SMOKE"* || "${gui_output}" != *'"status":"passed"'* ]]; then
      printf '%s\n' 'Installed GUI smoke did not report a passed release payload.' >&2
      exit 1
    fi
    printf '%s\n' 'proxyforge-deb-container-gui-smoke: passed'
  fi
  if [[ "${browser_trust_smoke}" == "1" ]]; then
    browser_trust_out="${PROXYFORGE_DEB_SMOKE_CONTAINER_OUT:-/out/proxyforge-browser-trust}"
    mkdir -p "${browser_trust_out}"
    ELECTRON_RUN_AS_NODE=1 /opt/ProxyForge/proxyforge /opt/ProxyForge/resources/app.asar/dist-electron/releaseBrowserRoutingSmoke.js --out-dir "${browser_trust_out}" --browser chromium --trusted-ca
    printf '%s\n' 'proxyforge-deb-container-browser-trust-smoke: passed'
  fi
  dpkg-query -W -f='${Package} ${Version} ${Status}\n' proxyforge
  apt-get remove -y proxyforge
  test ! -e /opt/ProxyForge/proxyforge
  printf '%s\n' 'proxyforge-deb-container-install-smoke: passed'
  exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(node -p "require('${root}/package.json').version")"
gui_smoke="0"
browser_trust_smoke="0"
artifact=""
for arg in "$@"; do
  case "${arg}" in
    --gui)
      gui_smoke="1"
      ;;
    --browser-trust)
      browser_trust_smoke="1"
      ;;
    *)
      if [[ -z "${artifact}" ]]; then
        artifact="${arg}"
      else
        printf 'Unexpected argument: %s\n' "${arg}" >&2
        exit 1
      fi
      ;;
  esac
done
artifact="${artifact:-release/proxyforge_${version}_amd64.deb}"
image="${PROXYFORGE_DEB_SMOKE_IMAGE:-debian:bookworm-slim}"
docker_command="${PROXYFORGE_DOCKER:-docker}"

if [[ "${artifact}" != /* ]]; then
  artifact="${root}/${artifact}"
fi

if [[ ! -f "${artifact}" ]]; then
  printf 'Deb artifact not found: %s\n' "${artifact}" >&2
  exit 1
fi

artifact_dir="$(cd "$(dirname "${artifact}")" && pwd)"
artifact_name="$(basename "${artifact}")"
script_path="${root}/scripts/release-deb-container-smoke.sh"
out_dir="${PROXYFORGE_DEB_SMOKE_OUT:-${root}/.gitignored/deb-container-smoke}"
mkdir -p "${out_dir}"

read -r -a docker_parts <<< "${docker_command}"
container_args=(bash /work/release-deb-container-smoke.sh --inside-container "/release/${artifact_name}")
if [[ "${gui_smoke}" == "1" ]]; then
  container_args+=(--gui)
fi
if [[ "${browser_trust_smoke}" == "1" ]]; then
  container_args+=(--browser-trust)
fi
"${docker_parts[@]}" run --rm \
  -e "PROXYFORGE_VERSION=${version}" \
  -v "${artifact_dir}:/release:ro" \
  -v "${script_path}:/work/release-deb-container-smoke.sh:ro" \
  -v "${out_dir}:/out" \
  "${image}" \
  "${container_args[@]}"
