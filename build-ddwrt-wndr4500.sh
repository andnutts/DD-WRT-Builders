#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Configuration
WORKDIR="${HOME}/ddwrt-build"
REPO_URL="https://github.com/mirror/dd-wrt.git"
REPO_DIR="${WORKDIR}/ddwrt"
BOOTLOG_PATH="${1:-}"         # first arg optional: path to bootlog text file
SERIAL_DEVICE="${2:-}"        # optional second arg: e.g., /dev/ttyUSB0 to capture live bootlog
BAUDRATE="${3:-115200}"
BOARD_NAME_FALLBACK="WNDR4500"
OUTPUT_DIR="${WORKDIR}/output"
IMAGE_PATTERNS=("*.trx" "*.chk" "*-factory.*" "*-recovery.*")
REQUIRED_PKGS=(git build-essential subversion libncurses5-dev zlib1g-dev gawk flex bison \
  libssl-dev u-boot-tools python3 python3-distutils hexdump)

# Utilities
log() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ensure_workdir() {
  mkdir -p "${WORKDIR}"
  mkdir -p "${OUTPUT_DIR}"
}

capture_bootlog() {
  local out="${OUTPUT_DIR}/bootlog.txt"
  if [[ -n "${BOOTLOG_PATH}" && -f "${BOOTLOG_PATH}" ]]; then
    cp "${BOOTLOG_PATH}" "${out}"
    log "Using provided bootlog: ${BOOTLOG_PATH} -> ${out}"
  elif [[ -n "${SERIAL_DEVICE}" && -c "${SERIAL_DEVICE}" ]]; then
    log "Capturing serial output from ${SERIAL_DEVICE} at ${BAUDRATE} baud for 10s..."
    timeout 10s cat "${SERIAL_DEVICE}" > "${out}" || true
    log "Saved serial capture to ${out}"
  else
    err "No bootlog file and no serial device provided. Provide bootlog path as first arg or serial device as second arg."
  fi
  echo "${out}"
}

# parse bootlog for fields we need
parse_bootlog() {
  local src="$1"
  local outjson="${OUTPUT_DIR}/device-info.json"

  # init defaults
  local boardname="${BOARD_NAME_FALLBACK}"
  local cpu_rev=""
  local cpu_model=""
  local cpu_mhz=""
  local nand_total_bytes=""
  local nand_page=""
  local nand_oob=""
  local nand_block=""
  local bootloader_size=""
  local nvram_size=""
  local boardflags=""
  local boardflags2=""

  # read file
  local content
  content="$(<"${src}")"

  # boardname: try explicit label lines, otherwise fallback
  boardname="$(awk '/^found .*WNDR|WNDR4500|found WNDR4500/ {for(i=1;i<=NF;i++) if ($i ~ /WNDR/){print $i; exit}}' "${src}" || true)"
  boardname="${boardname:-${BOARD_NAME_FALLBACK}}"

  # CPU model and freq
  cpu_model="$(awk -F: '/CPU: /{print $2; exit}' "${src}" | sed -e 's/^[[:space:]]*//' || true)"
  cpu_mhz="$(awk '/CPU: .* at/ { if (match($0, /at[[:space:]]*([0-9]+)[[:space:]]*MHz/,a)) print a[1]; exit }' "${src}" || true)"
  cpu_rev="$(awk '/CPU0 revision is:/ {print $NF; exit}' "${src}" || true)"

  # NAND geometry and sizes
  nand_total_bytes="$(awk '/Samsung NAND/ { if (match($0, /([0-9]+)MiB/,a)) print a[1]*1024*1024; exit }' "${src}" || true)"
  if [[ -z "${nand_total_bytes}" ]]; then
    # alternative parse "nand: 128 MiB"
    nand_total_bytes="$(awk '/nand:.*MiB/ { if (match($0, /([0-9]+)[[:space:]]MiB/,a)) print a[1]*1024*1024; exit }' "${src}" || true)"
  fi
  nand_page="$(awk '/page size:/ { if (match($0, /page size:[[:space:]]*([0-9]+)/,a)) print a[1]; exit }' "${src}" || true)"
  nand_oob="$(awk '/OOB size:/ { if (match($0, /OOB size:[[:space:]]*([0-9]+)/,a)) print a[1]; exit }' "${src}" || true)"
  nand_block="$(awk '/erase size:/ { if (match($0, /erase size:[[:space:]]*([0-9]+)[[:alpha:]]*/,a)) print a[1]; exit }' "${src}" || true)"

  # bootloader and nvram
  bootloader_size="$(awk '/bootloader size:/ { if (match($0, /bootloader size:[[:space:]]*([0-9]+)/,a)) print a[1]; exit }' "${src}" || true)"
  nvram_size="$(awk '/nvram size:/ { if (match($0, /nvram size:[[:space:]]*([0-9]+)/,a)) print a[1]; exit }' "${src}" || true)"

  # boardflags
  boardflags="$(awk -F= '/boardflags=/ {gsub(/[[:space:]]/,"",$2);print $2; exit}' "${src}" || true)"
  boardflags2="$(awk -F= '/boardflags2=/ {gsub(/[[:space:]]/,"",$2);print $2; exit}' "${src}" || true)"

  # fallback conversions & defaults
  nand_total_bytes="${nand_total_bytes:-134217728}"  # default 128MiB
  nand_page="${nand_page:-2048}"
  nand_oob="${nand_oob:-64}"
  nand_block="${nand_block:-131072}" # 128KiB
  bootloader_size="${bootloader_size:-2097152}"     # 2MiB
  nvram_size="${nvram_size:-65536}"

  # write JSON
  cat > "${outjson}" <<EOF
{
  "board_name": "${boardname}",
  "cpu_model": "${cpu_model}",
  "cpu_mhz": "${cpu_mhz}",
  "cpu_rev": "${cpu_rev}",
  "nand_total_bytes": ${nand_total_bytes},
  "nand_page_size": ${nand_page},
  "nand_oob_size": ${nand_oob},
  "nand_block_size": ${nand_block},
  "bootloader_size": ${bootloader_size},
  "nvram_size": ${nvram_size},
  "boardflags": "${boardflags}",
  "boardflags2": "${boardflags2}"
}
EOF

  log "Wrote device info to ${outjson}"
  echo "${outjson}"
}

# check presence of required packages (prints missing list)
verify_build_env() {
  local missing=()
  for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
      missing+=("${pkg}")
    fi
  done
  if (( ${#missing[@]} )); then
    log "Missing packages: ${missing[*]}"
    log "Attempting to install missing packages via sudo apt-get install -y ..."
    sudo apt-get update
    sudo apt-get install -y "${missing[@]}"
  else
    log "All required packages appear installed."
  fi

  # confirm cross compile tools or build will rely on tree's toolchain
  if ! command -v make >/dev/null 2>&1; then err "make not found"; fi
  if ! command -v git >/dev/null 2>&1; then err "git not found"; fi
}

clone_repo() {
  if [[ -d "${REPO_DIR}/.git" ]]; then
    log "Repository already exists at ${REPO_DIR}, fetching latest..."
    git -C "${REPO_DIR}" fetch --all --prune
    git -C "${REPO_DIR}" checkout master || true
    git -C "${REPO_DIR}" pull --ff-only || true
  else
    log "Cloning DD-WRT repo to ${REPO_DIR}..."
    git clone "${REPO_URL}" "${REPO_DIR}"
  fi
}

export_build_vars_and_build() {
  local devicejson="$1"
  local boardname
  boardname="$(jq -r '.board_name' "${devicejson}")"
  boardname="${boardname:-${BOARD_NAME_FALLBACK}}"
  log "Setting build environment for BOARD=${boardname}"

  cd "${REPO_DIR}"
  # adapt to your tree's build invocation; this is a common pattern
  export DD_BOARD="${boardname}"
  export TARGET="broadcom"
  mkdir -p build  # ensure build dir
  log "Running make clean"
  make clean || true

  log "Starting build (this can take a long time). Output will be in ${REPO_DIR}/build/bin if successful."
  # Choose the make invocation your tree expects; try common one:
  if make V=1 TARGET=broadcom BOARD="${boardname}"; then
    log "Build finished successfully."
  else
    err "Build failed. Inspect build output above to debug."
  fi
}

find_images_and_validate() {
  local devicejson="$1"
  local found=()
  local max_payload
  local total_flash bootloader
  total_flash="$(jq -r '.nand_total_bytes' "${devicejson}")"
  bootloader="$(jq -r '.bootloader_size' "${devicejson}")"
  max_payload=$(( total_flash - bootloader ))
  log "Total flash bytes: ${total_flash}. Bootloader reserve: ${bootloader}. Max payload: ${max_payload} bytes."

  # search for images
  local bins=()
  while IFS= read -r -d $'\0' f; do bins+=("$f"); done < <(find "${REPO_DIR}" -type f \( -name "*.trx" -o -name "*.chk" -o -name "*-factory.*" -o -name "*-recovery.*" \) -print0)

  if (( ${#bins[@]} == 0 )); then
    err "No firmware images found in repo build output."
  fi

  log "Found images: ${bins[*]}"
  local chosen="${bins[0]}"
  log "Validating first candidate: ${chosen}"

  # get filesize
  local fsize
  fsize=$(stat -c%s "${chosen}")
  log "Image size: ${fsize} bytes"

  # check TRX header if present (0x30524448 "HDR0" at offset 0 for TRX)
  if hexdump -n 4 -v -e '1/4 "%08X"' "${chosen}" | grep -qi "30524448"; then
    log "TRX header detected."
    # TRX header length is at offset 8 (little endian 32-bit), total length at offset 4 sometimes; try to read common fields
    local len_le
    len_le=$(xxd -p -s 4 -l 4 -e "${chosen}" 2>/dev/null || true)
    if [[ -n "${len_le}" ]]; then
      local len_hex=$(echo "${len_le}" | tr -d '\n' | sed 's/../& /g' | awk '{print $4$3$2$1}')
      local claimed_len=$((16#${len_hex}))
      log "TRX claimed length: ${claimed_len} bytes"
      if (( claimed_len != fsize )); then
        log "Warning: TRX header claimed length (${claimed_len}) differs from file size (${fsize})."
      fi
    fi
  else
    log "No TRX signature found; file may be .chk or vendor-wrapped. Proceeding with size-only checks."
  fi

  # final fit check
  if (( fsize >= max_payload )); then
    err "Image does not fit payload area: ${fsize} >= ${max_payload}"
  fi
  log "Image fits in device payload area: ${fsize} < ${max_payload}"

  # copy chosen image to output
  cp "${chosen}" "${OUTPUT_DIR}/firmware-validated$(basename "${chosen}")"
  log "Copied validated image to ${OUTPUT_DIR}"
  printf '\nVALIDATION_RESULT\n{\n  "image":"%s",\n  "size":%d,\n  "max_payload":%d\n}\n' "${chosen}" "${fsize}" "${max_payload}" > "${OUTPUT_DIR}/validation-summary.json"
  log "Wrote validation summary to ${OUTPUT_DIR}/validation-summary.json"
}

main() {
  ensure_workdir
  local bootlogfile
  bootlogfile="$(capture_bootlog)"
  local devicejson
  devicejson="$(parse_bootlog "${bootlogfile}")"
  verify_build_env
  clone_repo
  export_build_vars_and_build "${devicejson}"
  find_images_and_validate "${devicejson}"
  log "All steps completed. Device info: ${OUTPUT_DIR}/device-info.json (and repo at ${REPO_DIR})"
}

main "$@"
