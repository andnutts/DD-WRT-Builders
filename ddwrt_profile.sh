#!/usr/bin/env bash
# Gather DD-WRT board profile with mappings, interactive confirmation, and menu-driven UI (bash conversion)
set -euo pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
VERSION="1.0.0"

# ----------------------
# Default parameters
# ----------------------
REPO_URL="https://github.com/dd-wrt/dd-wrt.git"
WORK_DIR="$PWD/ddwrt-build"
BOOTLOG=""
declare -a NVRAM_FILES=()
MAPPINGS_FILE="$PWD/mappings/ddwrt-mappings.json"
DRY_RUN=0
FORCE=0
VERBOSE=0

# ----------------------
# Logging and helpers
# ----------------------
log() {
  local level="${2:-INFO}"
  if [[ "$level" == "DEBUG" && $VERBOSE -eq 0 ]]; then return; fi
  printf '[%s] [%s] %s\n' "$(date -Iseconds)" "$level" "$1"
}
die() { log "$1" "ERROR"; exit 1; }

safe_readfile() {
  local path="$1"
  if [[ ! -f "$path" ]]; then die "File not found: $path"; fi
  cat "$path"
}

load_mappings() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    log "Mappings file not found at $path" "DEBUG"
    echo "[]"
    return
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -c '.' "$path"
  else
    # fallback: output raw JSON (best-effort)
    cat "$path"
  fi
}

ensure_git_clone() {
  local repo="$1" path="$2"
  if [[ -d "$path/.git" ]]; then
    pushd "$path" >/dev/null
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      if (( DRY_RUN )); then
        log "Dry-run: would fetch and reset repo in $path" "INFO"
        popd >/dev/null
        echo "dry-run-commit"
        return
      fi
      git fetch --all --prune --quiet
      git reset --hard origin/HEAD --quiet
      commit=$(git rev-parse --short HEAD)
      popd >/dev/null
      log "Updated repo to $commit" "INFO"
      echo "$commit"
      return
    fi
    popd >/dev/null
    rm -rf -- "$path"
  fi
  if (( DRY_RUN )); then
    log "Dry-run: would clone $repo to $path" "INFO"
    echo "dry-run-commit"
    return
  fi
  log "Cloning $repo to $path" "INFO"
  git clone --depth 1 "$repo" "$path" --quiet
  pushd "$path" >/dev/null
  commit=$(git rev-parse --short HEAD)
  popd >/dev/null
  log "Cloned repo at commit $commit" "INFO"
  echo "$commit"
}

# ----------------------
# Binary/string extraction
# ----------------------
extract_strings() {
  local file="$1"
  if command -v strings >/dev/null 2>&1; then
    strings -a -n 4 "$file" || true
    return
  fi
  # fallback: use python to extract printable runs >=4
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import sys
b=open("$file","rb").read()
out=[]
run=[]
for c in b:
    if 32 <= c <= 126:
        run.append(chr(c))
    else:
        if len(run) >= 4:
            out.append(''.join(run))
        run=[]
if len(run) >= 4:
    out.append(''.join(run))
sys.stdout.write("\n".join(out))
PY
    return
  fi
  # last fallback: hexdump printable ascii (best effort)
  hexdump -v -e '1/1 "%c"' "$file" | sed 's/[^[:print:]]/ /g' | tr -s ' ' | sed -n '1,1000p'
}

# ----------------------
# Parsers
# ----------------------
parse_bootlog() {
  local text
  text="$1"
  # Output as simple key:value lines
  echo "Raw:START"
  printf '%s\n' "$text"
  echo "Raw:END"
  # Extract some fields
  awk '
  BEGIN{IGNORECASE=1}
  /Model[[:space:]]*:|Model[[:space:]]/ { sub(/^.*Model[: ]*/,""); print "Model:"$0 }
  /Machine[[:space:]]*:|Machine[[:space:]]/ { sub(/^.*Machine[: ]*/,""); print "Machine:"$0 }
  /Board[[:space:]]*:|Board[[:space:]]/ { sub(/^.*Board[: ]*/,""); print "Board:"$0 }
  /([0-9A-Fa-f]{2}(:|-)){5}[0-9A-Fa-f]{2}/ {
    match($0, /([0-9A-Fa-f]{2}(:|-)){5}[0-9A-Fa-f]{2}/, m);
    if (m[0] != "") print "MAC:" m[0];
  }
  /kernel.*cmdline/ { print "Cmdline:" $0 }
  /soc|Atheros|Qualcomm|Broadcom/ { print "Soc:" $0 }
  /(mtd|nand|spi|flash|NOR|NAND|SPI)/ { print "Flash:" $0 }
  ' <<<"$text" | awk -F: '!seen[$1"_"$2]++ { print $1":"substr($0, index($0,$2)) }'
}

parse_nvram_strings() {
  local strings="$1"
  # Output as key=value lines; handles "key=value" and "key: value" or "key - value" common patterns
  while IFS= read -r line; do
    l="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ "$l" =~ ^([^=[:space:]]+)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      k="${BASH_REMATCH[1]}"
      v="${BASH_REMATCH[2]}"
      echo "$k=$v"
    elif [[ "$l" =~ ^(productid|model|board|boardid)[[:space:]]*[:\-][[:space:]]*(.+)$ ]]; then
      k="${BASH_REMATCH[1]}"
      v="${BASH_REMATCH[2]}"
      echo "$k=$v"
    fi
  done <<<"$strings"
}

# ----------------------
# Filesystem/tree matching and scoring
# ----------------------
try_match_intree() {
  local workdir="$1"
  shift
  local -a candidates=("$@")
  for c in "${candidates[@]}"; do
    [[ -z "$c" ]] && continue
    # sanitize search: treat spaces as wildcard
    local pattern
    pattern="$(printf "%s" "$c" | sed 's/[[:space:]]\\+/\\*/g;s/[][^$.*/]/\\&/g')"
    # find within depth 4
    find "$workdir" -maxdepth 4 -type f -iname "*${c}*" -print -quit 2>/dev/null || true
  done
}

score_with_mappings() {
  local mappings_json="$1"    # one-line JSON (jq optional)
  shift
  local -a search_strings=("$@")
  if command -v jq >/dev/null 2>&1; then
    # produce id,score,matches lines
    echo "$mappings_json" | jq -c '.[]' | while read -r m; do
      id=$(jq -r '.id // empty' <<<"$m")
      keys=$(jq -r '.keys[]? // empty' <<<"$m")
      score=0
      matches=()
      while IFS= read -r k; do
        for s in "${search_strings[@]}"; do
          if [[ -n "$s" && "${s,,}" == *"${k,,}"* ]]; then
            ((score+=10))
            matches+=("$k")
          fi
        done
      done <<<"$keys"
      printf '%s\t%d\t%s\n' "$id" "$score" "$(IFS=','; echo "${matches[*]}")"
    done | sort -k2 -nr
  else
    # Without jq we cannot parse mappings reliably
    log "jq not available; skipping mapping scoring" "DEBUG"
    return
  fi
}

# ----------------------
# Small interactive prompt helper
# ----------------------
prompt_edit_field() {
  local label="$1" current="$2"
  read -r -p "$label [$current]: " input
  if [[ -z "$input" ]]; then
    printf "%s" "$current"
  elif [[ "$input" == "clear" ]]; then
    printf ""
  else
    printf "%s" "$input"
  fi
}

# ----------------------
# Argument parsing (getopt)
# ----------------------
print_usage() {
  cat <<USAGE
Usage: $PROGNAME --bootlog FILE [options]
Options:
  --repo-url URL        Git repo to clone (default $REPO_URL)
  --workdir DIR         Working directory (default $WORK_DIR)
  --bootlog FILE        Path to device boot log (required)
  --nvram FILE          One or more NVRAM blob paths (can be repeated)
  --mappings FILE       Mappings JSON (default $MAPPINGS_FILE)
  --dry-run             Do not write files or modify repo
  --force               Overwrite existing profile without prompting
  --verbose             Show debug logs
  -h, --help            Show this help
USAGE
}

# use getopt for long options
PARSED=$(getopt -o h --long repo-url:,workdir:,bootlog:,nvram:,mappings:,dry-run,force,verbose,help -n "$PROGNAME" -- "$@") || { print_usage; exit 2; }
eval set -- "$PARSED"
while true; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --workdir) WORK_DIR="$2"; shift 2 ;;
    --bootlog) BOOTLOG="$2"; shift 2 ;;
    --nvram) NVRAM_FILES+=("$2"); shift 2 ;;
    --mappings) MAPPINGS_FILE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

[[ -n "$BOOTLOG" ]] || { print_usage; die "Missing required --bootlog"; }

# ----------------------
# Main flow (example orchestration)
# ----------------------
main() {
  log "Starting $PROGNAME version $VERSION" "INFO"
  log "Boot log: $BOOTLOG" "DEBUG"
  commit="$(ensure_git_clone "$REPO_URL" "$WORK_DIR")"
  log "Repo commit: $commit" "DEBUG"

  log "Reading boot log" "INFO"
  BOOT_RAW="$(safe_readfile "$BOOTLOG")"

  log "Parsing boot log" "DEBUG"
  parse_bootlog "$BOOT_RAW" > /tmp/ddwrt_boot_parsed.txt || true

  # Extract strings from NVRAM files
  declare -a NV_STRINGS=()
  for f in "${NVRAM_FILES[@]}"; do
    if [[ -f "$f" ]]; then
      log "Extracting strings from $f" "DEBUG"
      NV_STRINGS+=( "$(extract_strings "$f")" )
    else
      log "NVRAM file not found: $f" "DEBUG"
    fi
  done

  # Load mappings
  mappings_json="$(load_mappings "$MAPPINGS_FILE")"

  # Build search string list (boot parsed values + nvram contents)
  declare -a SEARCH_STRINGS=()
  # include lines from parsed boot that look useful
  mapfile -t parsed_lines < <(awk -F: '/^(Model|Machine|Board|Soc|MAC|Cmdline|Flash):/ { print $2 }' /tmp/ddwrt_boot_parsed.txt | sed 's/^[[:space:]]*//')
  for pl in "${parsed_lines[@]}"; do
    SEARCH_STRINGS+=("$pl")
  done
  for s in "${NV_STRINGS[@]}"; do
    # add first 200 lines of each nvram string as candidates
    mapfile -t parts < <(printf '%s\n' "$s" | sed -n '1,200p')
    for p in "${parts[@]}"; do SEARCH_STRINGS+=("$p"; done
  done

  log "Scoring with mappings (top results):" "INFO"
  if [[ "${mappings_json:-}" != "[]" ]]; then
    score_with_mappings "$mappings_json" "${SEARCH_STRINGS[@]}" | head -n 20 || true
  else
    log "No mappings loaded" "INFO"
  fi

  # Example of trying to find candidates in repo tree
  log "Trying to match candidate names in tree (sample)" "DEBUG"
  # Use first few parsed lines as candidates
  mapfile -t candidates < <(printf '%s\n' "${parsed_lines[@]}" | sed -n '1,10p')
  for c in "${candidates[@]}"; do
    try_match_intree "$WORK_DIR" "$c" || true
  done

  log "Completed analysis (dry-run=$DRY_RUN). Review outputs above." "INFO"
}

main "$@"
