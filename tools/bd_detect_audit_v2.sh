#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Script: bd_detect_audit_v2.sh
# Purpose (V2 Dynamic Audit):
# Discover Black Duck / Synopsys Detect integration across:
# 1) Common CI pipeline files (Azure/GHA/Jenkins/Bamboo/Travis)
# 2) Local wrapper scripts & build files
# Identify:
# - Direct integrations (Detect execution visible) => high confidence
# - Indirect integrations (templates/shared libs/container refs) => medium/low confidence
#
# Outputs:
# - Console summary
# - CSV report (default: bd_detect_audit_v2.csv)
#
# Notes:
# - Pipeline-safe: avoids failing on grep "no match"
# - Grep-safe: uses `--` to prevent patterns being treated as options
# ============================================================

ROOT="${1:-.}"
OUT_CSV="${2:-bd_detect_audit_v2.csv}"

shopt -s globstar nullglob

PIPELINE_GLOBS=(
  "azure-pipelines.yml" "azure-pipelines.yaml"
  ".github/workflows/*.yml" ".github/workflows/*.yaml"
  "Jenkinsfile" "Jenkinsfile*"
  ".travis.yml"
  "bamboo-specs/**/*.yml" "bamboo-specs/**/*.yaml"
  "**/bamboo-specs.yml" "**/bamboo-specs.yaml"
)

WRAPPER_GLOBS=(
  "ci/**/*"
  "scripts/**/*"
  ".ci/**/*"
  ".github/scripts/**/*"
  ".jenkins/**/*"
  ".build/**/*"
  "build/**/*"
  "tools/**/*"
  "devops/**/*"
  "Makefile" "Makefile.*"
  "**/*.sh"
  "**/*.bash"
  "**/*.ps1"
  "**/*.cmd"
  "**/*.bat"
  "**/*.groovy"
  "**/*.gradle"
  "**/*.kts"
  "**/pom.xml"
  "**/build.gradle"
  "**/package.json"
  "**/requirements.txt"
)

DIRECT_DETECT_PATTERN='detect\.sh|synopsys[- ]?detect|hub-detect|blackduck\.hub\.detect|java[[:space:]]+-jar[[:space:]].*detect|--blackduck\.|--detect\.project\.name|--detect\.project\.version\.name'

URL_PATTERN='blackduck\.url|BLACKDUCK_URL|DETECT_BLACKDUCK_URL'
TOKEN_PATTERN='blackduck\.(api\.token|token)|BLACKDUCK_API_TOKEN|DETECT_BLACKDUCK_API_TOKEN|BLACKDUCK_TOKEN|DETECT_TOKEN'
PROJECT_PATTERN='detect\.project\.name|PROJECT_NAME|DETECT_PROJECT_NAME'
VERSION_PATTERN='detect\.project\.version\.name|PROJECT_VERSION|DETECT_PROJECT_VERSION'

# NOTE: patterns containing "- template:" must not be interpreted by grep as options.
# We'll always call grep with: grep ... -- "$pattern" "$file"
INDIRECT_TEMPLATE_PATTERN='- template:|extends:|resources:|@templates|include:|uses:[[:space:]]*[^[:space:]]+\/[^[:space:]]+@|workflow_call|reusable workflow'
INDIRECT_JENKINS_LIB_PATTERN='@Library\(|library\(|sharedLibrary|vars\/|def[[:space:]]+securityScan|securityScan\(|blackduckScan\(|detectScan\('
INDIRECT_CONTAINER_PATTERN='docker[[:space:]]+run|container:|image:|services:|podman[[:space:]]+run'
INDIRECT_KEYWORDS_PATTERN='blackduck|synopsys|detect|polaris|coverity|sca|sast'

echo "repo,artifact_type,file_path,ci_type,found_type,confidence,approach,invocation_style,blackduck_url_ref,token_ref,project_name_ref,project_version_ref,example_lines" > "$OUT_CSV"

# --- Helper: safe grep wrappers to avoid "invalid option" and -e pipefail failures ---
grep_q() { grep -Eq "$1" -- "$2" 2>/dev/null; } # quiet (true/false), no output
grep_in() { grep -Ein "$1" -- "$2" 2>/dev/null || true; } # numbered output, never fails

ci_type_of() {
  local f="$1"
  if [[ "$f" == *".github/workflows/"* ]]; then echo "github_actions"
  elif [[ "$(basename "$f")" == "azure-pipelines.yml" || "$(basename "$f")" == "azure-pipelines.yaml" ]]; then echo "azure_devops"
  elif [[ "$(basename "$f")" == Jenkinsfile* ]]; then echo "jenkins"
  elif [[ "$(basename "$f")" == ".travis.yml" ]]; then echo "travis"
  elif [[ "$f" == *"bamboo-specs"* ]]; then echo "bamboo"
  else echo "unknown"
  fi
}

detect_invocation_style() {
  local f="$1"
  if grep_q 'bash[[:space:]]*<\([[:space:]]*curl.*detect\.sh' "$f"; then
    echo "bash_process_substitution_curl_detect.sh"
  elif grep_q 'curl.*detect\.sh.*\|[[:space:]]*bash' "$f"; then
    echo "curl_pipe_bash_detect.sh"
  elif grep_q 'java[[:space:]]+-jar[[:space:]].*detect' "$f"; then
    echo "java_jar_detect"
  elif grep_q 'synopsys[- ]?detect' "$f"; then
    echo "synopsys_detect_wrapper"
  elif grep_q 'detect\.sh' "$f"; then
    echo "detect_sh_direct"
  else
    echo "unknown"
  fi
}

extract_best_ref() {
  local f="$1"
  local pat="$2"
  local line
  line="$(grep_in "$pat" "$f" | head -1)"
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  line="${line#*:}"
  echo "$line" | sed -E 's/[[:space:]]+/ /g' | cut -c1-160
}

example_lines() {
  local f="$1"
  local n=6
  local bigpat="$DIRECT_DETECT_PATTERN|$URL_PATTERN|$TOKEN_PATTERN|$PROJECT_PATTERN|$VERSION_PATTERN|$INDIRECT_TEMPLATE_PATTERN|$INDIRECT_JENKINS_LIB_PATTERN|$INDIRECT_CONTAINER_PATTERN"

  (
    { grep_in "$bigpat" "$f"; } \
      | head -n "$n" \
      | sed -E 's/"/""/g' \
      | tr '\n' ';' \
      | sed 's/;*$//'
  )
}

classify_found() {
  local f="$1"

  if grep_q "$DIRECT_DETECT_PATTERN" "$f"; then
    echo "direct,high,detect_present"; return
  fi
  if grep_q "$INDIRECT_TEMPLATE_PATTERN" "$f" && grep_q "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,medium,template_or_reusable_workflow"; return
  fi
  if grep_q "$INDIRECT_JENKINS_LIB_PATTERN" "$f"; then
    echo "indirect,medium,jenkins_shared_library_or_wrapper"; return
  fi
  if grep_q "$INDIRECT_CONTAINER_PATTERN" "$f" && grep_q "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,medium,container_based_scan"; return
  fi
  if grep_q "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,low,keyword_only_possible_scan"; return
  fi

  echo "none,none,none"
}

scan_files_and_report() {
  local repo="$1"
  local repobase="$2"
  local artifact_type="$3"
  shift 3
  local files=("$@")

  for abs in "${files[@]}"; do
    [[ -f "$abs" ]] || continue
    local rel="${abs#$repo/}"

    local cls found_type confidence approach
    cls="$(classify_found "$abs")"
    found_type="${cls%%,*}"
    cls="${cls#*,}"
    confidence="${cls%%,*}"
    approach="${cls#*,}"

    if [[ "$found_type" == "none" ]]; then
      continue
    fi

    local ci="n/a"
    if [[ "$artifact_type" == "pipeline" ]]; then
      ci="$(ci_type_of "$rel")"
    fi

    local style=""
    if [[ "$found_type" == "direct" ]]; then
      style="$(detect_invocation_style "$abs")"
    fi

    local urlref tokref projref verref ex
    urlref="$(extract_best_ref "$abs" "$URL_PATTERN")"
    tokref="$(extract_best_ref "$abs" "$TOKEN_PATTERN")"
    projref="$(extract_best_ref "$abs" "$PROJECT_PATTERN")"
    verref="$(extract_best_ref "$abs" "$VERSION_PATTERN")"
    ex="$(example_lines "$abs")"

    echo "[${found_type^^}] ($confidence) $repobase :: $rel (artifact=$artifact_type, approach=$approach${style:+, style=$style})"
    echo "\"$repobase\",\"$artifact_type\",\"$rel\",\"$ci\",\"$found_type\",\"$confidence\",\"$approach\",\"$style\",\"$urlref\",\"$tokref\",\"$projref\",\"$verref\",\"$ex\"" >> "$OUT_CSV"
  done
}

audit_repo() {
  local repo="$1"
  local repobase
  repobase="$(basename "$repo")"

  local pipeline_files=()
  for g in "${PIPELINE_GLOBS[@]}"; do
    for f in "$repo"/$g; do
      [[ -f "$f" ]] && pipeline_files+=("$f")
    done
  done
  mapfile -t pipeline_files < <(printf "%s\n" "${pipeline_files[@]}" | awk '!seen[$0]++')

  local wrapper_files=()
  for g in "${WRAPPER_GLOBS[@]}"; do
    for f in "$repo"/$g; do
      [[ -f "$f" ]] && wrapper_files+=("$f")
    done
  done
  mapfile -t wrapper_files < <(printf "%s\n" "${wrapper_files[@]}" | awk '!seen[$0]++')

  if [[ ${#pipeline_files[@]} -eq 0 && ${#wrapper_files[@]} -eq 0 ]]; then
    echo "[INFO] $repobase: no files matched for scanning"
    return
  fi

  if [[ ${#pipeline_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repobase" "pipeline" "${pipeline_files[@]}"
  else
    echo "[INFO] $repobase: no pipeline files found"
  fi

  if [[ ${#wrapper_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repobase" "wrapper_or_script" "${wrapper_files[@]}"
  else
    echo "[INFO] $repobase: no wrapper/script files found"
  fi
}

echo "Writing report to: $OUT_CSV"
echo

if [[ -d "$ROOT/.git" ]]; then
  audit_repo "$ROOT"
else
  for d in "$ROOT"/*; do
    [[ -d "$d/.git" ]] || continue
    audit_repo "$d"
  done
fi

echo
echo "Done. CSV: $OUT_CSV"
echo "How to read results:"
echo " - found_type=direct + confidence=high => Detect is directly invoked here (true execution point)"
echo " - found_type=indirect + confidence=medium => likely via templates/shared-lib/container"
echo " - found_type=indirect + confidence=low => only keywords; needs manual verification"
echo "Tip: Filter CSV on confidence=high first."
