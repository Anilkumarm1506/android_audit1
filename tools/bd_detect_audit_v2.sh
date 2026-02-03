#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Script: bd_detect_audit_v2.sh
# Purpose (V2 Dynamic Audit):
# Discover Black Duck / Synopsys Detect integration across:
# 1) Common CI pipeline files (Azure/GHA/Jenkins/Bamboo/Travis)
# 2) Local wrapper scripts & build files (ci/, scripts/, Makefile, etc.)
# Identify BOTH:
# - Direct integrations (Detect command is visible) => high confidence
# - Indirect integrations (templates/shared libs/container refs) => medium/low confidence
#
# Outputs:
# - Console summary
# - CSV report (default: bd_detect_audit_v2.csv)
#
# Usage:
# ./bd_detect_audit_v2.sh # audit current repo
# ./bd_detect_audit_v2.sh /repos # audit all git repos in folder
# ./bd_detect_audit_v2.sh . out.csv # custom CSV
#
# Notes:
# - Pipeline-safe: avoids failing on grep "no match" (exit code 1)
# ============================================================

# --- What this block does: read root path and output CSV path from args ---
ROOT="${1:-.}"
OUT_CSV="${2:-bd_detect_audit_v2.csv}"

# --- What this block does: enable ** recursive globs; avoid errors if globs don't match files ---
shopt -s globstar nullglob

# ------------------------------------------------------------
# What this block does:
# Define file patterns for CI pipelines across major systems
# ------------------------------------------------------------
PIPELINE_GLOBS=(
  "azure-pipelines.yml" "azure-pipelines.yaml"
  ".github/workflows/*.yml" ".github/workflows/*.yaml"
  "Jenkinsfile" "Jenkinsfile*"
  ".travis.yml"
  "bamboo-specs/**/*.yml" "bamboo-specs/**/*.yaml"
  "**/bamboo-specs.yml" "**/bamboo-specs.yaml"
)

# ------------------------------------------------------------
# What this block does:
# Define common wrapper/script/build file patterns where Detect is often hidden
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# What this block does:
# Define strong markers for "Direct Detect integration"
# ------------------------------------------------------------
DIRECT_DETECT_PATTERN='detect\.sh|synopsys[- ]?detect|hub-detect|blackduck\.hub\.detect|java[[:space:]]+-jar[[:space:]].*detect|--blackduck\.|--detect\.project\.name|--detect\.project\.version\.name'

# ------------------------------------------------------------
# What this block does:
# Define config markers to extract likely project/url/token naming from evidence
# ------------------------------------------------------------
URL_PATTERN='blackduck\.url|BLACKDUCK_URL|DETECT_BLACKDUCK_URL'
TOKEN_PATTERN='blackduck\.(api\.token|token)|BLACKDUCK_API_TOKEN|DETECT_BLACKDUCK_API_TOKEN|BLACKDUCK_TOKEN|DETECT_TOKEN'
PROJECT_PATTERN='detect\.project\.name|PROJECT_NAME|DETECT_PROJECT_NAME'
VERSION_PATTERN='detect\.project\.version\.name|PROJECT_VERSION|DETECT_PROJECT_VERSION'

# ------------------------------------------------------------
# What this block does:
# Define "Indirect integration" markers:
# - templates / includes / reusable workflows
# - Jenkins shared libraries
# - container based scan hints
# - generic security keywords
# ------------------------------------------------------------
INDIRECT_TEMPLATE_PATTERN='- template:|extends:|resources:|@templates|include:|uses:[[:space:]]*[^[:space:]]+\/[^[:space:]]+@|workflow_call|reusable workflow'
INDIRECT_JENKINS_LIB_PATTERN='@Library\(|library\(|sharedLibrary|vars\/|def[[:space:]]+securityScan|securityScan\(|blackduckScan\(|detectScan\('
INDIRECT_CONTAINER_PATTERN='docker[[:space:]]+run|container:|image:|services:|podman[[:space:]]+run'
INDIRECT_KEYWORDS_PATTERN='blackduck|synopsys|detect|polaris|coverity|sca|sast'

# --- What this block does: create the CSV header with extra fields for approach + confidence ---
echo "repo,artifact_type,file_path,ci_type,found_type,confidence,approach,invocation_style,blackduck_url_ref,token_ref,project_name_ref,project_version_ref,example_lines" > "$OUT_CSV"

# --- What this function does: identify CI type from file path/name (best-effort) ---
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

# --- What this function does: classify Detect invocation style (best-effort) ---
detect_invocation_style() {
  local f="$1"
  if grep -Eqi 'bash[[:space:]]*<\([[:space:]]*curl.*detect\.sh' "$f"; then
    echo "bash_process_substitution_curl_detect.sh"
  elif grep -Eqi 'curl.*detect\.sh.*\|[[:space:]]*bash' "$f"; then
    echo "curl_pipe_bash_detect.sh"
  elif grep -Eqi 'java[[:space:]]+-jar[[:space:]].*detect' "$f"; then
    echo "java_jar_detect"
  elif grep -Eqi 'synopsys[- ]?detect' "$f"; then
    echo "synopsys_detect_wrapper"
  elif grep -Eqi 'detect\.sh' "$f"; then
    echo "detect_sh_direct"
  else
    echo "unknown"
  fi
}

# --- What this function does: extract first matching line snippet for a given pattern (pipeline-safe) ---
extract_best_ref() {
  local f="$1"
  local pat="$2"
  local line
  line="$(grep -Ein "$pat" "$f" | head -1 || true)" # <- grep may return 1; do not fail
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  line="${line#*:}" # remove line number
  echo "$line" | sed -E 's/[[:space:]]+/ /g' | cut -c1-160
}

# --- What this function does: collect evidence lines for CSV/debugging (pipeline-safe) ---
example_lines() {
  local f="$1"
  local n=6

  # grep returns exit code 1 when no matches; with set -euo pipefail this would fail.
  # Wrap grep with "|| true" so the pipeline succeeds even when there is no evidence.
  (
    { grep -Ein "$DIRECT_DETECT_PATTERN|$URL_PATTERN|$TOKEN_PATTERN|$PROJECT_PATTERN|$VERSION_PATTERN|$INDIRECT_TEMPLATE_PATTERN|$INDIRECT_JENKINS_LIB_PATTERN|$INDIRECT_CONTAINER_PATTERN" "$f" || true; } \
      | head -n "$n" \
      | sed -E 's/"/""/g' \
      | tr '\n' ';' \
      | sed 's/;*$//'
  )
}

# ------------------------------------------------------------
# What this function does:
# Determine FOUND TYPE + CONFIDENCE + APPROACH based on file content.
# ------------------------------------------------------------
classify_found() {
  local f="$1"

  # Direct detection is highest confidence
  if grep -Eqi "$DIRECT_DETECT_PATTERN" "$f"; then
    echo "direct,high,detect_present"
    return
  fi

  # Template / reusable workflow references: medium confidence
  if grep -Eqi "$INDIRECT_TEMPLATE_PATTERN" "$f" && grep -Eqi "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,medium,template_or_reusable_workflow"
    return
  fi

  # Jenkins shared library references: medium confidence
  if grep -Eqi "$INDIRECT_JENKINS_LIB_PATTERN" "$f"; then
    echo "indirect,medium,jenkins_shared_library_or_wrapper"
    return
  fi

  # Container usage + security keywords: medium confidence
  if grep -Eqi "$INDIRECT_CONTAINER_PATTERN" "$f" && grep -Eqi "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,medium,container_based_scan"
    return
  fi

  # Only keywords, no strong evidence: low confidence
  if grep -Eqi "$INDIRECT_KEYWORDS_PATTERN" "$f"; then
    echo "indirect,low,keyword_only_possible_scan"
    return
  fi

  echo "none,none,none"
}

# --- What this function does: scan a list of files and append findings to CSV ---
scan_files_and_report() {
  local repo="$1"
  local repobase="$2"
  local artifact_type="$3"
  shift 3
  local files=("$@")

  for abs in "${files[@]}"; do
    [[ -f "$abs" ]] || continue
    local rel="${abs#$repo/}"

    # What this block does: classify evidence type and confidence
    local cls found_type confidence approach
    cls="$(classify_found "$abs")"
    found_type="${cls%%,*}"
    cls="${cls#*,}"
    confidence="${cls%%,*}"
    approach="${cls#*,}"

    # Skip no-signal files to reduce noise
    if [[ "$found_type" == "none" ]]; then
      continue
    fi

    # What this block does: infer CI type only for pipeline artifacts
    local ci="n/a"
    if [[ "$artifact_type" == "pipeline" ]]; then
      ci="$(ci_type_of "$rel")"
    fi

    # What this block does: detect invocation style only if direct evidence exists
    local style=""
    if [[ "$found_type" == "direct" ]]; then
      style="$(detect_invocation_style "$abs")"
    fi

    # What this block does: extract best-effort URL/token/project/version refs + evidence lines
    local urlref tokref projref verref ex
    urlref="$(extract_best_ref "$abs" "$URL_PATTERN")"
    tokref="$(extract_best_ref "$abs" "$TOKEN_PATTERN")"
    projref="$(extract_best_ref "$abs" "$PROJECT_PATTERN")"
    verref="$(extract_best_ref "$abs" "$VERSION_PATTERN")"
    ex="$(example_lines "$abs")"

    # What this block does: log to console for quick visibility
    echo "[${found_type^^}] ($confidence) $repobase :: $rel (artifact=$artifact_type, approach=$approach${style:+, style=$style})"

    # What this block does: append a structured record to CSV
    echo "\"$repobase\",\"$artifact_type\",\"$rel\",\"$ci\",\"$found_type\",\"$confidence\",\"$approach\",\"$style\",\"$urlref\",\"$tokref\",\"$projref\",\"$verref\",\"$ex\"" >> "$OUT_CSV"
  done
}

# --- What this function does: audit a single repo (pipelines + wrappers/scripts) ---
audit_repo() {
  local repo="$1"
  local repobase
  repobase="$(basename "$repo")"

  # Collect pipeline artifacts
  local pipeline_files=()
  for g in "${PIPELINE_GLOBS[@]}"; do
    for f in "$repo"/$g; do
      [[ -f "$f" ]] && pipeline_files+=("$f")
    done
  done
  mapfile -t pipeline_files < <(printf "%s\n" "${pipeline_files[@]}" | awk '!seen[$0]++')

  # Collect wrapper/script/build artifacts
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

  # Scan pipelines first (higher signal)
  if [[ ${#pipeline_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repobase" "pipeline" "${pipeline_files[@]}"
  else
    echo "[INFO] $repobase: no pipeline files found"
  fi

  # Scan wrappers/scripts next (to catch hidden integrations)
  if [[ ${#wrapper_files[@]} -gt 0 ]]; then
    scan_files_and_report "$repo" "$repobase" "wrapper_or_script" "${wrapper_files[@]}"
  else
    echo "[INFO] $repobase: no wrapper/script files found"
  fi
}

# --- What this block does: announce output destination ---
echo "Writing report to: $OUT_CSV"
echo

# --- What this block does: decide whether ROOT is one repo or a folder containing many repos ---
if [[ -d "$ROOT/.git" ]]; then
  audit_repo "$ROOT"
else
  for d in "$ROOT"/*; do
    [[ -d "$d/.git" ]] || continue
    audit_repo "$d"
  done
fi

# --- What this block does: print completion help text ---
echo
echo "Done. CSV: $OUT_CSV"
echo "How to read results:"
echo " - found_type=direct + confidence=high => Detect is directly invoked here (true execution point)"
echo " - found_type=indirect + confidence=medium => likely via templates/shared-lib/container"
echo " - found_type=indirect + confidence=low => only keywords; needs manual verification"
echo "Tip: Filter CSV on confidence=high first."
