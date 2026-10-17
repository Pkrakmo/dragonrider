#!/usr/bin/env bash
# Read-only loader probe of an already imported program. Never imports or changes analysis.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${GHIDRA_HOME:?Set GHIDRA_HOME to your Ghidra installation directory}"
ghidra_home=$GHIDRA_HOME
research_root=${DRAGONRIDER_RESEARCH_ROOT:-"$root/research"}
project_dir="$research_root/ghidra-projects"
project=Drakan_US_Retail
[[ -f "$project_dir/$project.gpr" ]] || { echo "Missing existing project: $project_dir/$project.gpr" >&2; exit 1; }
[[ -x "$ghidra_home/support/analyzeHeadless" ]] || { echo "Missing analyzeHeadless in $ghidra_home" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }
# Cooperative lock covers all instances of this wrapper; Ghidra also enforces its project lock.
exec 9>"$project_dir/.drakan-loader-probe.lock"
flock -n 9 || { echo "Another loader probe is running" >&2; exit 1; }
logdir="$research_root/ghidra-logs/loader-probe"
outdir="$research_root/exports/loader-probe"
mkdir -p "$logdir" "$outdir"
run=$(mktemp -d "$logdir/run-XXXXXXXX")
json="$outdir/$(basename "$run").json"
# Keep Ghidra preferences and caches local to this run, including in restricted environments.
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
echo "Ensure all GUI sessions for $project are closed before running." >&2
echo "Log: $run/ghidra.log" >&2
"$ghidra_home/support/analyzeHeadless" "$project_dir" "$project" \
  -process Drakan.exe -readOnly -noanalysis \
  -scriptPath "$root/tools/ghidra/scripts" \
  -postScript InvestigateFileLoader.java "$json" \
  -log "$run/ghidra.log" -scriptlog "$run/script.log"
[[ -s "$json" ]] || { echo "Probe did not produce JSON; inspect $run" >&2; exit 1; }
echo "Evidence: $json"
