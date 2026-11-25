# Docker capacity is shared by every tenantbleed job on this machine (planted suite, full runs,
# single-app scans, a benchmark in another session). Too many Supabase stacks at once wedged Docker,
# so jobs take slots: one per running stack. The number of slots follows the memory Docker has
# (about 1.5 GB a stack, at most 6); TENANTBLEED_DOCKER_SLOTS sets it. Each slot has its own port
# range, so two jobs never start a stack on the same ports. Sourced.
#
#   take_docker_slots <n|all> "<what>" [wait]   takes n slots (all: every slot, for the planted suite)
#                                               and sets TENANTBLEED_PORT_PREFIX (the first slot's)
#   release_docker_slots                        gives them back (also done when the script exits)
#   take_docker_lock "<what>"                   the older call: one slot, refused when none is free
#
# A slot is a folder in $DOCKER_SLOT_DIR (mkdir is atomic); a slot whose process is gone is taken
# over. A live DOCKER.lock from a job started before slots existed holds every slot.
DOCKER_LAB=${TENANTBLEED_LAB:-$HOME/Projects/tenantbleed-lab}
DOCKER_SLOT_DIR=$DOCKER_LAB/DOCKER.slots
DOCKER_LOCK=$DOCKER_LAB/DOCKER.lock
# Port prefixes per slot (ports <prefix>20 to <prefix>29). Not used elsewhere: the planted apps use
# 533, 563, 573, 583, 593, the CLI default is 543, older lab scripts 553 and 613.
DOCKER_SLOT_PREFIXES="603 623 633 643 653 523"
DOCKER_SLOTS_HELD=""

docker_slot_count() {
  if [ -n "${TENANTBLEED_DOCKER_SLOTS:-}" ]; then echo "$TENANTBLEED_DOCKER_SLOTS"; return; fi
  local bytes
  bytes=$(perl -e 'alarm 10; exec @ARGV' docker info --format '{{.MemTotal}}' 2> /dev/null)
  [ -n "$bytes" ] || { echo 1; return; }
  awk -v b="$bytes" 'BEGIN { n = int(b / 1073741824 / 1.5); if (n < 1) n = 1; if (n > 6) n = 6; print n }'
}

_slot_alive() { # <slot number>: held by a live process?
  local pid age
  pid=$(head -1 "$DOCKER_SLOT_DIR/$1/owner" 2> /dev/null)
  if [ -z "$pid" ]; then
    # Just made, owner not written yet: taken, unless it has been like that for a while.
    [ -d "$DOCKER_SLOT_DIR/$1" ] || return 1
    age=$(($(date +%s) - $(stat -f %m "$DOCKER_SLOT_DIR/$1" 2> /dev/null || echo 0)))
    [ "$age" -lt 30 ]
    return
  fi
  kill -0 "$pid" 2> /dev/null
}

# A DOCKER.lock written by the slot code (third line "slots") only tells older scripts, which know
# no slots, that Docker is in use; only one written by an older script holds every slot.
_legacy_lock_alive() {
  [ -f "$DOCKER_LOCK" ] || return 1
  [ "$(sed -n 3p "$DOCKER_LOCK")" = slots ] && return 1
  local pid
  pid=$(head -1 "$DOCKER_LOCK")
  [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null
}

# Keep DOCKER.lock naming a live slot holder while any slot is taken, and remove it when none is.
_sync_legacy_lock() {
  _legacy_lock_alive && return
  local i
  for i in $(seq 1 6); do
    if [ -f "$DOCKER_SLOT_DIR/$i/owner" ] && _slot_alive "$i"; then
      printf '%s\n%s\nslots\n' "$(head -1 "$DOCKER_SLOT_DIR/$i/owner")" "$(sed -n 2p "$DOCKER_SLOT_DIR/$i/owner" 2> /dev/null) (Docker slots in use)" > "$DOCKER_LOCK"
      return
    fi
  done
  [ "$(sed -n 3p "$DOCKER_LOCK" 2> /dev/null)" = slots ] && rm -f "$DOCKER_LOCK"
}

# A job waiting for every slot (the planted suite) puts up a drain marker: nobody else takes a slot
# until it has them, so it is not starved by workers that hand slots back and take them again.
_drain_by_other() {
  local pid
  pid=$(head -1 "$DOCKER_SLOT_DIR/drain" 2> /dev/null)
  [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -0 "$pid" 2> /dev/null
}

_try_slots() { # <n> <what>: all n or none
  local want=$1 total got="" i
  total=$(docker_slot_count)
  [ "$want" = all ] && want=$total
  [ "$want" -gt "$total" ] && want=$total
  _legacy_lock_alive && return 1
  _drain_by_other && return 1
  mkdir -p "$DOCKER_SLOT_DIR"
  for i in $(seq 1 "$total"); do
    [ "$(echo "$got" | wc -w)" -ge "$want" ] && break
    if ! mkdir "$DOCKER_SLOT_DIR/$i" 2> /dev/null; then
      _slot_alive "$i" && continue
      # Left by a process that is gone: take it over.
      rm -rf "${DOCKER_SLOT_DIR:?}/$i"
      mkdir "$DOCKER_SLOT_DIR/$i" 2> /dev/null || continue
    fi
    printf '%s\n%s since %s\n' "$$" "$2" "$(date '+%Y-%m-%d %H:%M')" > "$DOCKER_SLOT_DIR/$i/owner"
    got="$got $i"
  done
  if [ "$(echo "$got" | wc -w)" -lt "$want" ]; then
    for i in $got; do rm -rf "${DOCKER_SLOT_DIR:?}/$i"; done
    return 1
  fi
  DOCKER_SLOTS_HELD="$DOCKER_SLOTS_HELD$got"
  local first
  first=$(echo "$got" | awk '{print $1}')
  TENANTBLEED_PORT_PREFIX=$(echo "$DOCKER_SLOT_PREFIXES" | awk -v i="$first" '{print $i}')
  export TENANTBLEED_PORT_PREFIX
  return 0
}

docker_slots_status() {
  local i
  _legacy_lock_alive && echo "older lock: $(sed -n 2p "$DOCKER_LOCK")"
  for i in $(seq 1 "$(docker_slot_count)"); do
    if _slot_alive "$i"; then echo "slot $i: $(sed -n 2p "$DOCKER_SLOT_DIR/$i/owner" 2> /dev/null)"; else echo "slot $i: free"; fi
  done
}

take_docker_slots() { # <n|all> <what> [wait]
  [ -d "$DOCKER_LAB" ] || return 0   # no lab on this machine: nothing to share
  local said=""
  until _try_slots "$1" "$2"; do
    if [ "${3:-}" != wait ]; then
      echo "Docker is in use by other tenantbleed jobs (no free slot):"
      docker_slots_status | sed 's/^/  /'
      exit 1
    fi
    [ -n "$said" ] || { echo "waiting for $1 Docker slot(s) for: $2" >&2; said=1; }
    if [ "$1" = all ] && ! _drain_by_other; then
      mkdir -p "$DOCKER_SLOT_DIR" && printf '%s\n%s\n' "$$" "$2" > "$DOCKER_SLOT_DIR/drain"
      trap 'rm -f "$DOCKER_SLOT_DIR/drain"; release_docker_slots' EXIT
    fi
    sleep 5
  done
  [ "$(head -1 "$DOCKER_SLOT_DIR/drain" 2> /dev/null)" = "$$" ] && rm -f "$DOCKER_SLOT_DIR/drain"
  _sync_legacy_lock
  trap release_docker_slots EXIT
}

release_docker_slots() {
  local i
  for i in $DOCKER_SLOTS_HELD; do rm -rf "${DOCKER_SLOT_DIR:?}/$i"; done
  DOCKER_SLOTS_HELD=""
  _sync_legacy_lock
}

take_docker_lock() { take_docker_slots 1 "$1"; }
