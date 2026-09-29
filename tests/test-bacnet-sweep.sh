#!/usr/bin/env bash
# Prove bacnet-sweep.py against the loopback fake device. No real network traffic.
#
#     tests/test-bacnet-sweep.sh [--keep]
#
# Starts tests/bacnet-fake-device.py on a free loopback port, runs discover /
# read / points against it, and asserts on the decoded output: device instance,
# point names, values, engineering units, the decoded Error/Reject/Abort text,
# and the exit codes. Every packet stays on 127.0.0.1.
#
# Exits 0 only if every assertion passed. Kills only the fixture PIDs it started.
# Whole run is a few seconds; nothing here waits on a real timeout longer than 2s.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
TOOL="$HERE/../bacnet-sweep.py"
FIXTURE="$HERE/bacnet-fake-device.py"
PY=${PY:-python3}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/bacnet-sweep-test.XXXXXX")
PASS=0
FAIL=0
PIDS=""

cleanup() {
    for p in $PIDS; do
        kill "$p" 2>/dev/null || true
    done
    if [ "$KEEP" = "1" ]; then
        echo "output kept in $OUTDIR"
    else
        rm -rf "$OUTDIR"
    fi
}
trap cleanup EXIT

say()  { printf '\n===== %s =====\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$*"; }

# grep -F: the expected strings include accented text and punctuation, not regexes.
want() {           # want <label> <file> <fixed-string>
    if grep -qF -- "$3" "$2"; then ok "$1"; else
        bad "$1 -- expected to find: $3"
        sed -n '1,25p' "$2" | sed 's/^/        | /'
    fi
}
want_not() {       # want_not <label> <file> <fixed-string>
    if grep -qF -- "$3" "$2"; then bad "$1 -- should NOT contain: $3"; else ok "$1"; fi
}
want_exit() {      # want_exit <label> <actual> <expected>
    if [ "$2" = "$3" ]; then ok "$1 (exit $2)"; else bad "$1 -- exit $2, expected $3"; fi
}
want_eq() {        # want_eq <label> <actual> <expected>
    if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 -- got '$2', expected '$3'"; fi
}

free_port() {
    "$PY" - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

start_fixture() {  # start_fixture <port> <logfile> [extra args...]
    port=$1; log=$2; shift 2
    "$PY" "$FIXTURE" --bind 127.0.0.1 --port "$port" "$@" >"$log" 2>&1 &
    pid=$!
    PIDS="$PIDS $pid"
    n=0
    while [ $n -lt 100 ]; do
        if grep -q "fixture listening" "$log" 2>/dev/null; then return 0; fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "fixture died at startup:"; cat "$log"; return 1
        fi
        "$PY" -c 'import time; time.sleep(0.05)'
        n=$((n + 1))
    done
    echo "fixture never became ready:"; cat "$log"
    return 1
}

for f in "$TOOL" "$FIXTURE"; do
    [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
[ -x "$TOOL" ] || bad "bacnet-sweep.py is not executable"
[ -x "$TOOL" ] && ok "bacnet-sweep.py has the executable bit"

PORT=$(free_port)
LPORT=$(free_port)
PORT2=$(free_port)
LPORT2=$(free_port)
DEAD=$(free_port)
COMMON="--bind 127.0.0.1 --port $PORT --local-port $LPORT --timeout 1 --delay 0.02"

echo "fake device on 127.0.0.1:$PORT, sweep sending from 127.0.0.1:$LPORT"
echo "transcript directory: $OUTDIR"

start_fixture "$PORT" "$OUTDIR/fixture.log" || exit 1
sed 's/^/  /' "$OUTDIR/fixture.log"

# --------------------------------------------------------------------- 0. help
say "help promises read-only"
"$PY" "$TOOL" --help >"$OUTDIR/help.txt" 2>&1
want_exit "--help exits 0" $? 0
want "--help says read-only"        "$OUTDIR/help.txt" "read-only"
want "--help names WriteProperty"   "$OUTDIR/help.txt" "no WriteProperty"
want "--help names ReinitializeDevice" "$OUTDIR/help.txt" "no ReinitializeDevice"
want "--help names DeviceCommunicationControl" "$OUTDIR/help.txt" "no DeviceCommunicationControl"
want "--help names COV"             "$OUTDIR/help.txt" "no COV subscription"
want "--help lists the limits"      "$OUTDIR/help.txt" "no BBMD"

say "read-only is enforced in code, not only in the docs"
"$PY" - "$TOOL" >"$OUTDIR/readonly.txt" 2>&1 <<'EOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("bs", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
assert m.ALLOWED_CONFIRMED_SERVICES == (12,), m.ALLOWED_CONFIRMED_SERVICES
# 15 writeProperty, 16 writePropertyMultiple, 17 deviceCommunicationControl,
# 20 reinitializeDevice, 5 subscribeCOV, 7 atomicWriteFile, 6 timeSynchronization
for svc in (15, 16, 17, 20, 5, 7, 6, 0, 99):
    try:
        m._assert_read_only(svc)
    except m.Fatal:
        continue
    print("ACCEPTED service %d -- read-only gate is broken" % svc)
    sys.exit(1)
m._assert_read_only(12)
print("gate ok: only ReadProperty(12) accepted, 9 write/other services refused")
EOF
want_exit "write services refused by _assert_read_only" $? 0
want "gate reports ok" "$OUTDIR/readonly.txt" "only ReadProperty(12) accepted"

# ----------------------------------------------------------------- 1. discover
say "discover"
"$PY" "$TOOL" discover $COMMON --broadcast 127.0.0.1 >"$OUTDIR/discover.txt" 2>&1
want_exit "discover exits 0" $? 0
cat "$OUTDIR/discover.txt"
want "discover finds device 260001"   "$OUTDIR/discover.txt" "260001"
want "discover shows the address"     "$OUTDIR/discover.txt" "127.0.0.1:$PORT"
want "discover decodes vendor id"     "$OUTDIR/discover.txt" "999"
want "discover decodes max APDU"      "$OUTDIR/discover.txt" "1476"
want "discover decodes segmentation"  "$OUTDIR/discover.txt" "no-segmentation"
want "discover reads object-name"     "$OUTDIR/discover.txt" "PL-Fixture-AHU1"
want "discover reads model-name"      "$OUTDIR/discover.txt" "FX-STUB-1"
want "discover counts the device"     "$OUTDIR/discover.txt" "1 device(s) answered"

say "discover --json"
"$PY" "$TOOL" discover $COMMON --broadcast 127.0.0.1 --json >"$OUTDIR/discover.json" 2>/dev/null
want_exit "discover --json exits 0" $? 0
"$PY" - "$OUTDIR/discover.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
dev = d["devices"][0]
assert dev["device"] == 260001, dev
assert dev["vendor"] == 999, dev
assert dev["max_apdu"] == 1476, dev
assert dev["segmentation"] == 3, dev
assert dev["object_name"] == "PL-Fixture-AHU1", dev
assert dev["routed"] is False, dev
print("json discover fields ok")
EOF
want_exit "discover --json carries the I-Am fields" $? 0

say "discover with a Who-Is range the device is outside"
"$PY" "$TOOL" discover $COMMON --broadcast 127.0.0.1 --low 1 --high 99 \
    >"$OUTDIR/discover-range.txt" 2>&1
want_exit "out-of-range Who-Is finds nothing" $? 3
want "out-of-range Who-Is explains itself" "$OUTDIR/discover-range.txt" "Nothing answered"

say "discover against a port with nothing on it"
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$DEAD" \
    --local-port "$LPORT" --timeout 0.5 >"$OUTDIR/silent.txt" 2>&1
want_exit "silent sweep exits 3" $? 3
cat "$OUTDIR/silent.txt"
want "silent sweep blames the subnet first" "$OUTDIR/silent.txt" "wrong subnet"
want "silent sweep mentions MS/TP"          "$OUTDIR/silent.txt" "MS/TP behind a BACnet router"
want "silent sweep mentions BBMD"           "$OUTDIR/silent.txt" "BBMD"
want "silent sweep refuses to claim empty"  "$OUTDIR/silent.txt" "not proof the network is empty"

# --------------------------------------------------------------------- 2. read
say "read: one property at a time"
rd() {             # rd <label> <object> <property> <expected-exit> <expected-text> [flags]
    label=$1; obj=$2; prop=$3; xc=$4; expect=$5; shift 5
    f="$OUTDIR/read-$(printf '%s' "$label" | tr -c 'a-zA-Z0-9' '-').txt"
    "$PY" "$TOOL" read 127.0.0.1 "$obj" "$prop" $COMMON "$@" >"$f" 2>&1
    got=$?
    printf '$ bacnet-sweep.py read 127.0.0.1 %s %s %s\n' "$obj" "$prop" "$*"
    sed 's/^/  /' "$f"
    want_exit "read $label exit" "$got" "$xc"
    want "read $label value" "$f" "$expect"
}

rd "real present-value"   analog-input:1        present-value  0 "18.6"
rd "char string name"     analog-input:1        object-name    0 "AHU1_SaTemp"
rd "units degC"           analog-input:1        units          0 "degrees-celsius"
rd "units degF"           analog-input:4        units          0 "degrees-fahrenheit"
rd "units pascals"        analog-input:2        units          0 "pascals"
rd "units kilopascals"    analog-value:3        units          0 "kilopascals"
rd "units percent"        analog-value:1        units          0 "percent"
rd "units kilowatts"      analog-value:4        units          0 "kilowatts"
rd "units kilowatt-hours" 46:1                  units          0 "kilowatt-hours"
rd "units litres per sec" analog-value:2        units          0 "liters-per-second"
rd "units ppm"            analog-input:3        units          0 "parts-per-million"
rd "units no-units"       analog-value:5        units          0 "no-units"
rd "latin-1 description"  ai:2                  description    0 "Pression différentielle"
rd "utf-8 description"    analog-input:1        description    0 "Supply air temperature"
rd "binary enumerated pv" bv:1                  present-value  0 "active"
rd "multistate pv"        msv:1                 present-value  0 "2"
rd "signed pv"            45:1                  present-value  0 "-17"
rd "double pv"            46:1                  present-value  0 "1234567.89"
rd "octet string pv"      47:1                  present-value  0 "0102deadbeef"
rd "boolean"              av:1                  out-of-service 0 "false"
rd "bit string clear"     analog-input:1        status-flags   0 "(none set)"
rd "bit string in-alarm"  analog-input:3        status-flags   0 "in-alarm"
rd "bit string overridden" bv:1                 status-flags   0 "overridden"
rd "date"                 device:260001         local-date     0 "2026-09-27 (Sun)"
rd "time"                 device:260001         local-time     0 "14:35:12.00"
rd "enumerated table"     device:260001         system-status  0 "operational"
rd "object identifier"    device:260001         object-identifier 0 "device:260001"
rd "object-list"          device:260001         object-list    0 "analog-input:1, analog-input:2"
rd "object-list length"   device:260001         object-list    0 "(18 elements)"
rd "trend-log in list"    device:260001         object-list    0 "trend-log:1"
rd "schedule in list"     device:260001         object-list    0 "schedule:1"
rd "notification class"   device:260001         object-list    0 "notification-class:1"
rd "array element count"  device:260001         object-list    0 "18" --index 0
rd "array element 5"      device:260001         object-list    0 "analog-input:4" --index 5
rd "priority array nulls" av:1                  priority-array 0 "null, null, null, null, null, null, null, 62.5"

say "read: the failure PDUs, decoded into words"
rd "error unknown-property" bv:1                units          4 "Error: property / unknown-property"
rd "error unknown-object"   analog-input:99     present-value  4 "Error: object / unknown-object"
rd "error invalid index"    device:260001       object-list    4 "invalid-array-index" --index 99
rd "reject"                 analog-input:1      1000           4 "Reject: parameter-out-of-range"
rd "abort segmentation"     trend-log:1         log-buffer     4 "Abort: segmentation-not-supported"
want "abort suggests --index" "$OUTDIR/read-abort-segmentation.txt" "element by element with --index"

say "read: nothing there"
"$PY" "$TOOL" read 127.0.0.1 analog-input:1 present-value --bind 127.0.0.1 \
    --port "$DEAD" --local-port "$LPORT" --timeout 0.5 >"$OUTDIR/read-timeout.txt" 2>&1
want_exit "timed-out read exits 4" $? 4
want "timed-out read says so" "$OUTDIR/read-timeout.txt" "no reply in 0.5s"

say "read: bad arguments are refused before any packet is sent"
"$PY" "$TOOL" read 127.0.0.1 frobnicator:1 present-value $COMMON >"$OUTDIR/badobj.txt" 2>&1
want_exit "unknown object type exits 2" $? 2
want "unknown object type explains" "$OUTDIR/badobj.txt" "unknown object type"
"$PY" "$TOOL" read 127.0.0.1 analog-input:1 wibble $COMMON >"$OUTDIR/badprop.txt" 2>&1
want_exit "unknown property exits 2" $? 2
want "unknown property explains" "$OUTDIR/badprop.txt" "unknown property"

# ------------------------------------------------------------------- 3. points
say "points"
"$PY" "$TOOL" points 127.0.0.1 260001 $COMMON >"$OUTDIR/points.txt" 2>"$OUTDIR/points.err"
want_exit "points exits 0" $? 0
cat "$OUTDIR/points.txt"
want "points has the device object"   "$OUTDIR/points.txt" "device:260001         PL-Fixture-AHU1"
want "points row: SaTemp"             "$OUTDIR/points.txt" "AHU1_SaTemp"
want "points row: temperature value"  "$OUTDIR/points.txt" "18.6           degrees-celsius"
want "points row: pascals"            "$OUTDIR/points.txt" "245            pascals"
want "points row: ppm"                "$OUTDIR/points.txt" "612            parts-per-million"
want "points row: percent"            "$OUTDIR/points.txt" "62.5           percent"
want "points row: l/s"                "$OUTDIR/points.txt" "1.85           liters-per-second"
want "points row: kPa"                "$OUTDIR/points.txt" "34.2           kilopascals"
want "points row: kW"                 "$OUTDIR/points.txt" "2.4            kilowatts"
want "points row: no-units"           "$OUTDIR/points.txt" "0.62           no-units"
want "points row: degF"               "$OUTDIR/points.txt" "65.3           degrees-fahrenheit"
want "points row: binary"             "$OUTDIR/points.txt" "AHU1_FanRun          active"
want "points row: multistate"         "$OUTDIR/points.txt" "AHU1_OccMode"
want "points row: signed"             "$OUTDIR/points.txt" "-17            seconds"
want "points row: double"             "$OUTDIR/points.txt" "1234567.89     kilowatt-hours"
want "points row: octet string"       "$OUTDIR/points.txt" "0102deadbeef"
want "points row: trend log"          "$OUTDIR/points.txt" "AHU1_SaTemp_Log"
want "points notes the error PDU"     "$OUTDIR/points.txt" "units: Error: property / unknown-property"
want "points explains the notes"      "$OUTDIR/points.txt" "the device's own answer, not a failure of the sweep"
want "points says values are not a synchronised sample" "$OUTDIR/points.txt" "not a synchronised sample"
want "points counts 18 objects"       "$OUTDIR/points.txt" "18 object(s) on device:260001"

say "points --csv"
"$PY" "$TOOL" points 127.0.0.1 260001 $COMMON --csv >"$OUTDIR/points.csv" 2>/dev/null
want_exit "points --csv exits 0" $? 0
cat "$OUTDIR/points.csv"
want_eq "csv has a header and 18 rows" "$(wc -l <"$OUTDIR/points.csv" | tr -d ' ')" 19
want "csv header"  "$OUTDIR/points.csv" "device,object,instance,object-name,present-value,units,note"
want "csv AI1 row" "$OUTDIR/points.csv" "260001,analog-input:1,1,AHU1_SaTemp,18.6,degrees-celsius,"
want "csv BV1 row" "$OUTDIR/points.csv" "260001,binary-value:1,1,AHU1_FanRun,active,(binary),"
"$PY" - "$OUTDIR/points.csv" <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
assert len(rows) == 18, len(rows)
by = dict((r["object"], r) for r in rows)
assert by["analog-value:2"]["units"] == "liters-per-second", by["analog-value:2"]
assert by["multi-state-value:1"]["note"].startswith("units: Error"), by["multi-state-value:1"]
print("csv parses as csv, 18 rows, fields in the right columns")
EOF
want_exit "csv is well-formed CSV" $? 0

say "points --json"
"$PY" "$TOOL" points 127.0.0.1 260001 $COMMON --json >"$OUTDIR/points.json" 2>/dev/null
want_exit "points --json exits 0" $? 0
"$PY" - "$OUTDIR/points.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
pts = d["points"]
assert len(pts) == 18, len(pts)
ai1 = [p for p in pts if p["object"] == "analog-input:1"][0]
assert ai1["name"] == "AHU1_SaTemp", ai1
assert ai1["units"] == "degrees-celsius" and ai1["units_raw"] == 62, ai1
print("json points ok: 18 points, raw unit enumeration preserved alongside the text")
EOF
want_exit "points --json keeps the raw enumeration" $? 0

say "points --csv together with --json"
# The usage line has always read "[--csv | --json]". Both together used to print
# JSON and say nothing, so a script that asked for CSV got JSON and could not
# tell. It is refused before any packet goes out, which is why this case needs
# no fixture and no port.
"$PY" "$TOOL" points 127.0.0.1 260001 $COMMON --csv --json \
    >"$OUTDIR/points-bothfmt.txt" 2>"$OUTDIR/points-bothfmt.err"
want_exit "--csv with --json exits 2" $? 2
want "it says which two" "$OUTDIR/points-bothfmt.err" "choose one of --csv and --json"
want_eq "nothing is written to stdout" \
    "$(wc -c <"$OUTDIR/points-bothfmt.txt" | tr -d ' ')" 0
want_not "no JSON leaked out with the error" "$OUTDIR/points-bothfmt.err" '"points":'

say "points --limit"
"$PY" "$TOOL" points 127.0.0.1 260001 $COMMON --limit 3 --csv >"$OUTDIR/points-limit.csv" 2>/dev/null
want_exit "points --limit exits 0" $? 0
want_eq "points --limit 3 gives 3 rows" \
    "$(($(wc -l <"$OUTDIR/points-limit.csv" | tr -d ' ') - 1))" 3

say "points against a device instance that is not there"
"$PY" "$TOOL" points 127.0.0.1 999999 $COMMON >"$OUTDIR/points-wrong.txt" 2>&1
want_exit "wrong device instance exits 5" $? 5
want "wrong device instance is explained" "$OUTDIR/points-wrong.txt" "unknown-object"

# ------------------------------------------- 4. the segmented-object-list path
say "points when the whole object-list will not fit one APDU"
start_fixture "$PORT2" "$OUTDIR/fixture2.log" --refuse-whole-object-list || exit 1
"$PY" "$TOOL" points 127.0.0.1 260001 --bind 127.0.0.1 --port "$PORT2" \
    --local-port "$LPORT2" --timeout 1 --delay 0.02 \
    >"$OUTDIR/points-indexed.txt" 2>"$OUTDIR/points-indexed.err"
want_exit "indexed points exits 0" $? 0
sed 's/^/  /' "$OUTDIR/points-indexed.err"
want "the slow path announces itself" "$OUTDIR/points-indexed.err" "element by element with --index"
want "the element count was read"     "$OUTDIR/points-indexed.err" "object-list has 18 elements"
want "indexed points counts 18"       "$OUTDIR/points-indexed.txt" "18 object(s) on device:260001"
want "indexed points still decodes"   "$OUTDIR/points-indexed.txt" "18.6           degrees-celsius"
norm() { sed 's/  */ /g; /properties were read one at a time/d' "$1"; }
if diff -q <(norm "$OUTDIR/points.txt") <(norm "$OUTDIR/points-indexed.txt") >/dev/null; then
    ok "indexed object-list produces the same table as the whole-list read"
else
    bad "indexed object-list table differs from the whole-list table"
    diff <(norm "$OUTDIR/points.txt") <(norm "$OUTDIR/points-indexed.txt") \
        | sed 's/^/        | /'
fi

# --------------------------------------------------- 5. it must not traceback
say "malformed replies and random bytes never produce a traceback"
GARBAGE_PORT=$(free_port)
"$PY" - "$GARBAGE_PORT" >"$OUTDIR/garbage.log" 2>&1 <<'EOF' &
import random, socket, sys
random.seed(20260927)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
print("garbage listening", flush=True)
canned = [
    b"",                                            # empty datagram
    b"\x81",                                        # one octet
    b"\x81\x0a\xff\xff\x01\x00",                    # BVLC length lies
    b"\x81\x0a\x00\x0b\x01\x00\x30\x01\x0c\x0c",    # ACK, objid tag with no data
    b"\x81\x0a\x00\x09\x01\x00\x30\x01\x0c",        # ACK that stops at the service
    b"\x81\x0a\x00\x10\x01\x00\x30\x01\x0c\x0c\x00\x00\x00\x01\x19\x55",  # no tag 3
    b"\x81\x0a\x00\x0c\x01\x00\x50\x01\x0c\x91",    # Error PDU, one truncated enum
    b"\x81\x0a\x00\x08\x01\x80\x00\x01",            # network-layer message
]
n = 0
while True:
    try:
        data, addr = s.recvfrom(1500)
    except OSError:
        break
    if n < len(canned):
        reply = canned[n]
    else:
        reply = bytes(random.randrange(256) for _ in range(random.randrange(1, 60)))
    s.sendto(reply, addr)
    n += 1
EOF
GPID=$!
PIDS="$PIDS $GPID"
n=0
while [ $n -lt 60 ]; do
    grep -q "garbage listening" "$OUTDIR/garbage.log" 2>/dev/null && break
    "$PY" -c 'import time; time.sleep(0.05)'; n=$((n + 1))
done
: >"$OUTDIR/garbage-out.txt"
i=0
while [ $i -lt 12 ]; do
    "$PY" "$TOOL" read 127.0.0.1 analog-input:1 present-value --bind 127.0.0.1 \
        --port "$GARBAGE_PORT" --local-port "$LPORT" --timeout 0.3 \
        >>"$OUTDIR/garbage-out.txt" 2>&1
    i=$((i + 1))
done
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$GARBAGE_PORT" \
    --local-port "$LPORT" --timeout 0.5 >>"$OUTDIR/garbage-out.txt" 2>&1
want_not "no traceback from junk replies" "$OUTDIR/garbage-out.txt" "Traceback"
want "junk replies are reported as undecodable" "$OUTDIR/garbage-out.txt" "undecodable"

say "fuzzing the decoders directly"
"$PY" - "$TOOL" >"$OUTDIR/fuzz.txt" 2>&1 <<'EOF'
import importlib.util, random, sys
spec = importlib.util.spec_from_file_location("bs", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
random.seed(1)
tolerated = (m.BacnetDecodeError,)
frames = apdus = acks = 0
for _ in range(20000):
    n = random.randrange(0, 64)
    b = bytes(random.randrange(256) for _ in range(n))
    try:
        m.parse_frame(b); frames += 1
    except tolerated:
        pass
    m.decode_apdu(b); apdus += 1
    r = m.decode_read_property_ack(b, 0, 85); acks += 1
    assert r["status"] in ("ok", "malformed"), r
    m.decode_error_body(b)
    m.decode_i_am(b)
print("20000 random inputs: %d frames parsed or rejected cleanly, %d APDUs "
      "classified, %d ACKs decoded, no unexpected exception" % (frames, apdus, acks))
EOF
want_exit "20k random inputs raise nothing unexpected" $? 0
cat "$OUTDIR/fuzz.txt"

# ---------------------------------------------------------- 6. port already in use
say "the BACnet port already being in use"
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$PORT" \
    --timeout 1 >"$OUTDIR/inuse.txt" 2>&1
want_exit "port in use exits 2" $? 2
cat "$OUTDIR/inuse.txt"
want "port in use is named"        "$OUTDIR/inuse.txt" "already in use"
want "port in use suggests a fix"  "$OUTDIR/inuse.txt" "--local-port"

# ------------------------------------------------------ 7. the fixture's own view
say "what the fixture saw"
kill $PIDS 2>/dev/null
sed 's/^/  /' "$OUTDIR/fixture.log"

# ------------------------------- 7.5 routed, BBMD-forwarded, and segmented-at
# These three exercise code paths that were previously untested, which is to say
# claimed but unproven. Each needs the fixture to behave like a different piece
# of infrastructure. Still all on loopback.

say "an I-Am that arrives routed, with SNET and SADR"
RPORT=$(free_port); RLPORT=$(free_port)
start_fixture "$RPORT" "$OUTDIR/fixture-routed.log" --verbose \
    --routed-from 2001:07 || exit 1
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$RPORT" \
    --local-port "$RLPORT" --timeout 1 --verbose \
    >"$OUTDIR/discover-routed.txt" 2>&1
want_exit "routed discover exits 0" $? 0
sed 's/^/  /' "$OUTDIR/discover-routed.txt"
want "the routed device is listed"   "$OUTDIR/discover-routed.txt" "260001"
want "the network number is decoded" "$OUTDIR/discover-routed.txt" "routed via network 2001"
want "the MS/TP address is decoded"  "$OUTDIR/discover-routed.txt" "addr 07"
want "routing is called unreadable"  "$OUTDIR/discover-routed.txt" "not readable by this tool"
# A routed device must not be read: the tool has no network layer, so the read
# would go to the router's own IP and answer about the wrong device.
want_not "no name was read from a routed device" "$OUTDIR/discover-routed.txt" \
    "PL-Fixture-AHU1"

say "an I-Am forwarded by a BBMD, whose origin is not the sender"
BPORT=$(free_port)      # the 'BBMD' that forwards
DPORT=$(free_port)      # the device itself, on another loopback address
BLPORT=$(free_port)
"$PY" "$FIXTURE" --bind 127.0.0.2 --port "$DPORT" \
    >"$OUTDIR/fixture-dev2.log" 2>&1 &
PIDS="$PIDS $!"
n=0
while [ $n -lt 100 ]; do
    grep -q "fixture listening" "$OUTDIR/fixture-dev2.log" 2>/dev/null && break
    "$PY" -c 'import time; time.sleep(0.05)'; n=$((n + 1))
done
want "a second device answers on 127.0.0.2" "$OUTDIR/fixture-dev2.log" "127.0.0.2"
start_fixture "$BPORT" "$OUTDIR/fixture-bbmd.log" --verbose \
    --forwarded-from "127.0.0.2:$DPORT" || exit 1
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$BPORT" \
    --local-port "$BLPORT" --timeout 1 --verbose \
    >"$OUTDIR/discover-forwarded.txt" 2>&1
want_exit "forwarded discover exits 0" $? 0
sed 's/^/  /' "$OUTDIR/discover-forwarded.txt"
want "the BVLC Forwarded-NPDU was accepted" "$OUTDIR/discover-forwarded.txt" "8104"
# The whole point: the device is reported at the origin address inside the
# forwarded frame, not at the address the frame came from.
want "the device is at the origin address" "$OUTDIR/discover-forwarded.txt" \
    "127.0.0.2:$DPORT"
want "follow-up reads went to the origin"  "$OUTDIR/discover-forwarded.txt" \
    "--> 127.0.0.2:$DPORT"
want "and the name came back"              "$OUTDIR/discover-forwarded.txt" \
    "PL-Fixture-AHU1"

say "a device that was never given an instance number"
UPORT=$(free_port)
start_fixture "$UPORT" "$OUTDIR/fixture-unconf.log" --device 4194303 || exit 1
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$UPORT" \
    --local-port "$(free_port)" --timeout 1 >"$OUTDIR/discover-unconf.txt" 2>&1
want_exit "unconfigured-instance discover exits 0" $? 0
sed 's/^/  /' "$OUTDIR/discover-unconf.txt"
want "the reserved instance is listed"  "$OUTDIR/discover-unconf.txt" "4194303"
want "and explained, not just printed"  "$OUTDIR/discover-unconf.txt" \
    "means 'unconfigured'"

say "two devices claiming the same device instance"
TPORT=$(free_port); TWPORT=$(free_port); TLPORT=$(free_port)
start_fixture "$TPORT" "$OUTDIR/fixture-twin.log" --verbose \
    --twin "127.0.0.2:$TWPORT" || exit 1
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$TPORT" \
    --local-port "$TLPORT" --timeout 1 >"$OUTDIR/discover-dup.txt" 2>&1
want_exit "duplicate-instance discover exits 0" $? 0
sed 's/^/  /' "$OUTDIR/discover-dup.txt"
want "both claimants are listed"   "$OUTDIR/discover-dup.txt" "127.0.0.1:$TPORT"
want "the twin is listed too"      "$OUTDIR/discover-dup.txt" "127.0.0.2:$TWPORT"
want "the clash is called out"     "$OUTDIR/discover-dup.txt" "DUPLICATE device instance"
want "two devices are counted"     "$OUTDIR/discover-dup.txt" "2 device(s) answered"
want "the summary names the instance" "$OUTDIR/discover-dup.txt" \
    "claimed from more than one address: 260001"
want "the clash is blamed on the site, not the tool" "$OUTDIR/discover-dup.txt" \
    "That is a site fault"
want_eq "the instance appears on two rows" \
    "$(grep -c '^260001' "$OUTDIR/discover-dup.txt")" "2"
"$PY" "$TOOL" discover --bind 127.0.0.1 --broadcast 127.0.0.1 --port "$TPORT" \
    --local-port "$(free_port)" --timeout 1 --json >"$OUTDIR/discover-dup.json" 2>/dev/null
"$PY" - "$OUTDIR/discover-dup.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
devs = d["devices"]
assert len(devs) == 2, devs
assert all(x["device"] == 260001 for x in devs), devs
assert all(x["duplicate_instance"] for x in devs), devs
assert sorted(x["ip"] for x in devs) == ["127.0.0.1", "127.0.0.2"], devs
print("json carries both claimants and flags each one")
EOF
want_exit "--json reports the duplicate as data" $? 0

say "a device that segments a response we never said we would accept"
SPORT=$(free_port); SLPORT=$(free_port)
start_fixture "$SPORT" "$OUTDIR/fixture-seg.log" --verbose --max-apdu 100 \
    --segment-responses || exit 1
"$PY" "$TOOL" read 127.0.0.1 device:260001 object-list --bind 127.0.0.1 \
    --port "$SPORT" --local-port "$SLPORT" --timeout 1 --verbose \
    >"$OUTDIR/read-segmented.txt" 2>&1
want_exit "a segmented reply exits 4" $? 4
sed 's/^/  /' "$OUTDIR/read-segmented.txt"
want "the segmented reply is named" "$OUTDIR/read-segmented.txt" \
    "device wanted to segment the response"
want "we said segmentation-not-supported" "$OUTDIR/read-segmented.txt" \
    "segmentation-not-supported was sent back"
# 0x70 = Abort from the client, invoke 1, reason 4. Checked on the wire, not
# inferred from our own message.
want "an Abort PDU went back on the wire" "$OUTDIR/read-segmented.txt" "0100700104"
want "the device saw the abort" "$OUTDIR/fixture-seg.log" "client aborted transaction"
"$PY" "$TOOL" read 127.0.0.1 device:260001 object-list --bind 127.0.0.1 \
    --port "$SPORT" --local-port "$(free_port)" --timeout 1 \
    >"$OUTDIR/read-segmented-plain.txt" 2>&1
want_not "no half-decoded value is printed" "$OUTDIR/read-segmented-plain.txt" \
    "analog-input:1"
want_eq "the plain output is two lines, not a table" \
    "$(wc -l <"$OUTDIR/read-segmented-plain.txt")" "2"

# ------------------------------------- 8. tables vs Tridium's own, if available
# Needs a Niagara install. Where there isn't one this is skipped, not failed --
# the rest of the suite proves the wire behaviour without it.
say "enumeration tables against Tridium's bacnet-rt.jar"
"$PY" "$HERE/check-enums-against-niagara.py" >"$OUTDIR/enums.txt" 2>&1
rc=$?
if [ "$rc" = "77" ]; then
    printf 'SKIP  no Niagara install to check enumerations against\n'
    sed 's/^/  /' "$OUTDIR/enums.txt"
else
    sed 's/^/  /' "$OUTDIR/enums.txt"
    want_exit "no enumeration disagrees with Tridium's" "$rc" 0
    want "the check ran over every table" "$OUTDIR/enums.txt" "TOTAL"
fi

printf '\n===== result =====\n'
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = "0" ] || exit 1
exit 0
