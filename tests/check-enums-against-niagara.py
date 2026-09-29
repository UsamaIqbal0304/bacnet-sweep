#!/usr/bin/env python3
"""Check bacnet-sweep.py's enumeration tables against Tridium's own, from bacnet-rt.jar.

    tests/check-enums-against-niagara.py [--modules DIR] [--verbose]

With no --modules it looks at $NIAGARA_HOME/modules, then the usual install
roots, and exits 77 ("skipped") when it finds no bacnet-rt.jar.

bacnet-sweep.py carries hand-written tables for object types, engineering units,
property identifiers, error classes and codes, reject and abort reasons. Those
tables were transcribed from the ASHRAE 135 enumerations, and a transcribed
table is exactly the kind of thing that is 97% right and quietly wrong in the
other 3%.

There is an independent copy of the same enumerations on this machine: the
`javax.baja.bacnet.enums.BBacnet*` classes inside the Niagara install's
bacnet-rt.jar, which are Tridium's implementation of the same standard. Each is
a frozen enum whose ordinals are `static final int` fields, so the mapping is in
the class file's constant pool and can be read without running any Java.

This reads them and prints, per table: how many names agree, which numbers
bacnet-sweep does not carry (fine -- it prints those as numbers), and which
names DISAGREE (not fine -- that is a wrong table). Exit code is non-zero only
for disagreements.

It needs a Niagara install and is therefore not part of the portable test run;
the test script runs it when the jar is there and skips it when it is not.
No licence is involved: this reads a jar already on disk.
"""

import argparse
import importlib.util
import io
import os
import re
import struct
import sys
import zipfile

def default_modules():
    """Where bacnet-rt.jar probably is, on whatever machine this is running on.

    $NIAGARA_HOME first, because an install that sets it is the one the operator
    means. Then the usual install roots, newest version last-sorted first, so a
    box with several versions is checked against its newest. Returning a path
    that does not exist is fine: main() reports that and exits 77, which the
    test script reads as a skip.
    """
    home = os.environ.get("NIAGARA_HOME")
    if home:
        return os.path.join(home, "modules")
    roots = []
    for base in ("/opt/Niagara", "/opt/niagara",
                 os.path.expanduser("~/Niagara"),
                 r"C:\Niagara", r"C:\Program Files\Niagara"):
        if os.path.isdir(base):
            roots += [os.path.join(base, d, "modules")
                      for d in sorted(os.listdir(base), reverse=True)]
    for path in roots:
        if os.path.isfile(os.path.join(path, "bacnet-rt.jar")):
            return path
    return roots[0] if roots else "/opt/Niagara/Niagara-4.15/modules"

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "bacnet-sweep.py")


def load_tool():
    spec = importlib.util.spec_from_file_location("bacnet_sweep", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------- class file reading

def parse_constant_pool(data, i):
    """Returns (pool, next_index). pool[n] is ('Utf8', s) or ('Integer', v) or None."""
    count = struct.unpack(">H", data[i:i + 2])[0]
    i += 2
    pool = [None] * count
    n = 1
    while n < count:
        tag = data[i]
        i += 1
        if tag == 1:                                    # Utf8
            length = struct.unpack(">H", data[i:i + 2])[0]
            i += 2
            pool[n] = ("Utf8", data[i:i + length].decode("utf-8", "replace"))
            i += length
        elif tag == 3:                                  # Integer
            pool[n] = ("Integer", struct.unpack(">i", data[i:i + 4])[0])
            i += 4
        elif tag == 4:                                  # Float
            pool[n] = ("Float", None)
            i += 4
        elif tag in (5, 6):                             # Long, Double: two slots
            pool[n] = ("Long/Double", None)
            i += 8
            n += 1
        elif tag in (7, 8, 16, 19, 20):                 # single u2 index
            i += 2
        elif tag in (9, 10, 11, 12, 17, 18):            # two u2 indices
            i += 4
        elif tag == 15:                                 # MethodHandle
            i += 3
        else:
            raise ValueError("unknown constant pool tag %d at %d" % (tag, i - 1))
        n += 1
    return pool, i


def static_int_fields(data):
    """{FIELD_NAME: value} for every `static final int` with a ConstantValue."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a class file")
    i = 8                                               # magic, minor, major
    pool, i = parse_constant_pool(data, i)
    i += 6                                              # access, this, super
    ifcount = struct.unpack(">H", data[i:i + 2])[0]
    i += 2 + 2 * ifcount
    fcount = struct.unpack(">H", data[i:i + 2])[0]
    i += 2
    out = {}
    for _ in range(fcount):
        _access = struct.unpack(">H", data[i:i + 2])[0]
        name_i = struct.unpack(">H", data[i + 2:i + 4])[0]
        desc_i = struct.unpack(">H", data[i + 4:i + 6])[0]
        acount = struct.unpack(">H", data[i + 6:i + 8])[0]
        i += 8
        name = pool[name_i][1]
        desc = pool[desc_i][1]
        value = None
        for _a in range(acount):
            an_i = struct.unpack(">H", data[i:i + 2])[0]
            alen = struct.unpack(">I", data[i + 2:i + 6])[0]
            abody = data[i + 6:i + 6 + alen]
            i += 6 + alen
            if pool[an_i][1] == "ConstantValue" and alen == 2:
                ci = struct.unpack(">H", abody)[0]
                if pool[ci] and pool[ci][0] == "Integer":
                    value = pool[ci][1]
        if desc == "I" and value is not None:
            out[name] = value
    return out


def dash(field_name):
    """SQUARE_METERS -> square-meters, the spelling bacnet-sweep prints."""
    return field_name.lower().replace("_", "-")


# ------------------------------------------------------------------- the check

# (class, our table attribute, how Tridium spells a name we spell differently)
CHECKS = [
    ("javax/baja/bacnet/enums/BBacnetObjectType.class", "OBJECT_TYPES", {}),
    ("javax/baja/bacnet/enums/BBacnetEngineeringUnits.class", "UNITS", {}),
    ("javax/baja/bacnet/enums/BBacnetPropertyIdentifier.class", "PROPERTIES", {}),
    ("javax/baja/bacnet/enums/BBacnetErrorClass.class", "ERROR_CLASS", {}),
    ("javax/baja/bacnet/enums/BBacnetErrorCode.class", "ERROR_CODE", {}),
    ("javax/baja/bacnet/enums/BBacnetRejectReason.class", "REJECT_REASON", {}),
    ("javax/baja/bacnet/enums/BBacnetAbortReason.class", "ABORT_REASON", {}),
    ("javax/baja/bacnet/enums/BBacnetSegmentation.class", "SEGMENTATION", {}),
    ("javax/baja/bacnet/enums/BBacnetDeviceStatus.class", "DEVICE_STATUS", {}),
    ("javax/baja/bacnet/enums/BBacnetEventState.class", "EVENT_STATE", {}),
    ("javax/baja/bacnet/enums/BBacnetReliability.class", "RELIABILITY", {}),
    ("javax/baja/bacnet/enums/BBacnetBinaryPv.class", "BINARY_PV", {}),
    ("javax/baja/bacnet/enums/BBacnetPolarity.class", "POLARITY", {}),
    ("javax/baja/bacnet/enums/BBacnetNotifyType.class", "NOTIFY_TYPE", {}),
]

# Nothing here: every name we carry matches Tridium's exactly. Kept because the
# next enumeration added may legitimately need one, and because an empty table
# is a stronger statement than no table.
COSMETIC = {}

# The Baja plumbing constants that are not BACnet ordinals. Named in full, not
# matched by wildcard: an earlier version of this used `.*_PROPERTY` and
# silently swallowed UNKNOWN_PROPERTY, NOT_COV_PROPERTY,
# NO_SPACE_TO_WRITE_PROPERTY and LOG_DEVICE_OBJECT_PROPERTY, then reported them
# as ordinals Tridium did not have. A filter that hides real data to look tidy
# is worse than no filter.
NOT_ORDINALS = re.compile(
    r"^(serialVersionUID|MAX_ID|MAX_ASHRAE_ID|MAX_RESERVED_ID)$")


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--modules", default=None)
    ap.add_argument("--verbose", action="store_true",
                    help="list every number Tridium has that we do not")
    a = ap.parse_args()

    modules = a.modules or default_modules()
    jar = os.path.join(modules, "bacnet-rt.jar")
    if not os.path.exists(jar):
        sys.stderr.write("no bacnet-rt.jar at %s -- nothing to check against\n" % jar)
        return 77                                       # conventional "skipped"
    tool = load_tool()
    zf = zipfile.ZipFile(jar)
    total_agree = total_extra = total_missing = total_conflict = 0
    print("%-22s %7s %7s %7s %7s" % ("table", "agree", "ours+", "theirs+", "CONFLICT"))
    print("%-22s %7s %7s %7s %7s" % ("-" * 22, "-" * 7, "-" * 7, "-" * 7, "-" * 8))
    conflicts = []
    for entry, attr, _renames in CHECKS:
        try:
            data = zf.read(entry)
        except KeyError:
            print("%-22s %7s  (class not in jar)" % (attr, "-"))
            continue
        theirs = {}
        for field, value in static_int_fields(data).items():
            if NOT_ORDINALS.match(field) or field != field.upper():
                continue
            theirs.setdefault(value, dash(field))
        ours = getattr(tool, attr)
        agree = extra = missing = 0
        for num, name in sorted(theirs.items()):
            if num not in ours:
                missing += 1
                if a.verbose:
                    print("    theirs only: %s = %d" % (name, num))
                continue
            if ours[num] == name or COSMETIC.get((attr, ours[num])) == name:
                agree += 1
            else:
                conflicts.append((attr, num, ours[num], name))
        for num in ours:
            if num not in theirs:
                extra += 1
                if a.verbose:
                    print("    ours only:   %s = %d" % (ours[num], num))
        nconf = sum(1 for c in conflicts if c[0] == attr)
        print("%-22s %7d %7d %7d %7d" % (attr, agree, extra, missing, nconf))
        total_agree += agree
        total_extra += extra
        total_missing += missing
        total_conflict += nconf
    print("%-22s %7d %7d %7d %7d" % ("TOTAL", total_agree, total_extra,
                                     total_missing, total_conflict))
    if conflicts:
        print("\nDisagreements (bacnet-sweep first, Tridium second):")
        for attr, num, mine, theirs_name in conflicts:
            print("  %-18s %6d  %-42s %s" % (attr, num, mine, theirs_name))
    print("\n%d entries agree with Tridium's implementation of the same enumerations.\n"
          "%d numbers Tridium carries are not in our tables; those print as numbers,\n"
          "which is the designed behaviour and not an error. %d of our entries are not\n"
          "in Tridium's. %d names disagree."
          % (total_agree, total_missing, total_extra, total_conflict))
    return 1 if total_conflict else 0


if __name__ == "__main__":
    sys.exit(main())
