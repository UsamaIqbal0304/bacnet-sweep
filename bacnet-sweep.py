#!/usr/bin/env python3
"""Ask a BACnet/IP network what is on it, and print the answer. Read-only, by construction.

    tools/bacnet-sweep.py discover [--broadcast ADDR]
    tools/bacnet-sweep.py read <ip> <objtype>:<inst> <property> [--index N]
    tools/bacnet-sweep.py points <ip> <device-instance> [--csv | --json]

Why this exists
---------------
The first question on any site visit is "what is actually on this box" — and the
usual answers are a laptop with Workbench on it, a vendor tool that only speaks
to that vendor, or a $600 licence. This is none of those: one Python file, no
dependencies, speaking BACnet/IP APDUs it encodes itself, that lists the devices
on a subnet and then every point on a device with its name, value and units.

The read-only promise
---------------------
The tool can only ever transmit two BACnet services, and there is no code path
in this file that encodes any other:

    Who-Is        (unconfirmed service 8)   -- "who is out there"
    ReadProperty  (confirmed service 12)    -- "what is this property"

There is no WriteProperty, no WritePropertyMultiple, no ReinitializeDevice, no
DeviceCommunicationControl, no TimeSynchronization, no AtomicWriteFile, no COV
subscription. `_assert_read_only()` gates every confirmed request and raises
before a socket is touched if the service choice is anything but 12. The one
other thing that leaves the socket is an Abort PDU (a transaction-layer PDU, not
a service: it carries no data and changes nothing) sent to close out a device
that answered with a segmented response we will not reassemble.

It is also quiet on purpose: one Who-Is (a second only with `--retries`),
per-point reads issued sequentially with a delay between them (`--delay`), never
in parallel, and never to an address the operator did not name.

* Two devices answering with the same device instance are both listed and both
  flagged. Discovery is keyed by instance *and* address, because de-duplicating
  by instance would hide a duplicate-instance clash -- one of the few faults a
  sweep can find that will not show up anywhere else until something breaks.
* Enumeration names were checked against Tridium's own BACnet enumerations in
  the Niagara install on the machine this was written on, not only against the
  standard as remembered: `tests/check-enums-against-niagara.py` prints the
  comparison, and it found four wrong property identifiers when first run.

Accuracy notes
--------------
* What a device reports is what gets printed. If a controller lies about its
  units, this prints the lie. No value is derived, scaled or inferred.
* Enumerations (object types, engineering units, error codes) are transcribed
  from the ASHRAE 135 enumerations. Anything not in the table prints as its
  number -- `unit-247`, `property-4194303` -- rather than a guess. Proprietary
  values above the standard ranges are labelled proprietary, not decoded.
* Segmentation is refused, not reassembled. The confirmed requests this tool
  sends do not set the segmented-response-accepted bit, so a device with a long
  object-list answers Abort(segmentation-not-supported). That is reported as
  such. `--index` is the way round it: `object-list` element 0 is the count, and
  elements 1..N can be read one at a time without segmentation.
* Only devices on the local IP subnet are reachable. There is no BBMD support,
  no foreign-device registration and no network-layer routing, so an MS/TP
  device behind a BACnet router will appear in `discover` (its I-Am is routed
  back with a source network) but cannot be read. Those rows are marked.
* Absence of an answer is not absence of a device. A silent sweep most often
  means the wrong subnet, a firewall, or devices that only speak MS/TP.

Licence
-------
MIT. Copyright (c) 2026 Usama Iqbal (Plantroom Labs). Use it, change it, ship it
inside something you sell — the only condition is that the copyright line and
the permission notice travel with it. Full text:
https://plantroomlabs.com/tools/LICENSE.txt
"""

import argparse
import csv
import errno
import json
import os
import socket
import struct
import sys
import time

BVLC_TYPE_BIP = 0x81
BVLC_ORIGINAL_UNICAST = 0x0a
BVLC_ORIGINAL_BROADCAST = 0x0b
BVLC_FORWARDED = 0x04

PDU_CONFIRMED_REQ = 0x0
PDU_UNCONFIRMED_REQ = 0x1
PDU_SIMPLE_ACK = 0x2
PDU_COMPLEX_ACK = 0x3
PDU_SEGMENT_ACK = 0x4
PDU_ERROR = 0x5
PDU_REJECT = 0x6
PDU_ABORT = 0x7

SERVICE_WHO_IS = 8
SERVICE_I_AM = 0
SERVICE_READ_PROPERTY = 12

# The only confirmed service this file is permitted to encode. See the docstring.
ALLOWED_CONFIRMED_SERVICES = (SERVICE_READ_PROPERTY,)

DEFAULT_PORT = 47808            # 0xBAC0
# 22-bit instance space is 0..4194302; the top value is reserved for "unknown",
# which in practice means a device nobody has commissioned.
UNCONFIGURED_INSTANCE = 4194303

OBJECT_TYPES = {
    0: "analog-input", 1: "analog-output", 2: "analog-value",
    3: "binary-input", 4: "binary-output", 5: "binary-value",
    6: "calendar", 7: "command", 8: "device", 9: "event-enrollment",
    10: "file", 11: "group", 12: "loop", 13: "multi-state-input",
    14: "multi-state-output", 15: "notification-class", 16: "program",
    17: "schedule", 18: "averaging", 19: "multi-state-value",
    20: "trend-log", 21: "life-safety-point", 22: "life-safety-zone",
    23: "accumulator", 24: "pulse-converter", 25: "event-log",
    26: "global-group", 27: "trend-log-multiple", 28: "load-control",
    29: "structured-view", 30: "access-door", 32: "access-credential",
    33: "access-point", 34: "access-rights", 35: "access-user",
    36: "access-zone", 37: "credential-data-input", 39: "bitstring-value",
    40: "character-string-value", 41: "date-pattern-value", 42: "date-value",
    43: "date-time-pattern-value", 44: "date-time-value",
    45: "integer-value", 46: "large-analog-value", 47: "octet-string-value",
    48: "positive-integer-value", 49: "time-pattern-value", 50: "time-value",
    51: "notification-forwarder", 52: "alert-enrollment", 53: "channel",
    54: "lighting-output", 55: "binary-lighting-output", 56: "network-port",
    57: "elevator-group", 58: "escalator", 59: "lift",
}
OBJECT_TYPE_BY_NAME = dict((v, k) for k, v in OBJECT_TYPES.items())
OBJECT_TYPE_ALIASES = {
    "ai": 0, "ao": 1, "av": 2, "bi": 3, "bo": 4, "bv": 5,
    "dev": 8, "device": 8, "mi": 13, "mo": 14, "msv": 19, "mv": 19,
    "tl": 20, "sched": 17, "nc": 15, "sv": 29, "acc": 23,
    # The standard's own hyphenation of these four is not what Niagara prints;
    # accept both spellings on the command line.
    "characterstring-value": 40, "datetime-pattern-value": 43,
    "datetime-value": 44, "octetstring-value": 47,
}
BINARY_TYPES = (3, 4, 5, 55)
MULTISTATE_TYPES = (13, 14, 19)

PROPERTIES = {
    0: "acked-transitions", 1: "ack-required", 2: "action", 3: "action-text",
    4: "active-text", 5: "active-vt-sessions", 6: "alarm-value",
    7: "alarm-values", 8: "all", 9: "all-writes-successful",
    10: "apdu-segment-timeout",
    11: "apdu-timeout", 12: "application-software-version",
    13: "archive", 14: "bias", 15: "change-of-state-count",
    16: "change-of-state-time", 17: "notification-class",
    19: "controlled-variable-reference", 20: "controlled-variable-units",
    21: "controlled-variable-value", 22: "cov-increment", 23: "date-list",
    24: "daylight-savings-status", 25: "deadband", 26: "derivative-constant",
    27: "derivative-constant-units", 28: "description",
    29: "description-of-halt", 30: "device-address-binding",
    31: "device-type", 32: "effective-period", 33: "elapsed-active-time",
    34: "error-limit", 35: "event-enable", 36: "event-state",
    37: "event-type", 38: "exception-schedule", 39: "fault-values",
    40: "feedback-value", 41: "file-access-method", 42: "file-size",
    43: "file-type", 44: "firmware-revision", 45: "high-limit",
    46: "inactive-text", 47: "in-process", 48: "instance-of",
    49: "integral-constant", 50: "integral-constant-units",
    52: "limit-enable", 53: "list-of-group-members",
    54: "list-of-object-property-references", 56: "local-date",
    57: "local-time", 58: "location", 59: "low-limit",
    60: "manipulated-variable-reference", 61: "maximum-output",
    62: "max-apdu-length-accepted", 63: "max-info-frames", 64: "max-master",
    65: "max-pres-value", 66: "minimum-off-time", 67: "minimum-on-time",
    68: "minimum-output", 69: "min-pres-value", 70: "model-name",
    71: "modification-date", 72: "notify-type", 73: "number-of-apdu-retries",
    74: "number-of-states", 75: "object-identifier", 76: "object-list",
    77: "object-name", 78: "object-property-reference", 79: "object-type",
    80: "optional", 81: "out-of-service", 82: "output-units",
    83: "event-parameters", 84: "polarity", 85: "present-value",
    86: "priority", 87: "priority-array", 88: "priority-for-writing",
    89: "process-identifier", 90: "program-change", 91: "program-location",
    92: "program-state", 93: "proportional-constant",
    94: "proportional-constant-units", 96: "protocol-object-types-supported",
    97: "protocol-services-supported", 98: "protocol-version",
    99: "read-only", 100: "reason-for-halt", 102: "recipient-list",
    103: "reliability", 104: "relinquish-default", 105: "required",
    106: "resolution", 107: "segmentation-supported", 108: "setpoint",
    109: "setpoint-reference", 110: "state-text", 111: "status-flags",
    112: "system-status", 113: "time-delay", 114: "time-of-active-time-reset",
    115: "time-of-state-count-reset", 116: "time-synchronization-recipients",
    117: "units", 118: "update-interval", 119: "utc-offset",
    120: "vendor-identifier", 121: "vendor-name", 122: "vt-classes-supported",
    123: "weekly-schedule", 124: "attempted-samples", 125: "average-value",
    126: "buffer-size", 127: "client-cov-increment", 128: "cov-resubscription-interval",
    130: "event-time-stamps", 131: "log-buffer", 132: "log-device-object-property",
    133: "enable", 134: "log-interval", 135: "maximum-value",
    136: "minimum-value", 137: "notification-threshold",
    139: "protocol-revision", 140: "records-since-notification",
    141: "record-count", 142: "start-time", 143: "stop-time",
    144: "stop-when-full", 145: "total-record-count", 146: "valid-samples",
    147: "window-interval", 148: "window-samples", 149: "maximum-value-timestamp",
    150: "minimum-value-timestamp", 151: "variance-value",
    152: "active-cov-subscriptions", 153: "backup-failure-timeout",
    154: "configuration-files", 155: "database-revision",
    156: "direct-reading", 157: "last-restore-time",
    158: "maintenance-required", 159: "member-of", 160: "mode",
    161: "operation-expected", 162: "setting", 163: "silenced",
    164: "tracking-value", 165: "zone-members",
    166: "life-safety-alarm-values", 167: "max-segments-accepted",
    168: "profile-name", 169: "auto-slave-discovery",
    170: "manual-slave-address-binding", 171: "slave-address-binding",
    172: "slave-proxy-enable", 173: "last-notify-record",
    174: "schedule-default", 371: "property-list", 372: "serial-number",
}
PROPERTY_BY_NAME = dict((v, k) for k, v in PROPERTIES.items())
PROPERTY_BY_NAME["datelist"] = 23          # older spelling, still typed

# BACnetEngineeringUnits, as enumerated in ASHRAE 135. Numbers not listed here
# print as `unit-<n>`; 256 and above is the proprietary range.
UNITS = {
    0: "square-meters", 1: "square-feet", 2: "milliamperes", 3: "amperes",
    4: "ohms", 5: "volts", 6: "kilovolts", 7: "megavolts", 8: "volt-amperes",
    9: "kilovolt-amperes", 10: "megavolt-amperes", 11: "volt-amperes-reactive",
    12: "kilovolt-amperes-reactive", 13: "megavolt-amperes-reactive",
    14: "degrees-phase", 15: "power-factor", 16: "joules", 17: "kilojoules",
    18: "watt-hours", 19: "kilowatt-hours", 20: "btus", 21: "therms",
    22: "ton-hours", 23: "joules-per-kilogram-dry-air",
    24: "btus-per-pound-dry-air", 25: "cycles-per-hour", 26: "cycles-per-minute",
    27: "hertz", 28: "grams-of-water-per-kilogram-dry-air",
    29: "percent-relative-humidity", 30: "millimeters", 31: "meters",
    32: "inches", 33: "feet", 34: "watts-per-square-foot",
    35: "watts-per-square-meter", 36: "lumens", 37: "luxes", 38: "foot-candles",
    39: "kilograms", 40: "pounds-mass", 41: "tons", 42: "kilograms-per-second",
    43: "kilograms-per-minute", 44: "kilograms-per-hour",
    45: "pounds-mass-per-minute", 46: "pounds-mass-per-hour", 47: "watts",
    48: "kilowatts", 49: "megawatts", 50: "btus-per-hour", 51: "horsepower",
    52: "tons-refrigeration", 53: "pascals", 54: "kilopascals", 55: "bars",
    56: "pounds-force-per-square-inch", 57: "centimeters-of-water",
    58: "inches-of-water", 59: "millimeters-of-mercury",
    60: "centimeters-of-mercury", 61: "inches-of-mercury",
    62: "degrees-celsius", 63: "degrees-kelvin", 64: "degrees-fahrenheit",
    65: "degree-days-celsius", 66: "degree-days-fahrenheit", 67: "years",
    68: "months", 69: "weeks", 70: "days", 71: "hours", 72: "minutes",
    73: "seconds", 74: "meters-per-second", 75: "kilometers-per-hour",
    76: "feet-per-second", 77: "feet-per-minute", 78: "miles-per-hour",
    79: "cubic-feet", 80: "cubic-meters", 81: "imperial-gallons", 82: "liters",
    83: "us-gallons", 84: "cubic-feet-per-minute", 85: "cubic-meters-per-second",
    86: "imperial-gallons-per-minute", 87: "liters-per-second",
    88: "liters-per-minute", 89: "us-gallons-per-minute", 90: "degrees-angular",
    91: "degrees-celsius-per-hour", 92: "degrees-celsius-per-minute",
    93: "degrees-fahrenheit-per-hour", 94: "degrees-fahrenheit-per-minute",
    95: "no-units", 96: "parts-per-million", 97: "parts-per-billion",
    98: "percent", 99: "percent-per-second", 100: "per-minute", 101: "per-second",
    102: "psi-per-degree-fahrenheit", 103: "radians",
    104: "revolutions-per-minute", 105: "currency-1", 106: "currency-2",
    107: "currency-3", 108: "currency-4", 109: "currency-5", 110: "currency-6",
    111: "currency-7", 112: "currency-8", 113: "currency-9", 114: "currency-10",
    115: "square-inches", 116: "square-centimeters", 117: "btus-per-pound",
    118: "centimeters", 119: "pounds-mass-per-second",
    120: "delta-degrees-fahrenheit", 121: "delta-degrees-kelvin",
    122: "kilohms", 123: "megohms", 124: "millivolts",
    125: "kilojoules-per-kilogram", 126: "megajoules",
    127: "joules-per-degree-kelvin", 128: "joules-per-kilogram-degree-kelvin",
    129: "kilohertz", 130: "megahertz", 131: "per-hour", 132: "milliwatts",
    133: "hectopascals", 134: "millibars", 135: "cubic-meters-per-hour",
    136: "liters-per-hour", 137: "kilowatt-hours-per-square-meter",
    138: "kilowatt-hours-per-square-foot", 139: "megajoules-per-square-meter",
    140: "megajoules-per-square-foot", 141: "watts-per-square-meter-degree-kelvin",
    142: "cubic-feet-per-second", 143: "percent-obscuration-per-foot",
    144: "percent-obscuration-per-meter", 145: "milliohms",
    146: "megawatt-hours", 147: "kilo-btus", 148: "mega-btus",
    149: "kilojoules-per-kilogram-dry-air", 150: "megajoules-per-kilogram-dry-air",
    151: "kilojoules-per-degree-kelvin", 152: "megajoules-per-degree-kelvin",
    153: "newton", 154: "grams-per-second", 155: "grams-per-minute",
    156: "tons-per-hour", 157: "kilo-btus-per-hour", 158: "hundredths-seconds",
    159: "milliseconds", 160: "newton-meters", 161: "millimeters-per-second",
    162: "millimeters-per-minute", 163: "meters-per-minute",
    164: "meters-per-hour", 166: "meters-per-second-per-second",
    167: "amperes-per-meter", 168: "amperes-per-square-meter",
    169: "ampere-square-meters", 170: "farads", 171: "henrys",
    172: "ohm-meters", 173: "siemens", 174: "siemens-per-meter", 175: "teslas",
    176: "volts-per-degree-kelvin", 177: "volts-per-meter", 178: "webers",
    179: "candelas", 180: "candelas-per-square-meter",
    181: "degrees-kelvin-per-hour", 182: "degrees-kelvin-per-minute",
    183: "joule-seconds", 184: "radians-per-second",
    185: "square-meters-per-newton", 186: "kilograms-per-cubic-meter",
    187: "newton-seconds", 188: "newtons-per-meter",
    189: "watts-per-meter-per-degree-kelvin", 190: "microsiemens",
    191: "cubic-feet-per-hour", 192: "us-gallons-per-hour", 193: "kilometers",
    194: "micrometers", 195: "grams", 196: "milligrams", 197: "milliliters",
    198: "milliliters-per-second", 199: "decibels", 200: "decibels-millivolt",
    201: "decibels-volt", 202: "millisiemens",
}

SEGMENTATION = {0: "segmented-both", 1: "segmented-transmit",
                2: "segmented-receive", 3: "no-segmentation"}
BINARY_PV = {0: "inactive", 1: "active"}
POLARITY = {0: "normal", 1: "reverse"}
EVENT_STATE = {0: "normal", 1: "fault", 2: "offnormal", 3: "high-limit",
               4: "low-limit", 5: "life-safety-alarm"}
RELIABILITY = {0: "no-fault-detected", 1: "no-sensor", 2: "over-range",
               3: "under-range", 4: "open-loop", 5: "shorted-loop",
               6: "no-output", 7: "unreliable-other", 8: "process-error",
               9: "multi-state-fault", 10: "configuration-error",
               12: "communication-failure", 13: "member-fault"}
DEVICE_STATUS = {0: "operational", 1: "operational-read-only",
                 2: "download-required", 3: "download-in-progress",
                 4: "non-operational", 5: "backup-in-progress"}
NOTIFY_TYPE = {0: "alarm", 1: "event", 2: "ack-notification"}
STATUS_FLAG_BITS = ("in-alarm", "fault", "overridden", "out-of-service")

ERROR_CLASS = {0: "device", 1: "object", 2: "property", 3: "resources",
               4: "security", 5: "services", 6: "vt", 7: "communication"}
ERROR_CODE = {
    0: "other", 1: "authentication-failed", 2: "configuration-in-progress",
    3: "device-busy", 4: "dynamic-creation-not-supported",
    5: "file-access-denied", 6: "incompatible-security-levels",
    7: "inconsistent-parameters", 8: "inconsistent-selection-criterion",
    9: "invalid-data-type", 10: "invalid-file-access-method",
    11: "invalid-file-start-position", 12: "invalid-operator-name",
    13: "invalid-parameter-data-type", 14: "invalid-time-stamp",
    15: "key-generation-error", 16: "missing-required-parameter",
    17: "no-objects-of-specified-type", 18: "no-space-for-object",
    19: "no-space-to-add-list-element", 20: "no-space-to-write-property",
    21: "no-vt-sessions-available", 22: "property-is-not-a-list",
    23: "object-deletion-not-permitted", 24: "object-identifier-already-exists",
    25: "operational-problem", 26: "password-failure", 27: "read-access-denied",
    28: "security-not-supported", 29: "service-request-denied", 30: "timeout",
    31: "unknown-object", 32: "unknown-property", 34: "unknown-vt-class",
    35: "unknown-vt-session", 36: "unsupported-object-type",
    37: "value-out-of-range", 38: "vt-session-already-closed",
    39: "vt-session-termination-failure", 40: "write-access-denied",
    41: "character-set-not-supported", 42: "invalid-array-index",
    43: "cov-subscription-failed", 44: "not-cov-property",
    45: "optional-functionality-not-supported", 46: "invalid-configuration-data",
    47: "datatype-not-supported", 48: "duplicate-name", 49: "duplicate-object-id",
    50: "property-is-not-an-array", 51: "abort-buffer-overflow",
    52: "abort-invalid-apdu-in-this-state",
    53: "abort-preempted-by-higher-priority-task",
    54: "abort-segmentation-not-supported", 55: "abort-proprietary",
    56: "abort-other", 57: "invalid-tag", 58: "network-down",
    59: "reject-buffer-overflow", 60: "reject-inconsistent-parameters",
    61: "reject-invalid-parameter-data-type", 62: "reject-invalid-tag",
    63: "reject-missing-required-parameter", 64: "reject-parameter-out-of-range",
    65: "reject-too-many-arguments", 66: "reject-undefined-enumeration",
    67: "reject-unrecognized-service", 68: "reject-proprietary",
    69: "reject-other", 70: "unknown-device", 71: "unknown-route",
    72: "value-not-initialized", 73: "invalid-event-state",
    74: "no-alarm-configured", 75: "log-buffer-full", 76: "logged-value-purged",
    77: "no-property-specified", 78: "not-configured-for-triggered-logging",
    79: "unknown-subscription", 80: "parameter-out-of-range",
    81: "list-element-not-found", 82: "busy", 83: "communication-disabled",
    84: "success", 85: "access-denied", 86: "bad-destination-address",
}
REJECT_REASON = {0: "other", 1: "buffer-overflow", 2: "inconsistent-parameters",
                 3: "invalid-parameter-data-type", 4: "invalid-tag",
                 5: "missing-required-parameter", 6: "parameter-out-of-range",
                 7: "too-many-arguments", 8: "undefined-enumeration",
                 9: "unrecognized-service"}
ABORT_REASON = {0: "other", 1: "buffer-overflow",
                2: "invalid-apdu-in-this-state",
                3: "preempted-by-higher-priority-task",
                4: "segmentation-not-supported", 5: "security-error",
                6: "insufficient-security", 7: "window-size-out-of-range",
                8: "application-exceeded-reply-time", 9: "out-of-resources",
                10: "tsm-timeout", 11: "apdu-too-long"}

CHAR_ENCODINGS = {0: "utf-8", 1: "cp1252", 2: "iso2022_jp",
                  3: "utf-32-be", 4: "utf-16-be", 5: "iso-8859-1"}
CHAR_ENCODING_NAMES = {0: "UTF-8 (ANSI X3.4)", 1: "IBM/Microsoft DBCS",
                       2: "JIS X 0208", 3: "UCS-4", 4: "UCS-2",
                       5: "ISO 8859-1"}


class BacnetDecodeError(Exception):
    """Bytes off the wire did not parse. Never allowed to escape to a traceback."""


# ---------------------------------------------------------------- tag encoding

def _len_bytes(n):
    """Unsigned integer in the fewest octets BACnet allows (at least one)."""
    if n < 0:
        raise ValueError("unsigned cannot be negative")
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def enc_tag(number, context, length):
    """One tag octet (plus extensions) for tag `number`, `length` octets of data."""
    if number > 254:
        raise ValueError("tag number out of range")
    head = 0x08 if context else 0x00
    first = (number << 4) | head if number <= 14 else 0xF0 | head
    if length <= 4:
        out = bytearray([first | length])
        ext = b""
    else:
        out = bytearray([first | 5])
        if length <= 253:
            ext = bytes([length])
        elif length <= 0xFFFF:
            ext = b"\xfe" + struct.pack(">H", length)
        else:
            ext = b"\xff" + struct.pack(">I", length)
    if number > 14:
        out.append(number)          # extended tag number precedes extended length
    return bytes(out) + ext


def enc_context_unsigned(number, value):
    b = _len_bytes(value)
    return enc_tag(number, True, len(b)) + b


def enc_context_objid(number, objtype, instance):
    b = struct.pack(">I", ((objtype & 0x3FF) << 22) | (instance & 0x3FFFFF))
    return enc_tag(number, True, 4) + b


# ---------------------------------------------------------------- tag decoding

def dec_tag(buf, i):
    """Return (tag_number, is_context, kind, data_bytes, next_index).

    kind is 'primitive', 'opening' or 'closing'. For opening/closing, data is b''.
    """
    if i >= len(buf):
        raise BacnetDecodeError("ran off the end of the APDU looking for a tag")
    b = buf[i]
    i += 1
    number = (b & 0xF0) >> 4
    context = bool(b & 0x08)
    lvt = b & 0x07
    if number == 0x0F:
        if i >= len(buf):
            raise BacnetDecodeError("extended tag number truncated")
        number = buf[i]
        i += 1
    if lvt == 6:
        return number, context, "opening", b"", i
    if lvt == 7:
        return number, context, "closing", b"", i
    if lvt == 5:
        if i >= len(buf):
            raise BacnetDecodeError("extended length truncated")
        n = buf[i]
        i += 1
        if n == 0xFE:
            if i + 2 > len(buf):
                raise BacnetDecodeError("16-bit extended length truncated")
            n = struct.unpack(">H", buf[i:i + 2])[0]
            i += 2
        elif n == 0xFF:
            if i + 4 > len(buf):
                raise BacnetDecodeError("32-bit extended length truncated")
            n = struct.unpack(">I", buf[i:i + 4])[0]
            i += 4
        length = n
    elif not context and number == 1:
        # Application boolean carries its value in the length field.
        return number, context, "primitive", bytes([lvt]), i
    else:
        length = lvt
    if i + length > len(buf):
        raise BacnetDecodeError("tag %d claims %d octets, only %d left"
                                % (number, length, len(buf) - i))
    return number, context, "primitive", bytes(buf[i:i + length]), i + length


def dec_app_value(tagnum, data):
    """Decode one application-tagged primitive into (typename, python value)."""
    if tagnum == 0:
        return "null", None
    if tagnum == 1:
        return "boolean", bool(data[0]) if data else False
    if tagnum == 2:
        return "unsigned", int.from_bytes(data, "big") if data else 0
    if tagnum == 3:
        return "signed", int.from_bytes(data, "big", signed=True) if data else 0
    if tagnum == 4:
        if len(data) != 4:
            raise BacnetDecodeError("real is %d octets, not 4" % len(data))
        return "real", struct.unpack(">f", data)[0]
    if tagnum == 5:
        if len(data) != 8:
            raise BacnetDecodeError("double is %d octets, not 8" % len(data))
        return "double", struct.unpack(">d", data)[0]
    if tagnum == 6:
        return "octet-string", bytes(data)
    if tagnum == 7:
        if not data:
            return "character-string", ""
        enc = data[0]
        codec = CHAR_ENCODINGS.get(enc)
        if codec is None:
            return "character-string", ("<charset %d, not decoded: %s>"
                                       % (enc, data[1:].hex()))
        try:
            return "character-string", data[1:].decode(codec, "replace")
        except (LookupError, UnicodeError):
            return "character-string", ("<charset %s undecodable: %s>"
                                        % (CHAR_ENCODING_NAMES.get(enc, enc),
                                           data[1:].hex()))
    if tagnum == 8:
        if not data:
            return "bit-string", []
        unused = data[0]
        bits = []
        for octet in data[1:]:
            for k in range(8):
                bits.append(bool(octet & (0x80 >> k)))
        if 0 < unused <= 7:
            bits = bits[:-unused]
        return "bit-string", bits
    if tagnum == 9:
        return "enumerated", int.from_bytes(data, "big") if data else 0
    if tagnum == 10:
        if len(data) != 4:
            raise BacnetDecodeError("date is %d octets, not 4" % len(data))
        return "date", (data[0], data[1], data[2], data[3])
    if tagnum == 11:
        if len(data) != 4:
            raise BacnetDecodeError("time is %d octets, not 4" % len(data))
        return "time", (data[0], data[1], data[2], data[3])
    if tagnum == 12:
        if len(data) != 4:
            raise BacnetDecodeError("object identifier is %d octets, not 4" % len(data))
        raw = struct.unpack(">I", data)[0]
        return "object-identifier", ((raw >> 22) & 0x3FF, raw & 0x3FFFFF)
    return "application-tag-%d" % tagnum, bytes(data)


def dec_app_values(buf, i, stop_context=None):
    """Decode a run of application-tagged primitives.

    Stops at the closing tag numbered `stop_context` (or at end of buffer).
    Constructed context data inside the run is skipped and reported as opaque,
    so an unexpected structure never raises.
    """
    out = []
    depth = 0
    while i < len(buf):
        number, context, kind, data, nxt = dec_tag(buf, i)
        if kind == "closing":
            if depth == 0 and (stop_context is None or number == stop_context):
                return out, nxt
            depth = max(0, depth - 1)
            i = nxt
            continue
        if kind == "opening":
            depth += 1
            i = nxt
            continue
        if context:
            out.append(("context-%d" % number, bytes(data)))
        else:
            out.append(dec_app_value(number, data))
        i = nxt
    return out, i


# -------------------------------------------------------------- formatting

def objid_str(objtype, instance):
    return "%s:%d" % (OBJECT_TYPES.get(objtype, "object-type-%d" % objtype), instance)


def property_name(pid):
    if pid in PROPERTIES:
        return PROPERTIES[pid]
    if pid >= 512:
        return "proprietary-property-%d" % pid
    return "property-%d" % pid


def enum_table_for(objtype, pid):
    if pid == 117:
        return UNITS, "unit"
    if pid == 79:
        return OBJECT_TYPES, "object-type"
    if pid == 107:
        return SEGMENTATION, "segmentation"
    if pid == 112:
        return DEVICE_STATUS, "device-status"
    if pid == 36:
        return EVENT_STATE, "event-state"
    if pid == 103:
        return RELIABILITY, "reliability"
    if pid == 84:
        return POLARITY, "polarity"
    if pid == 72:
        return NOTIFY_TYPE, "notify-type"
    if pid == 85 and objtype in BINARY_TYPES:
        return BINARY_PV, "binary-pv"
    return None, None


def fmt_real(v, digits=7):
    """A float32 carries ~7 significant digits, a float64 ~15. Print no more than
    the wire actually justified, so no precision is invented."""
    if v != v or v in (float("inf"), float("-inf")):
        return repr(v)
    return "%.*g" % (digits, v)


def fmt_one(kind, value, objtype=None, pid=None):
    if kind == "null":
        return "null"
    if kind == "boolean":
        return "true" if value else "false"
    if kind in ("unsigned", "signed"):
        return str(value)
    if kind == "real":
        return fmt_real(value, 7)
    if kind == "double":
        return fmt_real(value, 15)
    if kind == "octet-string":
        return value.hex() if value else "(empty)"
    if kind == "character-string":
        return value
    if kind == "bit-string":
        if pid == 111 and len(value) >= len(STATUS_FLAG_BITS):
            on = [n for n, f in zip(STATUS_FLAG_BITS, value) if f]
            return ",".join(on) if on else "(none set)"
        return "".join("1" if b else "0" for b in value)
    if kind == "enumerated":
        table, label = enum_table_for(objtype, pid)
        if table is not None:
            if value in table:
                return table[value]
            if label == "unit" and value >= 256:
                return "proprietary-unit-%d" % value
            return "%s-%d" % (label, value)
        return str(value)
    if kind == "date":
        y, m, d, dow = value
        year = "*" if y == 255 else str(1900 + y)
        mon = "*" if m == 255 else "%02d" % m
        day = "*" if d == 255 else "%02d" % d
        names = {1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat", 7: "Sun"}
        return "%s-%s-%s%s" % (year, mon, day,
                               "" if dow == 255 else " (%s)" % names.get(dow, dow))
    if kind == "time":
        h, m, s, cs = value
        p = lambda v: "*" if v == 255 else "%02d" % v
        return "%s:%s:%s.%s" % (p(h), p(m), p(s), p(cs))
    if kind == "object-identifier":
        return objid_str(value[0], value[1])
    if kind.startswith("context-"):
        return "<%s %s>" % (kind, value.hex())
    return "<%s %r>" % (kind, value)


def fmt_values(values, objtype=None, pid=None, limit=None):
    if not values:
        return "(empty)"
    parts = [fmt_one(k, v, objtype, pid) for k, v in values]
    if limit is not None and len(parts) > limit:
        return ", ".join(parts[:limit]) + " ... (+%d more)" % (len(parts) - limit)
    return ", ".join(parts)


def json_one(kind, value, objtype=None, pid=None):
    """JSON-safe pair of raw and decoded value."""
    if kind == "bit-string":
        raw = value
    elif kind == "octet-string":
        raw = value.hex()
    elif kind in ("date", "time", "object-identifier"):
        raw = list(value)
    else:
        raw = value
    return {"type": kind, "raw": raw, "text": fmt_one(kind, value, objtype, pid)}


def table(rows, headers):
    """Plain aligned table, house style: no box drawing, two spaces between columns."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    srows = []
    for r in rows:
        cells = [("" if c is None else str(c)) for c in r]
        cells += [""] * (cols - len(cells))
        srows.append(cells)
        for k in range(cols):
            widths[k] = max(widths[k], len(cells[k]))
    out = ["  ".join(h.ljust(widths[k]) for k, h in enumerate(headers)).rstrip()]
    out.append("  ".join("-" * widths[k] for k in range(cols)))
    for cells in srows:
        out.append("  ".join(cells[k].ljust(widths[k]) for k in range(cols)).rstrip())
    return "\n".join(out)


# ------------------------------------------------------------------ transport

class Link(object):
    """One UDP socket doing BACnet/IP. Read-only: see _assert_read_only."""

    def __init__(self, bind_ip, local_port, remote_port, timeout, delay,
                 broadcast=None, verbose=False):
        self.remote_port = remote_port
        self.timeout = timeout
        self.delay = delay
        self.broadcast = broadcast
        self.verbose = verbose
        self.invoke = 0
        self.sent = 0
        self.received = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            self.sock.bind((bind_ip, local_port))
        except OSError as exc:
            self.sock.close()
            if exc.errno == errno.EADDRINUSE:
                raise Fatal(
                    "UDP port %d on %s is already in use.\n"
                    "Something else on this machine holds the BACnet port — Workbench, a\n"
                    "station, a BACnet stack, or another copy of this tool. Devices reply to\n"
                    "whatever source port we send from, so `--local-port %d` normally just\n"
                    "works; only broadcast I-Am replies aimed at %d would be missed."
                    % (local_port, bind_ip or "0.0.0.0", local_port + 1, local_port))
            if exc.errno in (errno.EADDRNOTAVAIL, errno.ENODEV):
                raise Fatal("cannot bind to %s: no interface on this machine has that "
                            "address." % (bind_ip or "0.0.0.0"))
            raise Fatal("cannot bind UDP %s:%d: %s" % (bind_ip or "0.0.0.0", local_port, exc))
        self.bound = self.sock.getsockname()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def next_invoke(self):
        self.invoke = (self.invoke + 1) & 0xFF
        return self.invoke

    # -- sending ----------------------------------------------------------

    def _send(self, payload, addr, function):
        frame = bytes([BVLC_TYPE_BIP, function]) + struct.pack(">H", len(payload) + 4) + payload
        if self.verbose:
            sys.stderr.write("--> %s:%d  %s\n" % (addr[0], addr[1], frame.hex()))
        try:
            self.sock.sendto(frame, addr)
        except OSError as exc:
            raise Fatal("cannot send to %s:%d: %s" % (addr[0], addr[1], exc))
        self.sent += 1

    def send_who_is(self, low=None, high=None):
        apdu = bytearray([0x10, SERVICE_WHO_IS])
        if low is not None and high is not None:
            apdu += enc_context_unsigned(0, low) + enc_context_unsigned(1, high)
        npdu = b"\x01\x00"      # version 1, no destination specifier, no reply expected
        target = (self.broadcast or "255.255.255.255", self.remote_port)
        self._send(npdu + bytes(apdu), target, BVLC_ORIGINAL_BROADCAST)

    def send_read_property(self, ip, objtype, instance, pid, index=None, port=None):
        _assert_read_only(SERVICE_READ_PROPERTY)
        invoke = self.next_invoke()
        # Confirmed-Request-PDU: no SEG, no MOR, and deliberately no SA bit —
        # we do not accept segmented responses, so a device with too much to say
        # must answer Abort(segmentation-not-supported) rather than fragment.
        apdu = bytearray([0x00, 0x05, invoke, SERVICE_READ_PROPERTY])
        apdu += enc_context_objid(0, objtype, instance)
        apdu += enc_context_unsigned(1, pid)
        if index is not None:
            apdu += enc_context_unsigned(2, index)
        npdu = b"\x01\x04"      # version 1, reply expected, normal priority
        self._send(npdu + bytes(apdu), (ip, port or self.remote_port),
                   BVLC_ORIGINAL_UNICAST)
        return invoke

    def send_abort(self, ip, invoke, reason, port=None):
        """Transaction-layer Abort. Carries no service and no data."""
        apdu = bytes([0x70, invoke, reason])     # SRV=0: we are the client
        self._send(b"\x01\x00" + apdu, (ip, port or self.remote_port),
                   BVLC_ORIGINAL_UNICAST)

    # -- receiving --------------------------------------------------------

    def recv_frames(self, deadline):
        """Yield (source_addr, npdu_info, apdu_bytes) until the deadline."""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            self.sock.settimeout(left)
            try:
                data, addr = self.sock.recvfrom(1500)
            except socket.timeout:
                return
            except OSError as exc:
                if exc.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
                    # An ICMP error queued against our connectionless socket.
                    continue
                return
            self.received += 1
            if self.verbose:
                sys.stderr.write("<-- %s:%d  %s\n" % (addr[0], addr[1], data.hex()))
            try:
                parsed = parse_frame(data)
            except BacnetDecodeError as exc:
                if self.verbose:
                    sys.stderr.write("    ignored (%s)\n" % exc)
                continue
            if parsed is None:
                continue
            npdu_info, apdu = parsed
            if npdu_info.get("origin"):
                addr = npdu_info["origin"]
            yield addr, npdu_info, apdu


class Fatal(Exception):
    """A condition with a field explanation, printed without a traceback."""


def _assert_read_only(service_choice):
    if service_choice not in ALLOWED_CONFIRMED_SERVICES:
        raise Fatal("refusing to encode confirmed service %r: this tool is read-only "
                    "and only ReadProperty (12) is permitted." % (service_choice,))


def parse_frame(data):
    """BVLC + NPDU. Returns (npdu_info, apdu) or None for frames we do not handle."""
    if len(data) < 4:
        raise BacnetDecodeError("short frame (%d octets)" % len(data))
    if data[0] != BVLC_TYPE_BIP:
        raise BacnetDecodeError("not BACnet/IP (first octet 0x%02x)" % data[0])
    func = data[1]
    length = struct.unpack(">H", data[2:4])[0]
    if length != len(data):
        # Trailing or truncated: trust the smaller of the two so we never over-read.
        length = min(length, len(data))
    i = 4
    info = {"bvlc_function": func}
    if func == BVLC_FORWARDED:
        if length < 10:
            raise BacnetDecodeError("forwarded-NPDU too short")
        info["origin"] = (socket.inet_ntoa(data[4:8]), struct.unpack(">H", data[8:10])[0])
        i = 10
    elif func not in (BVLC_ORIGINAL_UNICAST, BVLC_ORIGINAL_BROADCAST):
        return None                     # BVLC-Result, BDT/FDT management: not ours
    if i + 2 > length:
        raise BacnetDecodeError("no NPDU")
    version = data[i]
    control = data[i + 1]
    i += 2
    if version != 1:
        raise BacnetDecodeError("NPDU version %d, expected 1" % version)
    if control & 0x20:
        if i + 3 > length:
            raise BacnetDecodeError("truncated DNET")
        info["dnet"] = struct.unpack(">H", data[i:i + 2])[0]
        dlen = data[i + 2]
        i += 3 + dlen
    if control & 0x08:
        if i + 3 > length:
            raise BacnetDecodeError("truncated SNET")
        info["snet"] = struct.unpack(">H", data[i:i + 2])[0]
        slen = data[i + 2]
        info["sadr"] = data[i + 3:i + 3 + slen].hex()
        i += 3 + slen
    if control & 0x20:
        i += 1                          # hop count follows SADR
    if control & 0x80:
        info["network_message"] = data[i] if i < length else None
        return None                     # network-layer message, no APDU
    if i >= length:
        raise BacnetDecodeError("no APDU after NPDU")
    return info, data[i:length]


# ---------------------------------------------------------------- APDU decode

def decode_apdu(apdu):
    """Classify an APDU. Returns a dict; never raises on bad bytes."""
    try:
        if not apdu:
            raise BacnetDecodeError("empty APDU")
        ptype = (apdu[0] & 0xF0) >> 4
        if ptype == PDU_UNCONFIRMED_REQ:
            if len(apdu) < 2:
                raise BacnetDecodeError("unconfirmed request truncated")
            return {"pdu": "unconfirmed", "service": apdu[1], "body": apdu[2:]}
        if ptype == PDU_COMPLEX_ACK:
            seg = bool(apdu[0] & 0x08)
            if len(apdu) < 3:
                raise BacnetDecodeError("complex ack truncated")
            invoke = apdu[1]
            i = 2
            if seg:
                i += 2
            if i >= len(apdu):
                raise BacnetDecodeError("complex ack has no service choice")
            return {"pdu": "complex-ack", "invoke": invoke, "segmented": seg,
                    "more": bool(apdu[0] & 0x04), "service": apdu[i], "body": apdu[i + 1:]}
        if ptype == PDU_SIMPLE_ACK:
            if len(apdu) < 3:
                raise BacnetDecodeError("simple ack truncated")
            return {"pdu": "simple-ack", "invoke": apdu[1], "service": apdu[2]}
        if ptype == PDU_ERROR:
            if len(apdu) < 3:
                raise BacnetDecodeError("error pdu truncated")
            return {"pdu": "error", "invoke": apdu[1], "service": apdu[2], "body": apdu[3:]}
        if ptype == PDU_REJECT:
            if len(apdu) < 3:
                raise BacnetDecodeError("reject pdu truncated")
            return {"pdu": "reject", "invoke": apdu[1], "reason": apdu[2]}
        if ptype == PDU_ABORT:
            if len(apdu) < 3:
                raise BacnetDecodeError("abort pdu truncated")
            return {"pdu": "abort", "invoke": apdu[1], "reason": apdu[2],
                    "server": bool(apdu[0] & 0x01)}
        if ptype == PDU_CONFIRMED_REQ:
            return {"pdu": "confirmed-request"}
        if ptype == PDU_SEGMENT_ACK:
            return {"pdu": "segment-ack", "invoke": apdu[1] if len(apdu) > 1 else None}
        return {"pdu": "pdu-type-%d" % ptype}
    except BacnetDecodeError as exc:
        return {"pdu": "malformed", "why": str(exc)}


def decode_error_body(body):
    """Error-PDU payload -> (class_text, code_text). Tolerates wrapped forms."""
    try:
        values, _ = dec_app_values(body, 0)
    except BacnetDecodeError as exc:
        return "?", "undecodable error payload (%s)" % exc
    nums = [v for k, v in values if k in ("enumerated", "unsigned")]
    if len(nums) < 2:
        return "?", "error PDU carried %d enumerated values, expected 2" % len(nums)
    cls, code = nums[0], nums[1]
    return (ERROR_CLASS.get(cls, "error-class-%d" % cls),
            ERROR_CODE.get(code, "error-code-%d" % code))


def decode_i_am(body):
    """I-Am service data -> dict, or None if it does not parse."""
    try:
        values, _ = dec_app_values(body, 0)
    except BacnetDecodeError:
        return None
    oid = next((v for k, v in values if k == "object-identifier"), None)
    if oid is None or oid[0] != 8:
        return None
    nums = [v for k, v in values if k in ("unsigned", "enumerated")]
    out = {"device": oid[1], "max_apdu": None, "segmentation": None, "vendor": None}
    if len(nums) >= 1:
        out["max_apdu"] = nums[0]
    if len(nums) >= 2:
        out["segmentation"] = nums[1]
    if len(nums) >= 3:
        out["vendor"] = nums[2]
    return out


# ------------------------------------------------------------- ReadProperty op

def read_property(link, ip, objtype, instance, pid, index=None, retries=0, port=None):
    """One ReadProperty transaction. Returns a result dict, never raises on wire data.

    result["status"] is one of: ok, error, reject, abort, timeout, malformed.

    `port` is the UDP port to talk to, when it is not the one we are sweeping.
    A device answers from whatever port it is bound to, and a BBMD-forwarded
    I-Am carries an origin port that need not be 47808; the address a reply
    actually came from is better information than the port we guessed.
    """
    attempts = retries + 1
    for attempt in range(attempts):
        invoke = link.send_read_property(ip, objtype, instance, pid, index, port)
        deadline = time.monotonic() + link.timeout
        for addr, _npdu, apdu in link.recv_frames(deadline):
            if addr[0] != ip:
                continue
            d = decode_apdu(apdu)
            if d.get("invoke") != invoke:
                continue
            if d["pdu"] == "complex-ack":
                if d["segmented"]:
                    link.send_abort(ip, invoke, 4, port)
                    return {"status": "abort", "reason": 4,
                            "text": "device wanted to segment the response; "
                                    "segmentation-not-supported was sent back",
                            "segmented_by_device": True}
                return decode_read_property_ack(d["body"], objtype, pid)
            if d["pdu"] == "error":
                cls, code = decode_error_body(d.get("body", b""))
                return {"status": "error", "class": cls, "code": code,
                        "text": "Error: %s / %s" % (cls, code)}
            if d["pdu"] == "reject":
                r = d["reason"]
                return {"status": "reject", "reason": r,
                        "text": "Reject: %s" % REJECT_REASON.get(r, "reject-reason-%d" % r)}
            if d["pdu"] == "abort":
                r = d["reason"]
                name = ABORT_REASON.get(r, "abort-reason-%d" % r)
                extra = ""
                if r == 4:
                    extra = (" — the answer does not fit one unsegmented APDU. "
                             "Read it element by element with --index.")
                return {"status": "abort", "reason": r,
                        "text": "Abort: %s%s" % (name, extra)}
            if d["pdu"] == "malformed":
                return {"status": "malformed", "text": "undecodable reply: %s" % d["why"]}
            if d["pdu"] == "simple-ack":
                return {"status": "malformed",
                        "text": "device answered SimpleACK to a ReadProperty"}
        if attempt + 1 < attempts:
            time.sleep(link.delay)
    return {"status": "timeout",
            "text": "no reply in %.1fs" % (link.timeout * attempts)}


def decode_read_property_ack(body, objtype_hint, pid_hint):
    """ReadProperty-ACK payload -> result dict."""
    try:
        i = 0
        number, context, kind, data, i = dec_tag(body, i)
        if not (context and number == 0 and kind == "primitive" and len(data) == 4):
            raise BacnetDecodeError("ACK does not start with an object identifier")
        raw = struct.unpack(">I", data)[0]
        objtype, instance = (raw >> 22) & 0x3FF, raw & 0x3FFFFF
        number, context, kind, data, i = dec_tag(body, i)
        if not (context and number == 1):
            raise BacnetDecodeError("ACK has no property identifier")
        pid = int.from_bytes(data, "big") if data else 0
        index = None
        number, context, kind, data, j = dec_tag(body, i)
        if context and number == 2 and kind == "primitive":
            index = int.from_bytes(data, "big") if data else 0
            i = j
            number, context, kind, data, j = dec_tag(body, i)
        if not (context and number == 3 and kind == "opening"):
            raise BacnetDecodeError("ACK has no opening tag 3 around the value")
        values, _ = dec_app_values(body, j, stop_context=3)
        return {"status": "ok", "objtype": objtype, "instance": instance,
                "property": pid, "index": index, "values": values,
                "text": fmt_values(values, objtype, pid)}
    except BacnetDecodeError as exc:
        return {"status": "malformed", "text": "undecodable ReadProperty-ACK: %s" % exc}
    except (struct.error, IndexError) as exc:
        return {"status": "malformed", "text": "undecodable ReadProperty-ACK: %s" % exc}


def read_text(link, ip, objtype, instance, pid, retries=0, port=None):
    """Read a property expected to be a single value; return (text, ok)."""
    r = read_property(link, ip, objtype, instance, pid, retries=retries, port=port)
    if r["status"] == "ok":
        return r["text"], True
    return r["text"], False


# ----------------------------------------------------------------- arg parsing

def parse_objid(spec):
    """'analog-input:1', 'ai:1', '0:1' -> (0, 1)."""
    if ":" not in spec:
        raise Fatal("object must look like analog-input:1 (got %r)" % spec)
    tname, _, inst = spec.rpartition(":")
    tname = tname.strip().lower().replace("_", "-")
    try:
        instance = int(inst)
    except ValueError:
        raise Fatal("object instance %r is not a number" % inst)
    if not 0 <= instance <= 0x3FFFFF:
        raise Fatal("object instance %d is outside 0..4194303" % instance)
    if tname in OBJECT_TYPE_BY_NAME:
        return OBJECT_TYPE_BY_NAME[tname], instance
    if tname in OBJECT_TYPE_ALIASES:
        return OBJECT_TYPE_ALIASES[tname], instance
    if tname.isdigit():
        return int(tname), instance
    raise Fatal("unknown object type %r. Known names: %s (or a number)"
                % (tname, ", ".join(sorted(OBJECT_TYPE_BY_NAME)[:8]) + ", ..."))


def parse_property(spec):
    s = spec.strip().lower().replace("_", "-")
    if s in PROPERTY_BY_NAME:
        return PROPERTY_BY_NAME[s]
    if s.isdigit():
        return int(s)
    raise Fatal("unknown property %r. Try object-name, present-value, units, "
                "description, object-list, or a number." % spec)


def iface_addresses(name):
    """(address, broadcast) for an interface, from the kernel. Linux only."""
    try:
        import fcntl
    except ImportError:
        raise Fatal("--iface needs the fcntl module (Linux); use --bind <ip> instead.")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name.encode()[:15])
        try:
            addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])
        except OSError:
            raise Fatal("interface %r has no IPv4 address (or does not exist). "
                        "`ip -4 addr` lists what does." % name)
        try:
            bcast = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8919, packed)[20:24])
        except OSError:
            bcast = None
        return addr, bcast
    finally:
        s.close()


def open_link(a):
    bind_ip = a.bind or ""
    broadcast = a.broadcast
    if a.iface:
        addr, bcast = iface_addresses(a.iface)
        bind_ip = a.bind or addr
        if not broadcast:
            broadcast = bcast
    local_port = a.local_port if a.local_port is not None else a.port
    return Link(bind_ip, local_port, a.port, a.timeout, a.delay,
                broadcast=broadcast, verbose=a.verbose)


NOTHING_ANSWERED = (
    "Nothing answered.\n"
    "That is not proof the network is empty. In order of how often it is the cause:\n"
    "  * wrong subnet — BACnet/IP discovery is a local broadcast and does not cross a\n"
    "    router. Put this machine on the controllers' subnet, or point --broadcast at\n"
    "    the right directed-broadcast address (e.g. --broadcast 10.20.30.255).\n"
    "  * the devices are MS/TP behind a BACnet router, so they have no IP of their own.\n"
    "    They can only be reached through that router's network number, which this tool\n"
    "    does not do.\n"
    "  * a BBMD is required: on a routed site, discovery needs foreign-device\n"
    "    registration with the BBMD. Not supported here.\n"
    "  * host firewall dropping inbound UDP %d, or a wireless link that does not pass\n"
    "    broadcast.\n"
    "  * wrong port: some sites run 47809 or 0xBAC1+. Try --port 47809.\n")


# --------------------------------------------------------------- subcommands

def cmd_discover(a):
    link = open_link(a)
    try:
        sys.stderr.write("Who-Is from %s:%d -> %s:%d, listening %.1fs\n"
                         % (link.bound[0] or "0.0.0.0", link.bound[1],
                            link.broadcast or "255.255.255.255", a.port, a.timeout))
        found = {}
        attempts = a.retries + 1
        for attempt in range(attempts):
            link.send_who_is(a.low, a.high)
            deadline = time.monotonic() + a.timeout
            for addr, npdu, apdu in link.recv_frames(deadline):
                d = decode_apdu(apdu)
                if d["pdu"] != "unconfirmed" or d.get("service") != SERVICE_I_AM:
                    continue
                iam = decode_i_am(d["body"])
                if iam is None:
                    continue
                # Keyed by instance AND address, not instance alone. Two
                # devices shipped with the same device instance is a real and
                # common site fault, and a tool that de-duplicates by instance
                # hides exactly the thing you most need to see.
                key = (iam["device"], addr)
                if key in found:
                    continue
                iam["address"] = "%s:%d" % (addr[0], addr[1])
                iam["ip"] = addr[0]
                iam["port"] = addr[1]
                iam["routed"] = ("snet" in npdu)
                iam["snet"] = npdu.get("snet")
                iam["sadr"] = npdu.get("sadr")
                found[key] = iam
                if a.limit and len(found) >= a.limit:
                    break
            if a.limit and len(found) >= a.limit:
                break
        if not found:
            sys.stderr.write("\n" + NOTHING_ANSWERED % a.port)
            return 3
        devices = [found[k] for k in sorted(found)]
        # One instance answering from more than one address: flag every row.
        seen = {}
        for dev in devices:
            seen.setdefault(dev["device"], []).append(dev["address"])
        duplicates = dict((d, a) for d, a in seen.items() if len(a) > 1)
        for dev in devices:
            others = [a for a in duplicates.get(dev["device"], [])
                      if a != dev["address"]]
            dev["duplicate_instance"] = others
        if not a.no_names:
            for dev in devices:
                if dev["routed"]:
                    continue
                time.sleep(a.delay)
                dev["object_name"], _ = read_text(link, dev["ip"], 8, dev["device"],
                                                  77, port=dev["port"])
                time.sleep(a.delay)
                dev["model_name"], _ = read_text(link, dev["ip"], 8, dev["device"],
                                                 70, port=dev["port"])
        if a.json:
            print(json.dumps({"tool": "bacnet-sweep", "command": "discover",
                              "our_device_instance": a.device_id,
                              "devices": devices}, indent=2, sort_keys=True))
            return 0
        rows = []
        for dev in devices:
            seg = dev["segmentation"]
            # Notes accumulate: a device can be routed AND a duplicate, and
            # dropping either fact would be the worse of the two mistakes.
            notes = []
            if dev["duplicate_instance"]:
                notes.append("DUPLICATE device instance — also claimed by %s"
                             % ", ".join(dev["duplicate_instance"]))
            if dev["device"] == UNCONFIGURED_INSTANCE:
                notes.append("instance %d means 'unconfigured' — this device has "
                             "never been given one" % UNCONFIGURED_INSTANCE)
            if dev["routed"]:
                notes.append("routed via network %s addr %s — not readable by this "
                             "tool" % (dev["snet"], dev["sadr"]))
            note = "; ".join(notes)
            rows.append([dev["device"], dev["address"], dev["vendor"],
                         dev["max_apdu"],
                         SEGMENTATION.get(seg, "segmentation-%s" % seg),
                         dev.get("object_name", "-"), dev.get("model_name", "-"),
                         note])
        print(table(rows, ["device", "address", "vendor", "max-apdu",
                           "segmentation", "object-name", "model-name", "note"]))
        print("\n%d device(s) answered. Vendor ids are numbers assigned by ASHRAE; this "
              "tool does not ship the vendor-id list." % len(devices))
        if duplicates:
            print("%d device instance(s) were claimed from more than one address: %s.\n"
                  "That is a site fault, not a fault here — two controllers with the "
                  "same\ninstance number will fight over every request addressed to "
                  "it by instance." % (len(duplicates),
                                       ", ".join(str(d) for d in sorted(duplicates))))
        return 0
    finally:
        link.close()


def cmd_read(a):
    objtype, instance = parse_objid(a.object)
    pid = parse_property(a.property)
    link = open_link(a)
    try:
        r = read_property(link, a.ip, objtype, instance, pid, a.index, a.retries)
        if a.json:
            out = dict(r)
            if r["status"] == "ok":
                out["values"] = [json_one(k, v, objtype, pid) for k, v in r["values"]]
            out.update({"tool": "bacnet-sweep", "command": "read", "ip": a.ip,
                        "object": objid_str(objtype, instance),
                        "property_requested": property_name(pid),
                        "our_device_instance": a.device_id})
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0 if r["status"] == "ok" else 4
        head = "%s  %s  %s" % (a.ip, objid_str(objtype, instance), property_name(pid))
        if a.index is not None:
            head += "[%d]" % a.index
        print(head)
        if r["status"] == "ok":
            n = len(r["values"])
            print("  %s" % fmt_values(r["values"], objtype, r["property"], a.limit or None))
            if n > 1:
                print("  (%d elements)" % n)
            return 0
        print("  %s" % r["text"])
        if r["status"] == "timeout":
            print("  Nothing at %s:%d answered this request. If `discover` found the\n"
                  "  device, the address is right and the object or property is not —\n"
                  "  some controllers drop requests for objects they do not have instead\n"
                  "  of answering with an error." % (a.ip, a.port))
        return 4
    finally:
        link.close()


def cmd_points(a):
    link = open_link(a)
    started = time.monotonic()
    try:
        dev = a.device_instance
        sys.stderr.write("Reading object-list of device:%d at %s:%d\n" % (dev, a.ip, a.port))
        listing = read_property(link, a.ip, 8, dev, 76, retries=a.retries)
        objects = []
        if listing["status"] == "ok":
            objects = [v for k, v in listing["values"] if k == "object-identifier"]
        elif listing["status"] == "abort" and listing.get("reason") == 4:
            sys.stderr.write("  object-list does not fit one APDU; reading it element by "
                             "element with --index (this is the slow path)\n")
            count = read_property(link, a.ip, 8, dev, 76, index=0, retries=a.retries)
            if count["status"] != "ok" or not count["values"]:
                print("Device %d refused the whole object-list (%s) and would not give the\n"
                      "element count either (%s). This device needs a client that reassembles\n"
                      "segmented responses; this tool does not." % (dev, listing["text"],
                                                                    count["text"]))
                return 5
            total = count["values"][0][1]
            sys.stderr.write("  object-list has %s elements\n" % total)
            for n in range(1, int(total) + 1):
                if a.limit and len(objects) >= a.limit:
                    break
                time.sleep(a.delay)
                el = read_property(link, a.ip, 8, dev, 76, index=n, retries=a.retries)
                if el["status"] == "ok":
                    objects += [v for k, v in el["values"] if k == "object-identifier"]
        else:
            print("Could not read the object-list of device:%d at %s: %s"
                  % (dev, a.ip, listing["text"]))
            if listing["status"] == "timeout":
                print("Run `discover` first: the device instance and the IP have to match "
                      "the same box, and this device instance may live somewhere else.")
            return 5
        if not objects:
            print("device:%d at %s reports an empty object-list. That is legal but unusual; "
                  "on most controllers it means the device object instance is wrong."
                  % (dev, a.ip))
            return 5
        if a.limit:
            objects = objects[:a.limit]
        rows = []
        for objtype, instance in objects:
            time.sleep(a.delay)
            name = read_property(link, a.ip, objtype, instance, 77, retries=a.retries)
            notes = []
            if name["status"] != "ok":
                notes.append("object-name: %s" % name["text"])
            time.sleep(a.delay)
            pv = read_property(link, a.ip, objtype, instance, 85, retries=a.retries)
            if pv["status"] != "ok":
                notes.append("present-value: %s" % pv["text"])
            units_text = ""
            units_raw = None
            if objtype not in BINARY_TYPES + (8,):
                time.sleep(a.delay)
                un = read_property(link, a.ip, objtype, instance, 117, retries=a.retries)
                if un["status"] == "ok":
                    units_text = un["text"]
                    units_raw = un["values"][0][1] if un["values"] else None
                else:
                    notes.append("units: %s" % un["text"])
            elif objtype in BINARY_TYPES:
                units_text = "(binary)"
            rows.append({
                "object": objid_str(objtype, instance),
                "objtype": objtype, "instance": instance,
                "name": name["text"] if name["status"] == "ok" else "",
                "present_value": pv["text"] if pv["status"] == "ok" else "",
                "units": units_text, "units_raw": units_raw,
                "note": "; ".join(notes),
            })
        if a.json:
            print(json.dumps({"tool": "bacnet-sweep", "command": "points",
                              "ip": a.ip, "device": dev,
                              "our_device_instance": a.device_id,
                              "points": rows}, indent=2, sort_keys=True))
            return 0
        if a.csv:
            w = csv.writer(sys.stdout, lineterminator="\n")
            w.writerow(["device", "object", "instance", "object-name",
                        "present-value", "units", "note"])
            for r in rows:
                w.writerow([dev, r["object"], r["instance"], r["name"],
                            r["present_value"], r["units"], r["note"]])
            return 0
        print(table([[r["object"], r["name"], r["present_value"], r["units"], r["note"]]
                     for r in rows],
                    ["object", "object-name", "present-value", "units", "note"]))
        bad = sum(1 for r in rows if r["note"])
        print("\n%d object(s) on device:%d at %s. %d row(s) carry a note: a note is the "
              "device's own answer, not a failure of the sweep — objects legitimately "
              "lack present-value or units." % (len(rows), dev, a.ip, bad))
        print("%d properties were read one at a time, %.2fs apart; every value is a "
              "snapshot at its own instant, not a synchronised sample."
              % (link.sent, a.delay))
        sys.stderr.write("done in %.1fs\n" % (time.monotonic() - started))
        return 0
    finally:
        link.close()


EPILOG = """\
read-only, and enforced:
  The only services this tool can encode are Who-Is (unconfirmed 8) and
  ReadProperty (confirmed 12). There is no WriteProperty, no
  WritePropertyMultiple, no ReinitializeDevice, no DeviceCommunicationControl,
  no TimeSynchronization, no AtomicWriteFile and no COV subscription anywhere in
  the file; _assert_read_only() raises before any socket write if a service
  other than ReadProperty is ever passed to the request builder. Nothing this
  tool sends can change a value, a schedule, a program or a device's state.
  The one exception to "two services" is an Abort PDU, which is a
  transaction-layer PDU carrying no service and no data; it is sent only to
  close out a device that offered a segmented response.

known limits (see the module docstring for the full list):
  local IP subnet only, no BBMD and no foreign-device registration; no
  network-layer routing, so MS/TP devices behind a BACnet router are listed but
  not readable; segmented responses are refused, not reassembled (use --index).

examples:
  bacnet-sweep.py discover --iface eth0
  bacnet-sweep.py discover --broadcast 10.20.30.255 --timeout 5 --retries 1
  bacnet-sweep.py read 10.20.30.41 analog-input:1 present-value
  bacnet-sweep.py read 10.20.30.41 device:260001 object-list --index 0
  bacnet-sweep.py points 10.20.30.41 260001 --csv > site-points.csv
"""


def add_common(p):
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="BACnet/IP UDP port on the devices (default %d / 0xBAC0)" % DEFAULT_PORT)
    p.add_argument("--local-port", type=int, default=None,
                   help="UDP port to bind locally (default: same as --port)")
    p.add_argument("--bind", default=None, metavar="IP",
                   help="local IP to send from (default: all interfaces)")
    p.add_argument("--iface", default=None, metavar="NAME",
                   help="take the local IP and broadcast address from this interface")
    p.add_argument("--broadcast", default=None, metavar="ADDR",
                   help="broadcast address for Who-Is (default: the interface's, "
                        "else 255.255.255.255)")
    p.add_argument("--timeout", type=float, default=3.0, metavar="S",
                   help="seconds to wait for each answer (default 3)")
    p.add_argument("--retries", type=int, default=0, metavar="N",
                   help="extra attempts per request (default 0: one Who-Is, one try "
                        "per read)")
    p.add_argument("--delay", type=float, default=0.05, metavar="S",
                   help="pause between consecutive reads, to stay polite on a live "
                        "network (default 0.05)")
    p.add_argument("--device-id", type=int, default=UNCONFIGURED_INSTANCE, metavar="N",
                   help="our own device instance. Default 4194303 is the "
                        "standard's 'unconfigured' instance, which is what we "
                        "are. Recorded in --json output only: "
                        "neither Who-Is nor ReadProperty carries a source device "
                        "instance, and this tool never announces itself with an I-Am.")
    p.add_argument("--limit", type=int, default=0, metavar="N",
                   help="stop after N devices / points / list elements (0 = no limit)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--verbose", action="store_true",
                   help="hex-dump every frame sent and received to stderr")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="bacnet-sweep.py",
        description=__doc__.strip().split("\n")[0],
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("discover", help="broadcast Who-Is, table the I-Am replies",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--low", type=int, default=None,
                   help="restrict the Who-Is to device instances >= LOW")
    p.add_argument("--high", type=int, default=None,
                   help="restrict the Who-Is to device instances <= HIGH")
    p.add_argument("--no-names", action="store_true",
                   help="skip the two follow-up reads for object-name and model-name")
    add_common(p)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("read", help="ReadProperty one property of one object")
    p.add_argument("ip")
    p.add_argument("object", metavar="objtype:inst",
                   help="e.g. analog-input:1, bv:3, device:260001, 19:2")
    p.add_argument("property", help="e.g. present-value, object-name, units, 85")
    p.add_argument("--index", type=int, default=None, metavar="N",
                   help="array index. For object-list, 0 is the element count.")
    add_common(p)
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("points", help="list every object on a device with value and units")
    p.add_argument("ip")
    p.add_argument("device_instance", type=int, metavar="device-instance")
    p.add_argument("--csv", action="store_true",
                   help="CSV on stdout instead of a table (not with --json)")
    add_common(p)
    p.set_defaults(func=cmd_points)

    a = ap.parse_args(argv)
    if not getattr(a, "cmd", None):
        ap.print_help()
        return 2
    # Two output formats, one stdout. The usage line at the top of this file has
    # always read "[--csv | --json]", but until 2026-09-30 passing both printed
    # JSON and said nothing about it, so a script that asked for CSV and was
    # overruled had no way to find out. mqtt-tap refuses the same pair in the
    # same words.
    if getattr(a, "csv", False) and a.json:
        ap.error("choose one of --csv and --json")
    try:
        if a.cmd == "discover" and (a.low is None) != (a.high is None):
            raise Fatal("--low and --high go together: a Who-Is range needs both ends")
        return a.func(a)
    except Fatal as exc:
        sys.stderr.write("bacnet-sweep: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except OSError as exc:
        sys.stderr.write("bacnet-sweep: network error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as exc:
        sys.stderr.write("bacnet-sweep: %s\n" % exc)
        sys.exit(2)
