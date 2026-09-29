#!/usr/bin/env python3
"""A fake BACnet/IP device on loopback, so bacnet-sweep.py can be tested without hardware.

    tests/bacnet-fake-device.py --port 47810 [--bind 127.0.0.1] [--device 260001]

There is no BACnet equipment on this machine and none on the network, so the
only honest way to prove the sweep decodes real frames is to put real frames in
front of it. This process does that: it binds one UDP socket on the loopback
address, answers Who-Is with an I-Am, and answers ReadProperty for a small plant
of objects that looks like one AHU controller.

It refuses to bind anything but a loopback address unless
`--allow-non-loopback` is passed, because a fixture that answers I-Am on a real
site network is a hazard.

Why it is a fair test
---------------------
Every byte it emits is built here, from the wire rules in ASHRAE 135, by code
that does not import bacnet-sweep.py and shares nothing with it:

  * BVLC   6.3     0x81, function, 2-octet length over the whole frame
  * NPDU   6.2     version 0x01, control octet, optional DNET/SNET fields
  * APDU   20.1    PDU type in the top nibble of the first octet
  * tags   20.2    tag number, class bit, and the length/value/type nibble,
                   with the 0xF escape for tag numbers above 14 and the 5
                   escape for lengths above 4

The two sides also barely overlap: this file only ever encodes *server* PDUs
(I-Am, ComplexACK, Error, Reject, Abort) and bacnet-sweep.py only ever encodes
*client* PDUs (Who-Is, ReadProperty). Neither can pass the other's test by
sharing a bug in a shared encoder, because there is no shared encoder.

What it deliberately gets "wrong" in the client's favour
-------------------------------------------------------
* I-Am is framed as an Original-Broadcast-NPDU (function 0x0b), as a real device
  frames it, but is sent to the requester's address rather than to a broadcast
  address: loopback has no broadcast domain to put it on.
* Reading a property identifier in the proprietary range (>= 512) answers
  Reject(parameter-out-of-range) rather than Error(unknown-property). Real
  devices differ on this; the fixture picks Reject so the client's Reject
  decoding is exercised at all.
* Segmentation refusal is a real size decision, not a special case: the trend
  log's log-buffer is built as 200 genuine BACnetLogRecords, the encoded APDU
  comes out over 5 kB, the request did not set the segmented-response-accepted
  bit, so the answer is Abort(segmentation-not-supported) per 5.4.5.3. Nothing
  about that path is faked.
* --segment-responses makes the fixture misbehave on purpose: it segments an
  over-long response even though the request's SA bit was clear, which no
  compliant device does. It exists because a client's "a device segmented at me
  anyway" path is worth proving, and a stack in the field will eventually do it.
  Everything else here is what the standard says.

Three flags let it stand in for infrastructure rather than a device:
  --routed-from NET:HEXADDR   answers with SNET/SADR in the NPDU, as a BACnet
                              router does for a device on an MS/TP trunk
  --forwarded-from IP:PORT    wraps broadcast replies in a BVLC Forwarded-NPDU
                              carrying that origin, as a BBMD does. Refuses a
                              non-loopback origin: it would send the client
                              off this machine.
  --segment-responses         see above
"""

import argparse
import os
import select
import socket
import struct
import sys
import time

# ---------------------------------------------------------------- BVLC / NPDU

BVLC_FORWARDED = 0x04
BVLC_ORIGINAL_UNICAST = 0x0a
BVLC_ORIGINAL_BROADCAST = 0x0b

# ------------------------------------------------- application tag encoding
# 20.2.1.3.1: the length/value/type nibble carries the length directly for
# lengths 0..4; the value 5 means "an extended length octet follows".

def _minimal_unsigned(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _app(tag_number, body):
    if tag_number > 14:
        raise ValueError("this fixture never needs an extended application tag")
    first = tag_number << 4                     # class bit 0x08 clear: application
    if len(body) <= 4:
        return bytes([first | len(body)]) + body
    if len(body) <= 253:
        return bytes([first | 5, len(body)]) + body
    if len(body) <= 0xFFFF:
        return bytes([first | 5, 0xFE]) + struct.pack(">H", len(body)) + body
    return bytes([first | 5, 0xFF]) + struct.pack(">I", len(body)) + body


def app_null():
    return b"\x00"                              # tag 0, length 0


def app_boolean(v):
    return b"\x11" if v else b"\x10"            # tag 1: the value IS the length nibble


def app_unsigned(v):
    return _app(2, _minimal_unsigned(v))


def app_signed(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return _app(3, v.to_bytes(n, "big", signed=True))


def app_real(v):
    return _app(4, struct.pack(">f", v))        # IEEE-754 single, big endian


def app_double(v):
    return _app(5, struct.pack(">d", v))


def app_octetstring(b):
    return _app(6, bytes(b))


def app_charstring(s, charset=0):
    # 20.2.9: first content octet is the character set. 0 = UTF-8 (ANSI X3.4),
    # 5 = ISO 8859-1.
    if charset == 0:
        raw = s.encode("utf-8")
    elif charset == 5:
        raw = s.encode("iso-8859-1")
    else:
        raise ValueError("fixture only emits charset 0 and 5")
    return _app(7, bytes([charset]) + raw)


def app_bitstring(bits):
    # 20.2.10: first content octet is the count of unused bits in the last octet,
    # then the bits, most significant first.
    unused = (8 - (len(bits) % 8)) % 8
    octets = bytearray()
    for start in range(0, len(bits), 8):
        octet = 0
        for k, bit in enumerate(bits[start:start + 8]):
            if bit:
                octet |= 0x80 >> k
        octets.append(octet)
    return _app(8, bytes([unused]) + bytes(octets))


def app_enumerated(v):
    return _app(9, _minimal_unsigned(v))


def app_date(year, month, day, dow):
    # 20.2.12: year is offset from 1900; 255 means unspecified.
    return _app(10, bytes([year - 1900 if year != 255 else 255, month, day, dow]))


def app_time(h, m, s, hundredths):
    return _app(11, bytes([h, m, s, hundredths]))


def app_objid(objtype, instance):
    # 20.2.14: 10 bits of type, 22 bits of instance, in one 32-bit field.
    return _app(12, struct.pack(">I", ((objtype & 0x3FF) << 22) | (instance & 0x3FFFFF)))


# ------------------------------------------------------ context tag encoding

def ctx(tag_number, body):
    if tag_number > 14:
        raise ValueError("this fixture never needs an extended context tag")
    first = (tag_number << 4) | 0x08            # class bit set: context specific
    if len(body) <= 4:
        return bytes([first | len(body)]) + body
    if len(body) <= 253:
        return bytes([first | 5, len(body)]) + body
    return bytes([first | 5, 0xFE]) + struct.pack(">H", len(body)) + body


def ctx_open(tag_number):
    return bytes([(tag_number << 4) | 0x08 | 6])


def ctx_close(tag_number):
    return bytes([(tag_number << 4) | 0x08 | 7])


# ------------------------------------------------------------- the fake plant

DEV_INSTANCE_DEFAULT = 260001
VENDOR_ID = 999
MAX_APDU = 1476
SEGMENTATION_SUPPORTED = 3          # no-segmentation

AI, AO, AV, BI, BO, BV = 0, 1, 2, 3, 4, 5
DEVICE, MSI, MSO, NOTIFICATION_CLASS, SCHEDULE = 8, 13, 14, 15, 17
MSV, TREND_LOG = 19, 20
INTEGER_VALUE, LARGE_ANALOG_VALUE, OCTETSTRING_VALUE = 45, 46, 47

# property identifiers used below (ASHRAE 135 enumeration)
P_DESCRIPTION = 28
P_FIRMWARE_REVISION = 44
P_LOG_BUFFER = 131
P_LOCAL_DATE = 56
P_LOCAL_TIME = 57
P_MAX_APDU = 62
P_MODEL_NAME = 70
P_NUMBER_OF_STATES = 74
P_OBJECT_IDENTIFIER = 75
P_OBJECT_LIST = 76
P_OBJECT_NAME = 77
P_OBJECT_TYPE = 79
P_OUT_OF_SERVICE = 81
P_PRESENT_VALUE = 85
P_PRIORITY_ARRAY = 87
P_PROTOCOL_REVISION = 139
P_RELIABILITY = 103
P_RESOLUTION = 106
P_SEGMENTATION = 107
P_STATUS_FLAGS = 111
P_SYSTEM_STATUS = 112
P_UNITS = 117
P_VENDOR_ID = 120
P_VENDOR_NAME = 121

U_DEG_C = 62
U_DEG_F = 64
U_PASCALS = 53
U_KILOPASCALS = 54
U_PPM = 96
U_PERCENT = 98
U_LITERS_PER_SECOND = 87
U_KILOWATTS = 48
U_KILOWATT_HOURS = 19
U_SECONDS = 73
U_NO_UNITS = 95

ERR_CLASS_OBJECT, ERR_CLASS_PROPERTY = 1, 2
ERR_UNKNOWN_OBJECT, ERR_UNKNOWN_PROPERTY, ERR_INVALID_ARRAY_INDEX = 31, 32, 42

REJECT_PARAMETER_OUT_OF_RANGE = 6
ABORT_SEGMENTATION_NOT_SUPPORTED = 4


def build_objects(dev_instance):
    """The plant. Values are (encoder, args) so each is encoded on demand."""
    ol = [(DEVICE, dev_instance), (AI, 1), (AI, 2), (AI, 3), (AI, 4),
          (AV, 1), (AV, 2), (AV, 3), (AV, 4), (AV, 5), (BV, 1),
          (MSV, 1), (INTEGER_VALUE, 1), (LARGE_ANALOG_VALUE, 1),
          (OCTETSTRING_VALUE, 1), (SCHEDULE, 1), (NOTIFICATION_CLASS, 1),
          (TREND_LOG, 1)]
    objects = {}

    objects[(DEVICE, dev_instance)] = {
        P_OBJECT_IDENTIFIER: app_objid(DEVICE, dev_instance),
        P_OBJECT_NAME: app_charstring("PL-Fixture-AHU1"),
        P_OBJECT_TYPE: app_enumerated(DEVICE),
        P_DESCRIPTION: app_charstring("Bench fixture, not a real controller"),
        P_MODEL_NAME: app_charstring("FX-STUB-1"),
        P_VENDOR_NAME: app_charstring("Plantroom Labs (fixture)"),
        P_VENDOR_ID: app_unsigned(VENDOR_ID),
        P_FIRMWARE_REVISION: app_charstring("0.1-fixture"),
        P_MAX_APDU: app_unsigned(MAX_APDU),
        P_SEGMENTATION: app_enumerated(SEGMENTATION_SUPPORTED),
        P_PROTOCOL_REVISION: app_unsigned(14),
        P_SYSTEM_STATUS: app_enumerated(0),             # operational
        P_LOCAL_DATE: app_date(2026, 9, 27, 7),         # Sunday
        P_LOCAL_TIME: app_time(14, 35, 12, 0),
        P_OBJECT_LIST: b"".join(app_objid(t, i) for t, i in ol),
    }
    objects[(AI, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_SaTemp"),
        P_OBJECT_TYPE: app_enumerated(AI),
        P_DESCRIPTION: app_charstring("Supply air temperature"),
        P_PRESENT_VALUE: app_real(18.6),
        P_UNITS: app_enumerated(U_DEG_C),
        P_STATUS_FLAGS: app_bitstring([False, False, False, False]),
        P_RELIABILITY: app_enumerated(0),               # no-fault-detected
        P_OUT_OF_SERVICE: app_boolean(False),
        P_RESOLUTION: app_real(0.1),
    }
    objects[(AI, 2)] = {
        P_OBJECT_NAME: app_charstring("AHU1_SaStaticPress"),
        P_OBJECT_TYPE: app_enumerated(AI),
        # ISO 8859-1, not UTF-8: plenty of European controllers still do this.
        P_DESCRIPTION: app_charstring("Pression différentielle", charset=5),
        P_PRESENT_VALUE: app_real(245.0),
        P_UNITS: app_enumerated(U_PASCALS),
        P_STATUS_FLAGS: app_bitstring([False, False, False, False]),
    }
    objects[(AI, 3)] = {
        P_OBJECT_NAME: app_charstring("AHU1_RmCo2"),
        P_OBJECT_TYPE: app_enumerated(AI),
        P_PRESENT_VALUE: app_real(612.0),
        P_UNITS: app_enumerated(U_PPM),
        P_STATUS_FLAGS: app_bitstring([True, False, False, False]),   # in-alarm
    }
    objects[(AI, 4)] = {
        P_OBJECT_NAME: app_charstring("AHU1_RaTemp_F"),
        P_OBJECT_TYPE: app_enumerated(AI),
        P_DESCRIPTION: app_charstring("Return air temperature, imperial sensor"),
        P_PRESENT_VALUE: app_real(65.3),
        P_UNITS: app_enumerated(U_DEG_F),
        P_STATUS_FLAGS: app_bitstring([False, False, False, False]),
    }
    objects[(AV, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_FanSpeedCmd"),
        P_OBJECT_TYPE: app_enumerated(AV),
        P_PRESENT_VALUE: app_real(62.5),
        P_UNITS: app_enumerated(U_PERCENT),
        P_OUT_OF_SERVICE: app_boolean(False),
        # A priority array: 16 slots, all relinquished except priority 8.
        P_PRIORITY_ARRAY: b"".join(
            app_real(62.5) if slot == 8 else app_null() for slot in range(1, 17)),
    }
    objects[(AV, 2)] = {
        P_OBJECT_NAME: app_charstring("AHU1_ChwFlow"),
        P_OBJECT_TYPE: app_enumerated(AV),
        P_PRESENT_VALUE: app_real(1.85),
        P_UNITS: app_enumerated(U_LITERS_PER_SECOND),
    }
    objects[(AV, 3)] = {
        P_OBJECT_NAME: app_charstring("AHU1_HxPressDrop"),
        P_OBJECT_TYPE: app_enumerated(AV),
        P_PRESENT_VALUE: app_real(34.2),
        P_UNITS: app_enumerated(U_KILOPASCALS),
    }
    objects[(AV, 4)] = {
        P_OBJECT_NAME: app_charstring("AHU1_FanPower"),
        P_OBJECT_TYPE: app_enumerated(AV),
        P_PRESENT_VALUE: app_real(2.4),
        P_UNITS: app_enumerated(U_KILOWATTS),
    }
    objects[(AV, 5)] = {
        P_OBJECT_NAME: app_charstring("AHU1_PidOutRaw"),
        P_OBJECT_TYPE: app_enumerated(AV),
        P_PRESENT_VALUE: app_real(0.62),
        P_UNITS: app_enumerated(U_NO_UNITS),
    }
    objects[(BV, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_FanRun"),
        P_OBJECT_TYPE: app_enumerated(BV),
        P_PRESENT_VALUE: app_enumerated(1),             # active
        P_STATUS_FLAGS: app_bitstring([False, False, True, False]),   # overridden
        # no P_UNITS: binary objects have none, so a read answers unknown-property
    }
    objects[(MSV, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_OccMode"),
        P_OBJECT_TYPE: app_enumerated(MSV),
        P_PRESENT_VALUE: app_unsigned(2),
        P_NUMBER_OF_STATES: app_unsigned(3),
        P_STATUS_FLAGS: app_bitstring([False, False, False, False]),
    }
    objects[(INTEGER_VALUE, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_FrostStatDelay"),
        P_OBJECT_TYPE: app_enumerated(INTEGER_VALUE),
        P_PRESENT_VALUE: app_signed(-17),
        P_UNITS: app_enumerated(U_SECONDS),
    }
    objects[(LARGE_ANALOG_VALUE, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_ElecMeterTotal"),
        P_OBJECT_TYPE: app_enumerated(LARGE_ANALOG_VALUE),
        P_PRESENT_VALUE: app_double(1234567.89),
        P_UNITS: app_enumerated(U_KILOWATT_HOURS),
    }
    objects[(OCTETSTRING_VALUE, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_LastRawFrame"),
        P_OBJECT_TYPE: app_enumerated(OCTETSTRING_VALUE),
        P_PRESENT_VALUE: app_octetstring(b"\x01\x02\xde\xad\xbe\xef"),
    }
    objects[(SCHEDULE, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_OccSchedule"),
        P_OBJECT_TYPE: app_enumerated(SCHEDULE),
        P_PRESENT_VALUE: app_unsigned(1),
    }
    objects[(NOTIFICATION_CLASS, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_Alarms"),
        P_OBJECT_TYPE: app_enumerated(NOTIFICATION_CLASS),
        # no present-value: notification-class objects have none
    }
    objects[(TREND_LOG, 1)] = {
        P_OBJECT_NAME: app_charstring("AHU1_SaTemp_Log"),
        P_OBJECT_TYPE: app_enumerated(TREND_LOG),
        P_DESCRIPTION: app_charstring("15-minute log of AHU1_SaTemp"),
        P_LOG_BUFFER: log_buffer(200),
        # no present-value: trend logs have none
    }
    return objects, ol


def log_buffer(n):
    """`n` BACnetLogRecords, encoded per 12.25.14 / 21.

    BACnetLogRecord ::= SEQUENCE {
        timestamp   [0] BACnetDateTime,
        logDatum    [1] CHOICE { real-value [4] REAL, ... },
        statusFlags [2] BACnetStatusFlags OPTIONAL }

    200 of them is about 5 kB, which is the point: it cannot fit one
    unsegmented APDU, so an unsegmented reader must be told so.
    """
    out = bytearray()
    for k in range(n):
        minute = (k * 15) % 60
        hour = (6 + (k * 15) // 60) % 24
        out += ctx_open(0)
        out += app_date(2026, 9, 27, 7)
        out += app_time(hour, minute, 0, 0)
        out += ctx_close(0)
        out += ctx_open(1)
        out += ctx(4, struct.pack(">f", 18.0 + (k % 40) * 0.1))   # real-value choice
        out += ctx_close(1)
        out += ctx(2, bytes([4, 0x00]))              # status flags, 4 bits, none set
    return bytes(out)


# ----------------------------------------------------------------- server PDUs

def i_am(dev_instance):
    """Unconfirmed-Request(I-Am). 20.1.4 / 16.10."""
    return (bytes([0x10, 0x00])                  # PDU type 1, service 0 (i-Am)
            + app_objid(DEVICE, dev_instance)
            + app_unsigned(MAX_APDU)
            + app_enumerated(SEGMENTATION_SUPPORTED)
            + app_unsigned(VENDOR_ID))


def complex_ack_read_property(invoke, objtype, instance, pid, index, value_bytes):
    """ComplexACK(ReadProperty-ACK). 20.1.5 / 15.5.1.2."""
    head = bytes([0x30, invoke, 12])             # PDU type 3, no SEG, service 12
    body = ctx(0, struct.pack(">I", ((objtype & 0x3FF) << 22) | (instance & 0x3FFFFF)))
    body += ctx(1, _minimal_unsigned(pid))
    if index is not None:
        body += ctx(2, _minimal_unsigned(index))
    body += ctx_open(3) + value_bytes + ctx_close(3)
    return head + body


def segmented_complex_ack(invoke, sequence, window, service, chunk, more):
    """First segment of a segmented ComplexACK. 20.1.5, with SEG and MOR set.

    Deliberately non-compliant when the request had SA=0: no honest device
    segments a response the client never said it would accept. It exists so the
    client's "someone segmented at me anyway" path can be exercised, because
    that path is exactly the one a field engineer meets when a stack misbehaves.
    """
    first = 0x30 | 0x08 | (0x04 if more else 0x00)
    return bytes([first, invoke, sequence & 0xFF, window & 0xFF, service]) + chunk


def error_pdu(invoke, service, error_class, error_code):
    """Error-PDU. 20.1.7: two application-tagged enumerations."""
    return (bytes([0x50, invoke, service])
            + app_enumerated(error_class) + app_enumerated(error_code))


def reject_pdu(invoke, reason):
    """Reject-PDU. 20.1.9."""
    return bytes([0x60, invoke, reason])


def abort_pdu(invoke, reason, from_server=True):
    """Abort-PDU. 20.1.10; bit 0 of the first octet is the server flag."""
    return bytes([0x70 | (0x01 if from_server else 0x00), invoke, reason])


# ------------------------------------------------------------ request decoding

class Truncated(Exception):
    pass


def split_frame(data):
    """BVLC + NPDU -> (function, apdu). Raises Truncated on rubbish."""
    if len(data) < 4 or data[0] != 0x81:
        raise Truncated("not a BACnet/IP frame")
    func = data[1]
    length = struct.unpack(">H", data[2:4])[0]
    if length > len(data):
        raise Truncated("BVLC length %d > %d received" % (length, len(data)))
    i = 4
    if func == 0x04:                             # Forwarded-NPDU
        i = 10
    elif func not in (BVLC_ORIGINAL_UNICAST, BVLC_ORIGINAL_BROADCAST):
        raise Truncated("BVLC function 0x%02x not handled by this fixture" % func)
    if i + 2 > length:
        raise Truncated("no NPDU")
    if data[i] != 0x01:
        raise Truncated("NPDU version %d" % data[i])
    control = data[i + 1]
    i += 2
    if control & 0x20:                           # DNET/DLEN/DADR
        dlen = data[i + 2]
        i += 3 + dlen
    if control & 0x08:                           # SNET/SLEN/SADR
        slen = data[i + 2]
        i += 3 + slen
    if control & 0x20:
        i += 1                                   # hop count
    if control & 0x80:
        raise Truncated("network layer message, not an APDU")
    if i >= length:
        raise Truncated("no APDU")
    return func, data[i:length]


def read_tag(buf, i):
    """(tag_number, is_context, is_opening, is_closing, data, next) per 20.2.1."""
    if i >= len(buf):
        raise Truncated("tag past end")
    b = buf[i]
    i += 1
    num = b >> 4
    context = bool(b & 0x08)
    lvt = b & 0x07
    if num == 0x0F:
        if i >= len(buf):
            raise Truncated("extended tag number truncated")
        num = buf[i]
        i += 1
    if lvt == 6:
        return num, context, True, False, b"", i
    if lvt == 7:
        return num, context, False, True, b"", i
    if lvt == 5:
        n = buf[i]
        i += 1
        if n == 0xFE:
            if i + 2 > len(buf):
                raise Truncated("16-bit extended length truncated")
            n = struct.unpack(">H", buf[i:i + 2])[0]
            i += 2
        elif n == 0xFF:
            if i + 4 > len(buf):
                raise Truncated("32-bit extended length truncated")
            n = struct.unpack(">I", buf[i:i + 4])[0]
            i += 4
    else:
        n = lvt
    if i + n > len(buf):
        raise Truncated("tag %d wants %d octets" % (num, n))
    return num, context, False, False, buf[i:i + n], i + n


def parse_read_property(body):
    """ReadProperty-Request -> (objtype, instance, pid, index)."""
    i = 0
    num, context, _o, _c, data, i = read_tag(body, i)
    if num != 0 or not context or len(data) != 4:
        raise Truncated("no object identifier at context tag 0")
    raw = struct.unpack(">I", data)[0]
    objtype, instance = (raw >> 22) & 0x3FF, raw & 0x3FFFFF
    num, context, _o, _c, data, i = read_tag(body, i)
    if num != 1 or not context:
        raise Truncated("no property identifier at context tag 1")
    pid = int.from_bytes(data, "big") if data else 0
    index = None
    if i < len(body):
        num, context, _o, _c, data, i = read_tag(body, i)
        if num == 2 and context:
            index = int.from_bytes(data, "big") if data else 0
    return objtype, instance, pid, index


def parse_who_is(body):
    """(low, high) or (None, None) for an unrestricted Who-Is."""
    if not body:
        return None, None
    try:
        i = 0
        num, context, _o, _c, data, i = read_tag(body, i)
        if num != 0 or not context:
            return None, None
        low = int.from_bytes(data, "big")
        num, context, _o, _c, data, i = read_tag(body, i)
        if num != 1 or not context:
            return None, None
        return low, int.from_bytes(data, "big")
    except Truncated:
        return None, None


# ------------------------------------------------------------------ the server

class FakeDevice(object):
    def __init__(self, bind, port, dev_instance, verbose=False,
                 refuse_whole_object_list=False, max_apdu=MAX_APDU,
                 routed_from=None, forwarded_from=None, segment_responses=False,
                 twin=None):
        self.dev = dev_instance
        self.objects, self.object_list = build_objects(dev_instance)
        self.verbose = verbose
        self.refuse_whole_object_list = refuse_whole_object_list
        self.max_apdu = max_apdu
        self.routed_from = routed_from            # (snet, sadr bytes) or None
        self.forwarded_from = forwarded_from      # (ip, port) or None
        self.segment_responses = segment_responses
        self.stats = {"who_is": 0, "read": 0, "error": 0, "reject": 0,
                      "abort": 0, "segments": 0}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind, port))
        self.addr = self.sock.getsockname()
        # A second address claiming the SAME device instance: what a site looks
        # like when two controllers were commissioned from the same template.
        # Both sockets answer everything, and both answer Who-Is.
        self.socks = [self.sock]
        self.twin_addr = None
        if twin is not None:
            tsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tsock.bind(twin)
            self.socks.append(tsock)
            self.twin_addr = tsock.getsockname()
        # Which socket the request under way arrived on. Single-threaded, so an
        # attribute is enough and every send() reply goes back the way it came.
        self.cur_sock = self.sock

    def log(self, msg):
        if self.verbose:
            sys.stderr.write("fixture: %s\n" % msg)
            sys.stderr.flush()

    def send(self, apdu, addr, function=BVLC_ORIGINAL_UNICAST, sock=None):
        if self.routed_from is None:
            npdu = b"\x01\x00"                   # version 1, no routing, no reply expected
        else:
            # 6.2.2: SNET/SLEN/SADR present, so control bit 3 is set. This is
            # what a BACnet router puts in front of a frame it forwards on
            # behalf of a device on another network -- an MS/TP trunk, say.
            snet, sadr = self.routed_from
            npdu = (b"\x01\x08" + struct.pack(">H", snet)
                    + bytes([len(sadr)]) + sadr)
        payload = npdu + apdu
        if self.forwarded_from is not None and function == BVLC_ORIGINAL_BROADCAST:
            # Annex J.4.5: a BBMD forwarding a broadcast replaces the BVLC
            # function with Forwarded-NPDU and prepends the *originating*
            # device's address. Only broadcasts get this treatment; a unicast
            # reply comes straight back from the device, which is why this is
            # conditional and not applied to everything.
            oip, oport = self.forwarded_from
            head = (bytes([0x81, BVLC_FORWARDED])
                    + struct.pack(">H", len(payload) + 10)
                    + socket.inet_aton(oip) + struct.pack(">H", oport))
            frame = head + payload
        else:
            frame = (bytes([0x81, function])
                     + struct.pack(">H", len(payload) + 4) + payload)
        out = sock or self.cur_sock
        out.sendto(frame, addr)
        self.log("--> %s:%d %s (from :%d)"
                 % (addr[0], addr[1], frame.hex(), out.getsockname()[1]))

    def serve_forever(self):
        while True:
            try:
                ready, _, _ = select.select(self.socks, [], [], 0.5)
            except OSError:
                return
            for sock in ready:
                self.cur_sock = sock
                try:
                    data, addr = sock.recvfrom(1500)
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.log("<-- %s:%d %s (on :%d)"
                         % (addr[0], addr[1], data.hex(), sock.getsockname()[1]))
                self._dispatch(data, addr)

    def _dispatch(self, data, addr):
        try:
            self.handle(data, addr)
        except Truncated as exc:
            self.log("ignored: %s" % exc)
        except Exception as exc:                   # a fixture must not die on bad input
            self.log("internal: %r" % exc)

    def handle(self, data, addr):
        _func, apdu = split_frame(data)
        if not apdu:
            raise Truncated("empty APDU")
        ptype = apdu[0] >> 4
        if ptype == 1:                            # Unconfirmed-Request
            if len(apdu) < 2:
                raise Truncated("short unconfirmed request")
            if apdu[1] == 8:                      # Who-Is
                low, high = parse_who_is(apdu[2:])
                if low is not None and not (low <= self.dev <= high):
                    self.log("Who-Is %d..%d does not include %d" % (low, high, self.dev))
                    return
                self.stats["who_is"] += 1
                for sock in self.socks:
                    self.send(i_am(self.dev), addr, BVLC_ORIGINAL_BROADCAST, sock)
            else:
                self.log("unconfirmed service %d ignored" % apdu[1])
            return
        if ptype == 7:                            # Abort from the client: fine, drop it
            self.log("client aborted transaction %d (reason %d)"
                     % (apdu[1], apdu[2] if len(apdu) > 2 else -1))
            return
        if ptype != 0:                            # not a Confirmed-Request
            self.log("PDU type %d ignored" % ptype)
            return
        if len(apdu) < 4:
            raise Truncated("short confirmed request")
        segmented_response_accepted = bool(apdu[0] & 0x02)
        invoke = apdu[2]
        service = apdu[3]
        if service != 12:
            self.stats["reject"] += 1
            self.send(reject_pdu(invoke, 9), addr)          # unrecognized-service
            return
        self.stats["read"] += 1
        objtype, instance, pid, index = parse_read_property(apdu[4:])
        self.respond_read(addr, invoke, objtype, instance, pid, index,
                          segmented_response_accepted)

    def respond_read(self, addr, invoke, objtype, instance, pid, index, sa):
        key = (objtype, instance)
        if pid >= 512:
            # Proprietary property identifier: this fixture rejects rather than
            # answering, to exercise the client's Reject decoding.
            self.stats["reject"] += 1
            self.send(reject_pdu(invoke, REJECT_PARAMETER_OUT_OF_RANGE), addr)
            return
        if key not in self.objects:
            self.stats["error"] += 1
            self.send(error_pdu(invoke, 12, ERR_CLASS_OBJECT, ERR_UNKNOWN_OBJECT), addr)
            return
        props = self.objects[key]
        if pid not in props:
            self.stats["error"] += 1
            self.send(error_pdu(invoke, 12, ERR_CLASS_PROPERTY, ERR_UNKNOWN_PROPERTY), addr)
            return
        value = props[pid]
        if pid == P_OBJECT_LIST and objtype == DEVICE:
            value = self.object_list_value(invoke, addr, index)
            if value is None:
                return
            if index is not None:
                self.send(complex_ack_read_property(invoke, objtype, instance, pid,
                                                    index, value), addr)
                return
        elif index is not None:
            # Arrays other than object-list are not indexed in this fixture.
            if pid != P_PRIORITY_ARRAY:
                self.stats["error"] += 1
                self.send(error_pdu(invoke, 12, ERR_CLASS_PROPERTY,
                                    ERR_INVALID_ARRAY_INDEX), addr)
                return
        apdu = complex_ack_read_property(invoke, objtype, instance, pid, index, value)
        if len(apdu) > self.max_apdu and self.segment_responses:
            # Misbehave on purpose: segment regardless of what the client said.
            self.stats["segments"] += 1
            self.log("%d octet response for %s: segmenting (SA=%d) -- deliberate "
                     "misbehaviour, see --segment-responses" % (len(apdu), pid, sa))
            self.send(segmented_complex_ack(invoke, 0, 1, 12,
                                            apdu[3:3 + self.max_apdu], True), addr)
            return
        if len(apdu) > self.max_apdu and not sa:
            # 5.4.5.3: the response does not fit and the client did not say it
            # accepts segments, so the transaction is aborted, not fragmented.
            self.stats["abort"] += 1
            self.log("%d octet response for %s does not fit %d and SA=0 -> abort"
                     % (len(apdu), pid, self.max_apdu))
            self.send(abort_pdu(invoke, ABORT_SEGMENTATION_NOT_SUPPORTED), addr)
            return
        self.send(apdu, addr)

    def object_list_value(self, invoke, addr, index):
        """object-list, whole or by element. Returns None if a PDU was already sent."""
        if index is None:
            if self.refuse_whole_object_list:
                self.stats["abort"] += 1
                self.send(abort_pdu(invoke, ABORT_SEGMENTATION_NOT_SUPPORTED), addr)
                return None
            return b"".join(app_objid(t, i) for t, i in self.object_list)
        if index == 0:
            return app_unsigned(len(self.object_list))       # array element 0 is the count
        if 1 <= index <= len(self.object_list):
            t, i = self.object_list[index - 1]
            return app_objid(t, i)
        self.stats["error"] += 1
        self.send(error_pdu(invoke, 12, ERR_CLASS_PROPERTY, ERR_INVALID_ARRAY_INDEX), addr)
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--port", type=int, default=47810)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--device", type=int, default=DEV_INSTANCE_DEFAULT)
    ap.add_argument("--verbose", action="store_true", help="hex-dump frames to stderr")
    ap.add_argument("--refuse-whole-object-list", action="store_true",
                    help="abort an unindexed object-list read, forcing the "
                         "element-by-element path")
    ap.add_argument("--max-apdu", type=int, default=MAX_APDU,
                    help="response size above which an unsegmented reader is aborted")
    ap.add_argument("--routed-from", metavar="NET:HEXADDR", default=None,
                    help="answer as though reached through a BACnet router: "
                         "NPDU carries SNET/SADR, e.g. --routed-from 2001:07")
    ap.add_argument("--forwarded-from", metavar="IP:PORT", default=None,
                    help="wrap broadcast replies in a BVLC Forwarded-NPDU "
                         "claiming this origin address, the way a BBMD does")
    ap.add_argument("--segment-responses", action="store_true",
                    help="segment an over-long response instead of aborting it, "
                         "even though the client did not accept segments")
    ap.add_argument("--twin", metavar="IP:PORT", default=None,
                    help="answer from a second address as well, claiming the "
                         "same device instance: a duplicate-instance site fault")
    ap.add_argument("--allow-non-loopback", action="store_true",
                    help="permit binding a routable address (do not do this on a site)")
    a = ap.parse_args()

    if not a.bind.startswith("127.") and a.bind != "::1" and not a.allow_non_loopback:
        sys.stderr.write(
            "bacnet-fake-device: refusing to bind %s. This fixture answers I-Am and\n"
            "would confuse a real BACnet network. Use 127.0.0.1, or pass\n"
            "--allow-non-loopback if you really mean it.\n" % a.bind)
        return 2
    routed = None
    if a.routed_from:
        net, _, hexaddr = a.routed_from.partition(":")
        try:
            routed = (int(net), bytes.fromhex(hexaddr))
        except ValueError:
            sys.stderr.write("bacnet-fake-device: --routed-from wants NET:HEXADDR, "
                             "e.g. 2001:07\n")
            return 2
    forwarded = None
    if a.forwarded_from:
        fip, _, fport = a.forwarded_from.partition(":")
        if not fip.startswith("127.") and not a.allow_non_loopback:
            sys.stderr.write("bacnet-fake-device: --forwarded-from %s would send a "
                             "client off loopback. Use a 127.x address.\n" % fip)
            return 2
        try:
            forwarded = (fip, int(fport))
        except ValueError:
            sys.stderr.write("bacnet-fake-device: --forwarded-from wants IP:PORT\n")
            return 2
    twin = None
    if a.twin:
        tip, _, tport = a.twin.partition(":")
        if not tip.startswith("127.") and not a.allow_non_loopback:
            sys.stderr.write("bacnet-fake-device: refusing to bind twin %s\n" % tip)
            return 2
        try:
            twin = (tip, int(tport))
        except ValueError:
            sys.stderr.write("bacnet-fake-device: --twin wants IP:PORT\n")
            return 2
    try:
        dev = FakeDevice(a.bind, a.port, a.device, a.verbose,
                         a.refuse_whole_object_list, a.max_apdu,
                         routed, forwarded, a.segment_responses, twin)
    except OSError as exc:
        sys.stderr.write("bacnet-fake-device: cannot bind %s:%d: %s\n"
                         % (a.bind, a.port, exc))
        return 2
    # Readiness line: the test script waits for this before sending anything.
    print("fixture listening on %s:%d as device:%d (pid %d), %d objects%s"
          % (dev.addr[0], dev.addr[1], a.device, os.getpid(), len(dev.object_list),
             "" if dev.twin_addr is None
             else ", twin on %s:%d claiming the same instance" % dev.twin_addr),
          flush=True)
    try:
        dev.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for sock in dev.socks:
            sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
