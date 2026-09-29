# bacnet-sweep

Ask a BACnet/IP network what is on it, and print the answer. Read-only, by construction.

One Python file, standard library only. It broadcasts a Who-Is, tables every device that
answers, and dumps a named device's object list — object name, present value, engineering
units — to a terminal table or to CSV.

```
bacnet-sweep.py discover [--broadcast ADDR]
bacnet-sweep.py read <ip> <objtype>:<inst> <property> [--index N]
bacnet-sweep.py points <ip> <device-instance> [--csv | --json]
```

## Read this first: what it has actually been run against

**It has never spoken to a real BACnet device.** There is no BACnet hardware on the machine
it was written on, so every claim on this page was proved against `tests/bacnet-fake-device.py`
— a fake device written from ASHRAE 135 and run on loopback. That suite is in this repo and
it is the whole basis for trusting the tool:

```
$ tests/test-bacnet-sweep.sh
194 passed, 0 failed
```

A real controller from any vendor will differ, most likely in which optional properties it
refuses and in how it answers an unindexed `object-list` read. That is the biggest gap in
the tool and no amount of test writing closes it. If you run this against real hardware and
it gets something wrong, an issue with the output in it is the single most useful thing
anyone can send.

## Install

There is no install. One file, standard library only — no pip, no `bacpypes`, no virtual
environment. Python 3.8 or newer; it has only ever been executed on 3.12, and the 3.8 floor
comes from reading the file rather than from running it.

```sh
curl -O https://raw.githubusercontent.com/UsamaIqbal0304/bacnet-sweep/main/bacnet-sweep.py
```

## Use

```sh
# who is out there? broadcasts a Who-Is and listens for I-Am replies
python3 bacnet-sweep.py discover

# what does device 1201 at 10.20.30.41 have on it?
python3 bacnet-sweep.py points 10.20.30.41 1201

# the same thing, as a file you can send to somebody
python3 bacnet-sweep.py points 10.20.30.41 1201 --csv > ahu-01.csv
```

It binds UDP 47808, which needs no privilege. What stops a sweep on a laptop is usually
something else already holding that port — Workbench, a running station, another BACnet
stack — in which case pass `--local-port 47809`: devices reply to whatever port the request
came from. The tool diagnoses that case by name rather than printing an empty table, and a
sweep that finds nothing prints the likely causes in order: the firewall, the port, the
wrong broadcast address.

## The read-only promise

The tool can encode two BACnet services and no others:

| service | number | what it is |
| --- | --- | --- |
| Who-Is | unconfirmed 8 | who is out there |
| ReadProperty | confirmed 12 | what is this property |

There is no WriteProperty, no WritePropertyMultiple, no ReinitializeDevice, no
DeviceCommunicationControl, no TimeSynchronization, no AtomicWriteFile, no COV subscription
anywhere in the file. `_assert_read_only()` gates every confirmed request and raises before
a socket is touched if the service choice is anything but 12. The only other thing that
leaves the socket is an Abort PDU — a transaction-layer PDU carrying no data — sent to close
out a device that answered with a segmented response the tool will not reassemble.

It is also quiet on purpose: one Who-Is, per-point reads issued sequentially with a delay
between them (`--delay`), never in parallel, and never to an address you did not name.

Read-only is not the same as harmless. A sweep still puts traffic on a control network and
still reads from devices that are doing a job. Pace it, and do not point it at something
you do not own.

## Tests

```sh
tests/test-bacnet-sweep.sh          # 194 assertions, a few seconds, all on 127.0.0.1
```

The fixture covers the Who-Is broadcast and the I-Am decode including max APDU and
segmentation support; real, unsigned, signed, double, enumerated, character-string,
octet-string, bit-string, date, time and object-identifier values; array reads whole, by
element, and element 0 as a count; Error, Reject and Abort replies decoded into words
rather than numbers; a device that segments a reply it was told not to segment; a timeout;
a port already in use; and malformed and random frames, where the tool must print a
diagnosis rather than a traceback.

`tests/check-enums-against-niagara.py` is the one part that needs something else on the
machine. The tool's object-type, unit, property, error, reject and abort tables were
transcribed by hand from the standard, and a transcribed table is the kind of thing that is
97% right and quietly wrong in the other 3%. Where a Niagara install is present it reads
the independent copy of the same enumerations out of `bacnet-rt.jar`'s constant pool — no
Java runs — and fails on any name that disagrees. With no install it exits 77 and the suite
reports a skip.

## Licence

MIT. See [LICENSE](LICENSE). Use it, fork it, ship it inside something you sell; no
attribution needed beyond the licence text.

## More

The [tool's page](https://plantroomlabs.com/tools/bacnet-sweep/) has real terminal
transcripts from the fixture, the full blind-spot list, and notes on what a BACnet Who-Is
does and does not find. Its two siblings are
[mqtt-tap](https://github.com/UsamaIqbal0304/mqtt-tap) and
[decoder-check](https://github.com/UsamaIqbal0304/decoder-check).

Written by [Plantroom Labs](https://plantroomlabs.com) — Niagara Framework engineering:
modules and drivers, bajaux widgets, PX graphics, station and controller work. Issues and
pull requests are read.
