"""Bounded NMEA 0183 GNSS log parsing without network access or extra dependencies."""

import base64
import re
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, localcontext
from io import StringIO

MAX_SIZE = 20 * 1024 * 1024
MAX_LINES = 100_000
MAX_POSITIONS = 10_000
MAX_LINE_LENGTH = 1024
MODES = set("ADEFMNPRS")


def decode(encoded):
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("Provide base64-encoded NMEA log data; include attachments when fetching events.")
    if len(encoded) > 4 * ((MAX_SIZE + 2) // 3):
        raise ValueError("NMEA log exceeds the 20 MiB size limit.")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > MAX_SIZE:
        raise ValueError("NMEA log exceeds the 20 MiB size limit.")
    return raw


def _number(value, field, minimum=None, maximum=None):
    if (
        not isinstance(value, str)
        or len(value) > 32
        or not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", value)
    ):
        raise ValueError(f"Invalid {field}.")
    result = Decimal(value)
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise ValueError(f"Invalid {field}.")
    return result


def _coordinate(value, hemisphere, latitude):
    digits, limit, hemispheres = (4, 90, "NS") if latitude else (5, 180, "EW")
    if hemisphere not in tuple(hemispheres) or not re.fullmatch(rf"[0-9]{{{digits}}}(?:\.[0-9]{{1,24}})?", value):
        raise ValueError("Invalid NMEA coordinate or hemisphere.")
    degrees, minutes = Decimal(value[: digits - 2]), Decimal(value[digits - 2 :])
    if minutes >= 60 or degrees > limit or degrees == limit and minutes != 0:
        raise ValueError("NMEA coordinate is out of range.")
    with localcontext() as context:
        context.prec = 40
        result = degrees + minutes / 60
        return -result if hemisphere in "SW" else result


def _clock(value):
    if not re.fullmatch(r"[0-9]{6}(?:\.[0-9]{1,6})?", value):
        raise ValueError("Invalid UTC time; require hhmmss with at most six fractional digits.")
    fraction = value[7:].ljust(6, "0") if "." in value else "0"
    return time(int(value[:2]), int(value[2:4]), int(value[4:6]), int(fraction), tzinfo=timezone.utc)


def _rmc_date(value):
    if not re.fullmatch(r"[0-9]{6}", value):
        raise ValueError("Invalid RMC date; require ddmmyy.")
    year = int(value[4:])
    return date((1900 if year >= 80 else 2000) + year, int(value[2:4]), int(value[:2]))


def _mode(value):
    if value and value not in MODES:
        raise ValueError("Unsupported NMEA position mode.")
    return value


def _sentence(line):
    if len(line) > MAX_LINE_LENGTH:
        raise ValueError("NMEA sentence exceeds the 1,024-character limit.")
    match = re.fullmatch(r"[$!]([A-Z0-9]{4,16}),([^*]*)\*([0-9A-Fa-f]{2})", line)
    if not match:
        raise ValueError("Expected a bare NMEA sentence with a two-digit checksum.")
    checksum = 0
    for char in line[1 : line.rindex("*")]:
        checksum ^= ord(char)
    if checksum != int(match[3], 16):
        raise ValueError("NMEA checksum mismatch.")
    header = match[1]
    if line[0] == "$" and header.startswith("P"):
        talker, kind = None, header
    elif re.fullmatch(r"[A-Z]{2}[A-Z0-9]{3}", header):
        talker, kind = header[:2], header[2:]
    else:
        raise ValueError("Invalid NMEA sentence identifier.")
    # Encapsulation sentences (such as AIS !AIVDM) are retained, never decoded as GPS fixes.
    return talker, kind, [header, *match[2].split(",")], line[0] == "$"


class Log:
    def __init__(self, raw):
        if len(raw) > MAX_SIZE:
            raise ValueError("NMEA log exceeds the 20 MiB size limit.")
        if any(byte not in (10, 13) and not 32 <= byte <= 126 for byte in raw):
            raise ValueError("NMEA logs must contain ASCII sentences and CR/LF line endings.")
        self.positions, self.sentence_types, self.talkers = [], set(), set()
        self.sentence_count = self.invalid_fix_count = self.unhandled_count = self.line_count = 0
        self.anchors = {}
        for line_number, line in enumerate(StringIO(raw.decode("ascii"), newline=None), 1):
            self.line_count = line_number
            if line_number > MAX_LINES:
                raise ValueError("NMEA log exceeds the 100,000-line limit.")
            line = line.removesuffix("\n")
            if not line.strip():
                continue
            try:
                talker, kind, fields, standard = _sentence(line)
                self.sentence_count += 1
                self.sentence_types.add(kind)
                if talker:
                    self.talkers.add(talker)
                if standard and talker and kind == "ZDA":
                    if len(fields) < 7 or not all(
                        re.fullmatch(pattern, value)
                        for pattern, value in (
                            (r"[0-9]{2}", fields[2]),
                            (r"[0-9]{2}", fields[3]),
                            (r"[0-9]{4}", fields[4]),
                        )
                    ):
                        raise ValueError("Malformed ZDA date sentence.")
                    self.anchors[talker] = datetime.combine(
                        date(int(fields[4]), int(fields[3]), int(fields[2])), _clock(fields[1])
                    )
                elif standard and talker and kind == "DTM":
                    if len(fields) < 9 or fields[1] != "W84":
                        raise ValueError("Only WGS84 (W84) datum logs are supported.")
                elif standard and talker and kind in ("GGA", "RMC", "GLL"):
                    position = self._position(kind, fields, talker)
                    if position is None:
                        self.invalid_fix_count += 1
                    else:
                        position["details"].update(
                            {"line": line_number, "sentence-type": kind, "talker-id": talker, "raw-sentence": line}
                        )
                        self.positions.append(position)
                        if len(self.positions) > MAX_POSITIONS:
                            raise ValueError("NMEA log exceeds the 10,000-position limit.")
                else:
                    self.unhandled_count += 1
            except ValueError as error:
                raise ValueError(f"Line {line_number}: {error}") from None
        if not self.sentence_count:
            raise ValueError("The log contains no NMEA sentences.")

    def _timestamp(self, talker, clock, explicit_date=None):
        if explicit_date is not None:
            result = datetime.combine(explicit_date, clock)
        elif talker in self.anchors:
            anchor = self.anchors[talker]
            result = datetime.combine(anchor.date(), clock)
            if result - anchor > timedelta(hours=12):
                result -= timedelta(days=1)
            elif anchor - result > timedelta(hours=12):
                result += timedelta(days=1)
        else:
            return None
        self.anchors[talker] = result
        return result

    def _position(self, kind, fields, talker):
        details, altitude, explicit_date = {}, None, None
        if kind == "GGA":
            if len(fields) < 15 or not re.fullmatch(r"[0-8]", fields[6]):
                raise ValueError("Malformed GGA sentence or fix quality.")
            if fields[6] == "0":
                return None
            clock_text, lat, ns, lon, ew = fields[1:6]
            details["fix-quality"] = fields[6]
            for index, name, minimum in ((7, "satellites", 0), (8, "hdop", 0), (13, "dgps-age-seconds", 0)):
                if fields[index]:
                    value = _number(fields[index], name, minimum)
                    if name == "satellites" and (not re.fullmatch(r"[0-9]{1,3}", fields[index])):
                        raise ValueError("Invalid satellite count.")
                    details[name] = str(value)
            heights = []
            for index, name in ((9, "altitude-msl-metres"), (11, "geoid-separation-metres")):
                value = _number(fields[index], name) if fields[index] else None
                if value is not None:
                    if fields[index + 1] != "M":
                        raise ValueError("GGA heights must use metres (M).")
                    details[name] = str(value)
                heights.append(value)
            if all(value is not None for value in heights):
                with localcontext() as context:
                    context.prec = 80
                    altitude = sum(heights)
            if fields[14]:
                details["reference-station-id"] = fields[14]
        elif kind == "RMC":
            if len(fields) < 12 or fields[2] not in ("A", "V"):
                raise ValueError("Malformed RMC sentence or status.")
            mode = _mode(fields[12]) if len(fields) > 12 else ""
            navigation_status = fields[13] if len(fields) > 13 else ""
            if navigation_status not in ("", "S", "C", "U", "V"):
                raise ValueError("Unsupported RMC navigation status.")
            if fields[2] == "V" or mode == "N" or navigation_status == "V":
                return None
            clock_text, _, lat, ns, lon, ew = fields[1:7]
            explicit_date = _rmc_date(fields[9])
            details["status"], details["mode"] = fields[2], mode
            if navigation_status:
                details["navigation-status"] = navigation_status
            for index, name in ((7, "speed-knots"), (8, "course-degrees")):
                if fields[index]:
                    value = _number(fields[index], name, 0)
                    if name == "course-degrees" and value >= 360:
                        raise ValueError("Course must be less than 360 degrees.")
                    details[name] = str(value)
        else:
            if len(fields) < 7 or fields[6] not in ("A", "V"):
                raise ValueError("Malformed GLL sentence or status.")
            mode = _mode(fields[7]) if len(fields) > 7 else ""
            if fields[6] == "V" or mode == "N":
                return None
            lat, ns, lon, ew, clock_text = fields[1:6]
            details["status"], details["mode"] = fields[6], mode
        clock = _clock(clock_text)
        latitude, longitude = _coordinate(lat, ns, True), _coordinate(lon, ew, False)
        timestamp = self._timestamp(talker, clock, explicit_date)
        details["utc-time"] = clock_text
        return {
            "latitude": latitude,
            "longitude": longitude,
            "altitude": altitude,
            "timestamp": timestamp,
            "details": details,
        }
