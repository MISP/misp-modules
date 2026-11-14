These are published reference sentences for GGA, RMC, GLL and ZDA, with their
original checksums, as described in [GPSD's NMEA documentation](https://gpsd.io/NMEA.html).
They are independent protocol examples, not a continuous receiver capture:
the RMC date is in 1994 and the ZDA date is in 2002. Tests construct separate
streams to exercise midnight and year rollover, invalid fixes and multiple
talkers. The reference sentences also test checksum handling independently of
the test helper used to build those streams.
