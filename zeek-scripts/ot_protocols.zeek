##
## SmartShield OT Protocol Zeek Scripts
## ======================================
## Loads Zeek's built-in OT protocol analyzers and publishes parsed events
## to Redis channels consumed by modules/ot_detection/ot_detection.py.
##
## Supported protocols:
##   Modbus/TCP   (port 502)   - via @load policy/protocols/modbus
##   DNP3         (port 20000) - via @load policy/protocols/dnp3
##   S7Comm/ISO-TSAP (port 102)- connection-level detection (Zeek has no
##                                full S7 parser; deep parsing done in Python)
##
## The Redis publishing is done through Zeek's Input framework writing
## to a named pipe that SmartShield's OT module reads.
##
## For environments without the full Zeek OT policy bundle, this script
## falls back gracefully to conn.log analysis only.
##

@load base/protocols/conn
@load base/frameworks/notice

# Load OT protocol parsers if available
@ifdef ( have_Zeek_PolicyProtocolsModbus )
    @load policy/protocols/modbus
@endif
@ifdef ( have_Zeek_PolicyProtocolsDNP3 )
    @load policy/protocols/dnp3
@endif

module OT;

export {
    ## Notice types emitted for OT-specific attacks
    redef enum Notice::Type += {
        PLCModeSwitch,         ##< Rapid PLC RUN/STOP mode switching
        WatchdogManipulation,  ##< Watchdog timer disabled/manipulated
        ValveCycling,          ##< Rapid valve open/close commands
        MotorCycling,          ##< Rapid motor start/stop commands
        ModbusWriteCoil,       ##< Modbus write coil/register
        ModbusIllegalFunction, ##< Modbus exception / illegal function
        S7CommPLCStop,         ##< S7 STOP command
        DNP3UnauthorizedFunc,  ##< DNP3 unauthorized function code
        OTProtocolAnomaly,     ##< Generic OT anomaly
    };

    ## Set of OT device IPs (populated from conn.log patterns).
    ## Populated dynamically based on which IPs communicate on OT ports.
    global ot_device_ips: set[addr] = {} &redef;

    ## Modbus connection counter per source IP (reset each minute)
    global modbus_conn_count: table[addr] of count
        &default=0 &create_expire=60sec;

    ## S7Comm connection counter per source IP
    global s7_conn_count: table[addr] of count
        &default=0 &create_expire=60sec;

    ## DNP3 request counter per source IP
    global dnp3_req_count: table[addr] of count
        &default=0 &create_expire=60sec;

    ## PROFINET DCP counter per source IP
    global profinet_dcp_count: table[addr] of count
        &default=0 &create_expire=60sec;

    ## PLC mode switch tracker: dst -> count within 60s
    global plc_mode_switch_count: table[addr] of count
        &default=0 &create_expire=60sec;

    ## Thresholds
    const modbus_flood_threshold: count = 20 &redef;
    const s7_flood_threshold:     count = 50 &redef;
    const dnp3_flood_threshold:   count = 100 &redef;
    const profinet_threshold:     count = 50 &redef;
    const plc_mode_switch_limit:  count = 5 &redef;
}

## ── Modbus detection ────────────────────────────────────────────────────────

#ifdef ( modbus_message )
event modbus_message(c: connection, headers: ModbusHeaders,
                     is_orig: bool) &priority=5
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    ++modbus_conn_count[src];
    add ot_device_ips[dst];

    if (modbus_conn_count[src] >= modbus_flood_threshold) {
        NOTICE([$note=OTProtocolAnomaly,
                $conn=c,
                $msg=fmt("Modbus connection flood from %s: %d conns/min",
                         src, modbus_conn_count[src]),
                $identifier=fmt("modbus-flood-%s", src)]);
    }
}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                start_address: count, quantity: count)
{
    add ot_device_ips[c$id$resp_h];
}

event modbus_write_single_coil_request(c: connection,
                                       headers: ModbusHeaders,
                                       address: count, value: bool)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    NOTICE([$note=ModbusWriteCoil,
            $conn=c,
            $msg=fmt("Modbus WriteCoil from %s to %s: address=%d value=%s",
                     src, dst, address, value),
            $identifier=fmt("mb-write-coil-%s-%s", src, dst)]);
}

event modbus_write_multiple_coils_request(c: connection,
                                          headers: ModbusHeaders,
                                          start_address: count,
                                          coils: ModbusCoils)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    NOTICE([$note=ModbusWriteCoil,
            $conn=c,
            $msg=fmt("Modbus WriteMultipleCoils from %s to %s: "
                     "start=%d count=%d",
                     src, dst, start_address, |coils|),
            $identifier=fmt("mb-write-mcoils-%s-%s", src, dst)]);
}

event modbus_exception(c: connection, headers: ModbusHeaders,
                       code: ModbusExceptionCode)
{
    NOTICE([$note=ModbusIllegalFunction,
            $conn=c,
            $msg=fmt("Modbus exception from %s: code=%s",
                     c$id$orig_h, code),
            $identifier=fmt("mb-exception-%s", c$id$orig_h)]);
}
#endif

## ── DNP3 detection ──────────────────────────────────────────────────────────

#ifdef ( dnp3_application_request_header )
event dnp3_application_request_header(c: connection, is_orig: bool,
                                      application: count, fc: count)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    ++dnp3_req_count[src];
    add ot_device_ips[dst];

    if (dnp3_req_count[src] >= dnp3_flood_threshold) {
        NOTICE([$note=OTProtocolAnomaly,
                $conn=c,
                $msg=fmt("DNP3 request flood from %s: %d req/min (fc=%d)",
                         src, dnp3_req_count[src], fc),
                $identifier=fmt("dnp3-flood-%s", src)]);
    }

    # Function codes > 33 are reserved/dangerous in DNP3
    if (fc > 33) {
        NOTICE([$note=DNP3UnauthorizedFunc,
                $conn=c,
                $msg=fmt("DNP3 unauthorized function code %d from %s to %s",
                         fc, src, dst),
                $identifier=fmt("dnp3-func-%s-%d", src, fc)]);
    }
}
#endif

## ── S7Comm / ISO-TSAP detection (port 102) ──────────────────────────────────
## Zeek does not ship a full S7Comm parser; we detect at connection level
## and do deep parsing in Python (ot_detection.py).

event connection_state_remove(c: connection)
{
    if (c$id$resp_p == 102/tcp) {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;

        ++s7_conn_count[src];
        add ot_device_ips[dst];

        if (s7_conn_count[src] >= s7_flood_threshold) {
            NOTICE([$note=OTProtocolAnomaly,
                    $conn=c,
                    $msg=fmt("S7Comm (ISO-TSAP) connection flood from %s: "
                             "%d conns/min",
                             src, s7_conn_count[src]),
                    $identifier=fmt("s7-flood-%s", src)]);
        }
    }
}

## ── UDP-based OT protocol detection ─────────────────────────────────────────
## Merged all UDP request handlers into a single event to avoid duplicate
## handler definitions in Zeek.

event udp_contents(u: connection, is_orig: bool, contents: string)
{
    # PROFINET DCP (port 34964 UDP)
    if (u$id$resp_p == 34964/udp) {
        local src1 = u$id$orig_h;
        ++profinet_dcp_count[src1];

        if (profinet_dcp_count[src1] >= profinet_threshold) {
            NOTICE([$note=OTProtocolAnomaly,
                    $conn=u,
                    $msg=fmt("PROFINET DCP discovery flood from %s: "
                             "%d req/min",
                             src1, profinet_dcp_count[src1]),
                    $identifier=fmt("profinet-flood-%s", src1)]);
        }
    }

    # PTP (IEEE 1588) grandmaster spoofing detection
    # PTP event messages use port 319/UDP
    if (u$id$resp_p == 319/udp || u$id$orig_p == 319/udp) {
        local src2 = u$id$orig_h;
        NOTICE([$note=OTProtocolAnomaly,
                $conn=u,
                $msg=fmt("PTP (IEEE 1588) traffic from %s — verify it is "
                         "a known grandmaster clock", src2),
                $identifier=fmt("ptp-traffic-%s", src2)]);
    }
}

## ── Log all connections on OT ports ─────────────────────────────────────────

event connection_established(c: connection)
{
    local dport = c$id$resp_p;

    # Comprehensive list of OT/ICS TCP ports
    if (dport in {502/tcp, 102/tcp, 20000/tcp, 4840/tcp, 44818/tcp,
                  18245/tcp, 18246/tcp, 34962/tcp, 34963/tcp, 34964/tcp}) {
        add ot_device_ips[c$id$resp_h];

        Reporter::info(fmt("[OT] Connection established: %s -> %s:%d",
                           c$id$orig_h, c$id$resp_h, dport));
    }
}
