"""Tests for dsquic.new_reno."""

from dsquic.frames import Ping
from dsquic.new_reno import PACING_GAIN, NewReno
from dsquic.recovery import SentPacket
from dsquic.tls import EncryptionLevel

MDS = 1200


def packet(packet_number: int, time_sent: float, size: int = MDS) -> SentPacket:
    return SentPacket(
        level=EncryptionLevel.ONE_RTT,
        packet_number=packet_number,
        time_sent=time_sent,
        ack_eliciting=True,
        in_flight=True,
        size=size,
        frames=[Ping()],
    )


def test_initial_window() -> None:
    # B.3 with a 1200-byte datagram: min(12000, max(14720, 2400)) = 12000.
    assert NewReno(MDS).congestion_window == 10 * MDS


def test_bytes_in_flight_accounting() -> None:
    reno = NewReno(MDS)
    first, second = packet(0, 0.0), packet(1, 0.0)
    reno.on_packet_sent(first)
    reno.on_packet_sent(second)
    assert reno.bytes_in_flight == 2 * MDS
    reno.on_packets_acked([first], now=0.1)
    assert reno.bytes_in_flight == MDS
    reno.on_packets_discarded([second])
    assert reno.bytes_in_flight == 0


def test_slow_start_grows_by_bytes_acked() -> None:
    reno = NewReno(MDS)
    window = reno.congestion_window
    sent = packet(0, 0.0)
    reno.on_packet_sent(sent)
    reno.on_packets_acked([sent], now=0.1)
    assert reno.congestion_window == window + MDS


def test_loss_halves_window_and_exits_slow_start() -> None:
    reno = NewReno(MDS)
    window = reno.congestion_window
    lost = packet(0, time_sent=1.0)
    reno.on_packet_sent(lost)
    reno.on_packets_lost([lost], now=2.0)
    assert reno.congestion_window == window // 2

    # Post-recovery ACKs grow by the congestion-avoidance fraction,
    # not the slow-start byte count.
    later = packet(1, time_sent=3.0)
    reno.on_packet_sent(later)
    before = reno.congestion_window
    reno.on_packets_acked([later], now=3.1)
    assert 0 < reno.congestion_window - before < MDS


def test_one_reduction_per_recovery_period() -> None:
    reno = NewReno(MDS)
    first, second = packet(0, time_sent=1.0), packet(1, time_sent=1.5)
    reno.on_packet_sent(first)
    reno.on_packet_sent(second)
    reno.on_packets_lost([first], now=2.0)
    window = reno.congestion_window
    # Second loss was sent before recovery began: no further reduction (B.6).
    reno.on_packets_lost([second], now=2.5)
    assert reno.congestion_window == window


def test_window_floor_is_two_datagrams() -> None:
    reno = NewReno(MDS)
    for i in range(10):
        lost = packet(i, time_sent=float(i * 100))
        reno.on_packet_sent(lost)
        reno.on_packets_lost([lost], now=float(i * 100 + 50))
    assert reno.congestion_window == 2 * MDS


def test_persistent_congestion_collapses_to_minimum() -> None:
    reno = NewReno(MDS)
    reno.on_persistent_congestion()
    assert reno.congestion_window == 2 * MDS


def test_no_growth_for_packets_sent_in_recovery() -> None:
    reno = NewReno(MDS)
    lost = packet(0, time_sent=1.0)
    reno.on_packet_sent(lost)
    reno.on_packets_lost([lost], now=2.0)
    window = reno.congestion_window
    # Sent before recovery began, acked after: no growth (B.5).
    stale = packet(1, time_sent=1.5)
    reno.on_packet_sent(stale)
    reno.on_packets_acked([stale], now=2.5)
    assert reno.congestion_window == window


def test_pacing_rate_spreads_the_window_over_the_rtt() -> None:
    """§7.7: rate = N * congestion_window / smoothed_rtt."""
    reno = NewReno(MDS)
    assert reno.pacing_rate(0.1) == PACING_GAIN * reno.congestion_window / 0.1


def test_no_pacing_rate_without_an_rtt() -> None:
    assert NewReno(MDS).pacing_rate(0.0) is None


def test_ecn_ce_reduces_the_window_once_per_period() -> None:
    """RFC 9002 §7.1: a CE increase halves the window like loss, and
    B.6 limits the reduction to once per recovery period."""
    reno = NewReno(MDS)
    before = reno.congestion_window
    reno.on_ecn_ce(sent_time=1.0, now=2.0)
    assert reno.congestion_window == before // 2
    reno.on_ecn_ce(sent_time=1.5, now=2.1)  # sent inside the period
    assert reno.congestion_window == before // 2
