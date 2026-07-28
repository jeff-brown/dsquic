"""Tests for dsquic.recovery."""

import pytest

from dsquic.frames import Ack, Ping
from dsquic.new_reno import NewReno
from dsquic.recovery import (
    GRANULARITY,
    AckOfUnsentPacket,
    LossDetection,
    RttEstimator,
    SentPacket,
)
from dsquic.tls import EncryptionLevel

LEVEL = EncryptionLevel.ONE_RTT


def make_detector(is_client: bool = False) -> LossDetection:
    detector = LossDetection(NewReno(), is_client=is_client)
    detector.handshake_confirmed = True
    return detector


def send(
    detector: LossDetection,
    packet_number: int,
    time_sent: float,
    level: EncryptionLevel = LEVEL,
    ack_eliciting: bool = True,
) -> SentPacket:
    packet = SentPacket(
        level=level,
        packet_number=packet_number,
        time_sent=time_sent,
        ack_eliciting=ack_eliciting,
        in_flight=ack_eliciting,
        size=1200,
        frames=[Ping()],
    )
    detector.on_packet_sent(packet)
    return packet


def ack(ranges: list[tuple[int, int]]) -> Ack:
    return Ack(largest=ranges[0][1], delay=0, ranges=ranges)


class TestRttEstimator:
    def test_first_sample_initializes(self) -> None:
        rtt = RttEstimator()
        rtt.update(0.1, ack_delay=0.05)
        assert rtt.latest == 0.1
        assert rtt.min == 0.1
        assert rtt.smoothed == 0.1
        assert rtt.rttvar == 0.05

    def test_ewma_update(self) -> None:
        rtt = RttEstimator()
        rtt.update(0.1, 0)
        rtt.update(0.2, 0)
        assert rtt.smoothed == pytest.approx(7 / 8 * 0.1 + 1 / 8 * 0.2)
        assert rtt.min == 0.1

    def test_ack_delay_subtracted(self) -> None:
        rtt = RttEstimator()
        rtt.update(0.1, 0)
        rtt.update(0.3, ack_delay=0.1)
        assert rtt.smoothed == pytest.approx(7 / 8 * 0.1 + 1 / 8 * 0.2)

    def test_ack_delay_not_taken_below_min(self) -> None:
        rtt = RttEstimator()
        rtt.update(0.1, 0)
        # Subtracting the full delay would go below min_rtt; use the raw sample (§5.3).
        rtt.update(0.15, ack_delay=0.10)
        assert rtt.smoothed == pytest.approx(7 / 8 * 0.1 + 1 / 8 * 0.15)


class TestAckProcessing:
    def test_simple_ack(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        outcome = detector.on_ack_received(LEVEL, ack([(0, 0)]), ack_delay=0, now=0.1)
        assert [p.packet_number for p in outcome.acked] == [0]
        assert outcome.lost == []
        assert detector.rtt.latest == pytest.approx(0.1)
        assert detector.controller.bytes_in_flight == 0

    def test_ack_of_unsent_raises(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        with pytest.raises(AckOfUnsentPacket):
            detector.on_ack_received(LEVEL, ack([(0, 5)]), ack_delay=0, now=0.1)

    def test_duplicate_ack_is_idempotent(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        detector.on_ack_received(LEVEL, ack([(0, 0)]), ack_delay=0, now=0.1)
        outcome = detector.on_ack_received(LEVEL, ack([(0, 0)]), ack_delay=0, now=0.2)
        assert outcome.acked == []

    def test_no_rtt_sample_when_largest_not_newly_acked(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        send(detector, 1, time_sent=0.0)
        detector.on_ack_received(LEVEL, ack([(1, 1)]), ack_delay=0, now=0.1)
        # Packet 1 (the largest) was already acked; this ACK only news packet 0.
        outcome = detector.on_ack_received(LEVEL, ack([(0, 1)]), ack_delay=0, now=5.0)
        assert [p.packet_number for p in outcome.acked] == [0]
        assert detector.rtt.latest == pytest.approx(0.1)


class TestLossDetection:
    def test_packet_threshold(self) -> None:
        detector = make_detector()
        for packet_number in range(5):
            send(detector, packet_number, time_sent=0.0)
        outcome = detector.on_ack_received(LEVEL, ack([(4, 4)]), ack_delay=0, now=0.1)
        # kPacketThreshold = 3: packets 0 and 1 are 3+ behind the largest.
        assert [p.packet_number for p in outcome.lost] == [0, 1]

    def test_time_threshold(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        send(detector, 1, time_sent=5.0)
        outcome = detector.on_ack_received(LEVEL, ack([(1, 1)]), ack_delay=0, now=5.1)
        # Packet 0 is only 1 behind, but was sent far longer than
        # 9/8 * RTT ago: lost by the time threshold.
        assert [p.packet_number for p in outcome.lost] == [0]

    def test_not_yet_lost_sets_loss_timer(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0)
        send(detector, 1, time_sent=0.001)
        detector.on_ack_received(LEVEL, ack([(1, 1)]), ack_delay=0, now=0.1)
        timeout = detector.loss_detection_timeout()
        assert timeout is not None
        # Firing the timer at that time declares packet 0 lost.
        outcome = detector.on_loss_detection_timeout(timeout + GRANULARITY)
        assert [p.packet_number for p in outcome.lost] == [0]
        assert outcome.probe_level is None


class TestPto:
    def test_pto_armed_after_send(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=1.0)
        timeout = detector.loss_detection_timeout()
        assert timeout is not None
        assert timeout > 1.0

    def test_pto_backoff_doubles(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=1.0)
        first = detector.loss_detection_timeout()
        assert first is not None
        outcome = detector.on_loss_detection_timeout(first)
        assert outcome.probe_level is LEVEL
        second = detector.loss_detection_timeout()
        assert second is not None
        assert second - 1.0 == pytest.approx(2 * (first - 1.0))

    def test_ack_resets_backoff(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=1.0)
        first = detector.loss_detection_timeout()
        assert first is not None
        detector.on_loss_detection_timeout(first)
        detector.on_ack_received(LEVEL, ack([(0, 0)]), ack_delay=0, now=1.1)
        send(detector, 1, time_sent=2.0)
        after_ack = detector.loss_detection_timeout()
        assert after_ack is not None
        # Backoff was reset: the new timeout is one un-doubled PTO out.
        assert after_ack - 2.0 < 2 * (first - 1.0)

    def test_no_timer_when_nothing_in_flight(self) -> None:
        detector = make_detector()
        assert detector.loss_detection_timeout() is None

    def test_client_anti_deadlock_pto(self) -> None:
        detector = LossDetection(NewReno(), is_client=True)
        # Handshake not confirmed, nothing in flight: a client still arms
        # a PTO so lost server flights cannot deadlock it (§6.2.2.1).
        assert detector.loss_detection_timeout() is not None
        outcome = detector.on_loss_detection_timeout(1.0)
        assert outcome.probe_level is EncryptionLevel.INITIAL

    def test_no_app_pto_before_handshake_confirmed(self) -> None:
        detector = LossDetection(NewReno(), is_client=False)
        send(detector, 0, time_sent=0.0, level=EncryptionLevel.HANDSHAKE)
        send(detector, 0, time_sent=0.0, level=EncryptionLevel.ONE_RTT)
        outcome = detector.on_loss_detection_timeout(10.0)
        assert outcome.probe_level is EncryptionLevel.HANDSHAKE


class TestSpaceDiscard:
    def test_discard_removes_without_congestion_signal(self) -> None:
        detector = make_detector()
        send(detector, 0, time_sent=0.0, level=EncryptionLevel.INITIAL)
        window_before = detector.controller.congestion_window
        detector.discard_space(EncryptionLevel.INITIAL)
        assert detector.controller.bytes_in_flight == 0
        assert detector.controller.congestion_window == window_before
        assert not detector.ack_eliciting_in_flight()


class TestPersistentCongestion:
    def test_long_span_of_losses_collapses_window(self) -> None:
        detector = make_detector()
        detector.rtt.update(0.1, 0)  # establish a sample
        send(detector, 0, time_sent=0.0)
        send(detector, 1, time_sent=30.0)
        send(detector, 2, time_sent=31.0)
        detector.on_ack_received(LEVEL, ack([(2, 2)]), ack_delay=0, now=31.1)
        assert detector.controller.congestion_window == 2 * 1200
