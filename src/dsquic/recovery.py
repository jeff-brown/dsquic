"""Loss detection.

RFC 9002: §5 (RTT estimation), §6 (loss detection, PTO), Appendix A
(reference pseudocode).

Tracks sent packets per packet number space, processes ACK ranges,
declares loss by packet threshold and time threshold, arms the PTO timer
across spaces, and detects persistent congestion. Emits congestion
events to the pluggable controller defined in congestion.py. Lost
frames are sent again in new packets with new packet numbers; packets
themselves are never retransmitted.

Packet number spaces are keyed by tls.EncryptionLevel: Initial,
Handshake, and ONE_RTT for the application space. Time is a float in
seconds from the caller's clock; this module never reads a clock.
"""

from dataclasses import dataclass, field

from dsquic.congestion import CongestionController
from dsquic.frames import Ack, Frame
from dsquic.tls import EncryptionLevel

PACKET_THRESHOLD = 3  # kPacketThreshold (§6.1.1)
TIME_THRESHOLD = 9 / 8  # kTimeThreshold (§6.1.2)
GRANULARITY = 0.001  # kGranularity, seconds (A.2)
INITIAL_RTT = 0.333  # kInitialRtt, seconds (§6.2.2)
PERSISTENT_CONGESTION_THRESHOLD = 3  # kPersistentCongestionThreshold (§7.6.1)


class AckOfUnsentPacket(Exception):
    """An ACK acknowledged a packet number never sent (§13.1); the
    connection maps this to PROTOCOL_VIOLATION."""


@dataclass(frozen=True)
class SentPacket:
    """Bookkeeping for one sent packet (A.1.1).

    ``frames`` is kept so the connection can re-bundle a lost packet's
    frames into new packets; ``in_flight`` means the packet counts
    against the congestion window (ack-eliciting or PADDING-bearing).
    """

    level: EncryptionLevel
    packet_number: int
    time_sent: float
    ack_eliciting: bool
    in_flight: bool
    size: int
    frames: list[Frame]


@dataclass(frozen=True)
class AckOutcome:
    """What one ACK did: packets newly acknowledged and packets it exposed
    as lost. Lost frames are the connection's to resend."""

    acked: list[SentPacket]
    lost: list[SentPacket]


@dataclass(frozen=True)
class TimeoutOutcome:
    """What a loss-detection timeout did: either packets declared lost by
    the time threshold, or a PTO asking for a probe at ``probe_level``."""

    lost: list[SentPacket]
    probe_level: EncryptionLevel | None


class RttEstimator:
    """RTT estimation state (§5.3)."""

    def __init__(self, initial_rtt: float = INITIAL_RTT) -> None:
        self.latest = initial_rtt
        self.min = initial_rtt
        self.smoothed = initial_rtt
        self.rttvar = initial_rtt / 2
        self.has_sample = False

    def update(self, sample: float, ack_delay: float) -> None:
        """Fold in one RTT sample (§5.3, the EWMA update)."""
        self.latest = sample
        if not self.has_sample:
            # First sample initializes the estimator (§5.2).
            self.min = sample
            self.smoothed = sample
            self.rttvar = sample / 2
            self.has_sample = True
            return
        self.min = min(self.min, sample)
        # §5.3: subtract the peer's ack delay only if doing so does not
        # take the sample below min_rtt.
        adjusted = sample
        if sample - ack_delay >= self.min:
            adjusted = sample - ack_delay
        self.rttvar = 3 / 4 * self.rttvar + 1 / 4 * abs(self.smoothed - adjusted)
        self.smoothed = 7 / 8 * self.smoothed + 1 / 8 * adjusted


@dataclass
class _Space:
    sent: dict[int, SentPacket] = field(default_factory=dict[int, "SentPacket"])
    largest_sent: int = -1
    largest_acked: int = -1
    loss_time: float | None = None
    discarded: bool = False


class LossDetection:
    """Loss detection and PTO state across the three packet number spaces
    (§6, Appendix A). ``is_client`` drives the anti-deadlock PTO of
    §6.2.2.1; the connection sets ``handshake_confirmed`` when TLS says
    so, which gates ack-delay capping (§5.3) and the application-space
    PTO (§6.2.1)."""

    def __init__(
        self,
        controller: CongestionController,
        is_client: bool,
        max_ack_delay: float = 0.025,
    ) -> None:
        self.controller = controller
        self.rtt = RttEstimator()
        self.handshake_confirmed = False
        self._is_client = is_client
        self._max_ack_delay = max_ack_delay
        self._pto_count = 0
        self._spaces = {level: _Space() for level in EncryptionLevel}
        # When an ack-eliciting packet was last sent in each space. Kept
        # after those packets are acknowledged, because the anti-deadlock
        # PTO of §6.2.2.1 arms relative to it with nothing in flight.
        self._last_ack_eliciting_sent: dict[EncryptionLevel, float] = {}

    def on_packet_sent(self, packet: SentPacket) -> None:
        space = self._spaces[packet.level]
        space.sent[packet.packet_number] = packet
        space.largest_sent = max(space.largest_sent, packet.packet_number)
        if packet.ack_eliciting:
            self._last_ack_eliciting_sent[packet.level] = packet.time_sent
        self.controller.on_packet_sent(packet)

    def on_ack_received(
        self, level: EncryptionLevel, ack: Ack, ack_delay: float, now: float
    ) -> AckOutcome:
        """Process one ACK frame (§6.1, A.7).

        ``ack_delay`` is the decoded delay in seconds; the connection
        applies the peer's ack_delay_exponent before calling.
        """
        space = self._spaces[level]
        if ack.largest > space.largest_sent:
            raise AckOfUnsentPacket(f"ACK for unsent packet {ack.largest} at {level.name}")

        newly_acked = []
        for low, high in ack.ranges:
            for packet_number in list(space.sent):
                if low <= packet_number <= high:
                    newly_acked.append(space.sent.pop(packet_number))
        if not newly_acked:
            return AckOutcome(acked=[], lost=[])
        newly_acked.sort(key=lambda packet: packet.packet_number)
        space.largest_acked = max(space.largest_acked, ack.largest)

        # §5.1: an RTT sample requires the largest acknowledged packet to
        # be newly acknowledged and at least one newly acked packet to be
        # ack-eliciting.
        largest_newly = newly_acked[-1]
        if largest_newly.packet_number == ack.largest and any(
            packet.ack_eliciting for packet in newly_acked
        ):
            latest_rtt = now - largest_newly.time_sent
            # §5.3: cap the peer's reported delay by its max_ack_delay
            # only once the handshake is confirmed.
            if self.handshake_confirmed:
                ack_delay = min(ack_delay, self._max_ack_delay)
            self.rtt.update(latest_rtt, ack_delay)

        # A.7: a valid ACK resets the PTO backoff.
        self._pto_count = 0

        self.controller.on_packets_acked(
            [packet for packet in newly_acked if packet.in_flight], now
        )
        lost = self._detect_and_remove_lost(level, now)
        return AckOutcome(acked=newly_acked, lost=lost)

    def _detect_and_remove_lost(self, level: EncryptionLevel, now: float) -> list[SentPacket]:
        """Declare losses by packet threshold and time threshold (§6.1, A.10)."""
        space = self._spaces[level]
        space.loss_time = None
        # §6.1.2: the time threshold is a small multiple of the RTT,
        # floored at timer granularity.
        loss_delay = max(TIME_THRESHOLD * max(self.rtt.latest, self.rtt.smoothed), GRANULARITY)
        lost_before = now - loss_delay
        lost = []
        for packet_number in sorted(space.sent):
            packet = space.sent[packet_number]
            if packet_number > space.largest_acked:
                continue  # loss is only declared behind the largest acked (§6.1)
            if (
                packet_number <= space.largest_acked - PACKET_THRESHOLD
                or packet.time_sent <= lost_before
            ):
                del space.sent[packet_number]
                lost.append(packet)
            else:
                # Not yet lost by time; note when it would be (A.10).
                candidate = packet.time_sent + loss_delay
                if space.loss_time is None or candidate < space.loss_time:
                    space.loss_time = candidate
        if lost:
            in_flight_lost = [packet for packet in lost if packet.in_flight]
            if in_flight_lost:
                self.controller.on_packets_lost(in_flight_lost, now)
                # §7.6: persistent congestion needs an RTT sample and lost
                # ack-eliciting packets spanning longer than the
                # persistent congestion duration.
                if self.rtt.has_sample and self._spans_persistent_congestion(in_flight_lost):
                    self.controller.on_persistent_congestion()
        return lost

    def _spans_persistent_congestion(self, lost: list[SentPacket]) -> bool:
        """§7.6.1: the duration test over this batch of lost packets."""
        eliciting = [packet for packet in lost if packet.ack_eliciting]
        minimum_span_packets = 2  # §7.6.2: at least two ack-eliciting losses
        if len(eliciting) < minimum_span_packets:
            return False
        duration = (
            self.rtt.smoothed + max(4 * self.rtt.rttvar, GRANULARITY) + self._max_ack_delay
        ) * PERSISTENT_CONGESTION_THRESHOLD
        span = eliciting[-1].time_sent - eliciting[0].time_sent
        return span > duration

    def _pto_duration(self, level: EncryptionLevel) -> float:
        """§6.2.1: PTO = smoothed_rtt + max(4*rttvar, granularity), plus the
        peer's max_ack_delay in the application space, backed off per §6.2.4."""
        duration = self.rtt.smoothed + max(4 * self.rtt.rttvar, GRANULARITY)
        if level is EncryptionLevel.ONE_RTT:
            duration += self._max_ack_delay
        return duration * (1 << self._pto_count)

    def _earliest_loss_time(self) -> tuple[float, EncryptionLevel] | None:
        candidates = [
            (space.loss_time, level)
            for level, space in self._spaces.items()
            if space.loss_time is not None and not space.discarded
        ]
        # Compare on time only: equal deadlines are common with a real
        # clock, and EncryptionLevel is deliberately not orderable.
        return min(candidates, key=lambda item: item[0]) if candidates else None

    def _earliest_pto(self) -> tuple[float, EncryptionLevel] | None:
        candidates: list[tuple[float, EncryptionLevel]] = []
        for level, space in self._spaces.items():
            if space.discarded:
                continue
            if level is EncryptionLevel.ONE_RTT and not self.handshake_confirmed:
                continue  # §6.2.1: no application-space PTO before confirmation
            eliciting = [packet for packet in space.sent.values() if packet.ack_eliciting]
            if not eliciting:
                continue
            last_sent = max(packet.time_sent for packet in eliciting)
            candidates.append((last_sent + self._pto_duration(level), level))
        return min(candidates, key=lambda item: item[0]) if candidates else None

    def loss_detection_timeout(self) -> float | None:
        """When the connection must call on_loss_detection_timeout (A.8).

        Earliest pending time-threshold loss wins; otherwise the earliest
        PTO among spaces with ack-eliciting packets in flight. A client
        whose handshake is not yet confirmed arms a PTO even with nothing
        in flight, to avoid deadlock when the server's replies are lost
        (§6.2.2.1).
        """
        loss = self._earliest_loss_time()
        if loss is not None:
            return loss[0]
        pto = self._earliest_pto()
        if pto is not None:
            return pto[0]
        if self._is_client and not self.handshake_confirmed:
            return self._anti_deadlock_pto()
        return None

    def _anti_deadlock_pto(self) -> float | None:
        """§6.2.2.1: a client arms a PTO even with nothing in flight, so a
        lost server flight cannot deadlock the handshake.

        The timer runs from the last ack-eliciting packet this client
        actually sent, which is not the same as what is still in flight:
        those packets may all have been acknowledged.
        """
        level = (
            EncryptionLevel.INITIAL
            if not self._spaces[EncryptionLevel.INITIAL].discarded
            else EncryptionLevel.HANDSHAKE
        )
        last_sent = self._last_ack_eliciting_sent.get(level)
        if last_sent is None:
            return None  # nothing sent at this level yet; nothing to probe
        return last_sent + self._pto_duration(level)

    def on_loss_detection_timeout(self, now: float) -> TimeoutOutcome:
        """The timer fired: declare time-threshold losses, or back off the
        PTO and ask the connection to send a probe (§6.2.4, A.9)."""
        loss = self._earliest_loss_time()
        if loss is not None:
            return TimeoutOutcome(lost=self._detect_and_remove_lost(loss[1], now), probe_level=None)
        self._pto_count += 1
        pto = self._earliest_pto()
        if pto is not None:
            return TimeoutOutcome(lost=[], probe_level=pto[1])
        # Nothing in flight: this is the §6.2.2.1 anti-deadlock probe.
        level = (
            EncryptionLevel.INITIAL
            if not self._spaces[EncryptionLevel.INITIAL].discarded
            else EncryptionLevel.HANDSHAKE
        )
        return TimeoutOutcome(lost=[], probe_level=level)

    def discard_space(self, level: EncryptionLevel) -> None:
        """Keys were discarded (§6.4): forget the space's packets with no
        congestion signal, and reset the PTO backoff (A.11)."""
        space = self._spaces[level]
        self.controller.on_packets_discarded(
            [packet for packet in space.sent.values() if packet.in_flight]
        )
        space.sent.clear()
        space.loss_time = None
        space.discarded = True
        self._pto_count = 0

    def ack_eliciting_in_flight(self) -> bool:
        return any(
            packet.ack_eliciting
            for space in self._spaces.values()
            if not space.discarded
            for packet in space.sent.values()
        )
