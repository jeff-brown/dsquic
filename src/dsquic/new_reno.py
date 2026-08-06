"""NewReno congestion controller.

RFC 9002 §7 and Appendix B: slow start, congestion avoidance, the
recovery period, and the response to persistent congestion. The baseline
implementation of the interface in congestion.py.
"""

from dsquic.recovery import SentPacket

LOSS_REDUCTION_FACTOR = 0.5  # kLossReductionFactor (B.1)
MINIMUM_WINDOW_DATAGRAMS = 2  # kMinimumWindow (B.1)
PACING_GAIN = 1.25  # §7.7: N, at least 1, so RTT variation does not idle the window
INITIAL_WINDOW_FLOOR = 14720  # B.1: initial window upper clamp interacts with this floor


class NewReno:
    """RFC 9002 §7 congestion control, state per Appendix B.2."""

    def __init__(self, max_datagram_size: int = 1200) -> None:
        self._max_datagram_size = max_datagram_size
        # B.3: min(10 * max_datagram_size, max(kInitialWindowFloor, 2 * max_datagram_size))
        self._congestion_window = min(
            10 * max_datagram_size, max(INITIAL_WINDOW_FLOOR, 2 * max_datagram_size)
        )
        self._bytes_in_flight = 0
        self._slow_start_threshold = float("inf")
        self._recovery_start_time: float | None = None

    @property
    def congestion_window(self) -> int:
        return self._congestion_window

    @property
    def bytes_in_flight(self) -> int:
        return self._bytes_in_flight

    def pacing_rate(self, smoothed_rtt: float) -> float | None:
        """§7.7: N * congestion_window / smoothed_rtt."""
        if smoothed_rtt <= 0:
            return None
        return PACING_GAIN * self._congestion_window / smoothed_rtt

    def _in_recovery(self, sent_time: float) -> bool:
        """B.4: a packet sent before recovery began does not exit recovery."""
        return self._recovery_start_time is not None and sent_time <= self._recovery_start_time

    def on_packet_sent(self, packet: SentPacket) -> None:
        if packet.in_flight:
            self._bytes_in_flight += packet.size

    def on_packets_acked(self, packets: list[SentPacket], now: float) -> None:
        for packet in packets:
            if not packet.in_flight:
                continue
            self._bytes_in_flight -= packet.size
            # B.5: no window growth for packets sent during recovery.
            if self._in_recovery(packet.time_sent):
                continue
            if self._congestion_window < self._slow_start_threshold:
                # §7.3.1 slow start: grow by bytes acknowledged.
                self._congestion_window += packet.size
            else:
                # §7.3.3 congestion avoidance: one datagram per window acknowledged.
                growth = self._max_datagram_size * packet.size / self._congestion_window
                self._congestion_window += int(growth)

    def on_packets_lost(self, packets: list[SentPacket], now: float) -> None:
        for packet in packets:
            if packet.in_flight:
                self._bytes_in_flight -= packet.size
        # B.6: one window reduction per recovery period, triggered only by
        # packets sent after the current period began.
        latest_sent_time = max(packet.time_sent for packet in packets)
        if self._in_recovery(latest_sent_time):
            return
        self._recovery_start_time = now
        reduced = int(self._congestion_window * LOSS_REDUCTION_FACTOR)
        minimum = MINIMUM_WINDOW_DATAGRAMS * self._max_datagram_size
        self._congestion_window = max(reduced, minimum)
        self._slow_start_threshold = self._congestion_window

    def on_packets_discarded(self, packets: list[SentPacket]) -> None:
        """§6.4: keys discarded; bytes leave flight with no congestion signal."""
        for packet in packets:
            if packet.in_flight:
                self._bytes_in_flight -= packet.size

    def on_persistent_congestion(self) -> None:
        """§7.6.2, B.8: collapse to the minimum window and restart slow start."""
        self._congestion_window = MINIMUM_WINDOW_DATAGRAMS * self._max_datagram_size
        self._recovery_start_time = None
