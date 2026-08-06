"""Congestion controller interface.

RFC 9002 §7, expressed as the event vocabulary the loss detector in
recovery.py emits: packet sent, packets acknowledged, packets lost,
packets discarded (key retirement, §6.4), persistent congestion. A
controller consumes those events and exposes a congestion window, its
bytes in flight, and an optional pacing rate (per design.md §4.7).
Controllers are pluggable and live one per module (see new_reno.py);
loss detection is fixed and is not part of this interface.
"""

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from dsquic.recovery import SentPacket


@runtime_checkable
class CongestionController(Protocol):
    """The pluggable congestion response (RFC 9002 §7)."""

    @property
    def congestion_window(self) -> int:
        """Bytes allowed in flight; the sender's budget."""
        ...

    @property
    def bytes_in_flight(self) -> int:
        """Bytes of in-flight packets not yet acked, lost, or discarded."""
        ...

    def pacing_rate(self, smoothed_rtt: float) -> float | None:
        """Bytes per second to pace at, or None for no pacing (§7.7).

        The RTT is supplied because recovery owns it; the formula is the
        controller's, since a window-based controller and a rate-based
        one derive it differently.
        """
        ...

    def on_packet_sent(self, packet: "SentPacket") -> None: ...

    def on_packets_acked(self, packets: list["SentPacket"], now: float) -> None: ...

    def on_packets_lost(self, packets: list["SentPacket"], now: float) -> None: ...

    def on_packets_discarded(self, packets: list["SentPacket"]) -> None: ...

    def on_persistent_congestion(self) -> None: ...
