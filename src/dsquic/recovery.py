"""Loss detection.

RFC 9002: §5 (RTT estimation), §6 (loss detection, PTO), Appendix A
(reference pseudocode).

Tracks sent packets per packet number space, processes ACK ranges,
declares loss by packet threshold and time threshold, arms the PTO timer
across spaces, and detects persistent congestion. Emits congestion events
to the pluggable controller defined in congestion.py. Lost frames are
sent again in new packets with new packet numbers; packets themselves are
never retransmitted.
"""
