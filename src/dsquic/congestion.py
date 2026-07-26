"""Congestion controller interface.

RFC 9002 §7, expressed as the event vocabulary the loss detector in
recovery.py emits: packet sent, packets acknowledged, packets lost,
persistent congestion. A controller consumes those events and exposes a
congestion window and an optional pacing rate. Controllers are pluggable
and live one per module (see new_reno.py); loss detection is fixed and is
not part of this interface.
"""
