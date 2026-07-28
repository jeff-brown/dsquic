"""Tests for dsquic.congestion."""

from dsquic.congestion import CongestionController
from dsquic.new_reno import NewReno


def test_new_reno_satisfies_the_interface() -> None:
    controller: CongestionController = NewReno()
    assert isinstance(controller, CongestionController)
