# -*- coding: utf-8 -*-
"""Tests for recursive extraction safety budgets."""

import pytest

from pydecipher import utils


def test_recursion_depth_is_bounded_and_budget_is_shared() -> None:
    """Nested artifact kwargs advance depth while retaining one budget."""
    kwargs = {"max_recursion_depth": 1}

    nested_kwargs = utils.next_recursion_kwargs(kwargs)

    assert nested_kwargs["_recursion_depth"] == 1
    assert nested_kwargs["_extraction_budget"] is kwargs["_extraction_budget"]
    with pytest.raises(utils.ExtractionLimitError):
        utils.next_recursion_kwargs(nested_kwargs)
