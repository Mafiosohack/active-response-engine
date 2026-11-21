from __future__ import annotations

import pytest

from are.scoring import rescale_probability, score_evidence

from .conftest import make_ev


def score(cfg, *evidence):
    return score_evidence(evidence, cfg.scoring)


@pytest.mark.parametrize("severity,points", [("critical", 10), ("high", 6), ("medium", 3), ("low", 1), ("info", 0)])
def test_severity_points(cfg, severity, points):
    assert score(cfg, make_ev(severity=severity)).total == points


@pytest.mark.parametrize("count,expected", [(1, 6), (2, 12), (4, 18), (40, 18)])
def test_repeats_add_logarithmically_and_cap_at_three_times_base(cfg, count, expected):
    assert score(cfg, make_ev(count=count)).total == expected


def test_forty_repeats_split_over_records_are_one_group(cfg):
    s = score(cfg, *[make_ev(count=4) for _ in range(10)])
    assert len(s.groups) == 1 and s.groups[0].total_count == 40 and s.total == 18


def test_different_rules_are_separate_groups_and_sum(cfg):
    s = score(cfg, make_ev("TCP_CONNECT_SCAN"), make_ev("Host Brute Force", family="host_sensor"))
    assert s.total == 12 and s.families == ("host_sensor", "net_signature")


def test_ml_rescale_makes_the_alert_threshold_score_nothing(cfg):
    assert rescale_probability(0.5, 0.5) == 0
    assert rescale_probability(0.75, 0.5) == 0.5
    assert rescale_probability(1.0, 0.5) == 1
    assert score(cfg, make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.5, handshake=False)).total == 0


def test_ml_points_formula_and_cap(cfg):
    one = score(cfg, make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=0.75, handshake=False))
    assert one.total == 2                                      # 4 * 0.5 * (1 + 0.25*log2(1))
    many = score(cfg, make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=1.0, count=1000, handshake=False))
    assert many.total == 4                                     # capped below one high rule hit (6)


def test_ml_high_and_medium_rows_merge_per_destination(cfg):
    s = score(
        cfg,
        make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", severity="high", prob=0.9, handshake=False),
        make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", severity="medium", prob=0.6, handshake=False),
    )
    assert len(s.groups) == 1 and s.groups[0].total_count == 2 and s.groups[0].max_probability == 0.9


def test_ml_across_many_destinations_cannot_exceed_the_per_source_cap(cfg):
    evidence = [make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=1.0, dst=f"10.0.0.{i}", handshake=False)
                for i in range(2, 8)]
    s = score(cfg, *evidence)
    assert s.total == 4 and s.ml_capped and s.total < cfg.policy.block.score


def test_correlation_scores_nothing_and_is_not_a_family(cfg):
    s = score(cfg, make_ev("CORRELATED_INCIDENT", family="correlation", severity="critical",
                           stages=("reconnaissance", "initial_access"), technique=None))
    assert s.total == 0 and s.families == () and s.groups == ()


def test_a_family_that_scores_zero_is_not_independent_corroboration(cfg):
    s = score(cfg, make_ev(), make_ev("Host Brute Force", family="host_sensor", severity="info"))
    assert s.families == ("net_signature",)


def test_handshake_flag_is_any_evidence(cfg):
    assert not score(cfg, make_ev(handshake=False)).handshake_confirmed
    assert score(cfg, make_ev(handshake=False), make_ev("X", handshake=True)).handshake_confirmed


# ---- ML as a family: only a confident model counts -------------------------
def _ml(prob, **kw):
    return make_ev("ML_FLOW_ANOMALY", family="anomaly_ml", prob=prob, handshake=False, technique=None, **kw)


def test_the_real_config_sets_the_ml_family_cut_off_at_the_nids_high_confidence_line(cfg):
    assert cfg.scoring.ml.family_min_probability == 0.8


def test_faint_ml_still_adds_points_but_is_not_a_family(cfg):
    s = score(cfg, make_ev(), _ml(0.79))
    assert s.ml_points > 0 and s.total == round(6 + s.ml_points, 2)
    assert s.families == ("net_signature",)


def test_confident_ml_counts_as_a_family(cfg):
    s = score(cfg, make_ev(), _ml(0.8))
    assert s.families == ("anomaly_ml", "net_signature")


def test_one_confident_destination_is_enough_for_ml_to_count(cfg):
    s = score(cfg, make_ev(), _ml(0.6, dst="10.0.0.2"), _ml(0.9, dst="10.0.0.3"))
    assert "anomaly_ml" in s.families


def test_cut_off_set_to_null_counts_any_scoring_ml_as_a_family(cfg):
    cfg.scoring.ml.family_min_probability = None
    s = score(cfg, make_ev(), _ml(0.51))
    assert s.families == ("anomaly_ml", "net_signature")
