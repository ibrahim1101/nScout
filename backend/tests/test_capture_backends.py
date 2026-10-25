from etherlens.capture_backends import REQUIRED_FEATURES, provider_inventory


def _provider(result, provider_id):
    return next(item for item in result["providers"] if item["id"] == provider_id)


def test_non_windows_does_not_offer_windows_probe():
    result = provider_inventory(system_name="Linux", which=lambda _: "/fake/pktmon")
    probe = _provider(result, "windows_pktmon_probe")
    assert probe["available"] is False
    assert probe["selectable"] is False


def test_pktmon_detection_never_claims_capture_parity():
    result = provider_inventory(
        system_name="Windows",
        which=lambda name: r"C:\\Windows\\System32\\pktmon.exe" if name == "pktmon" else None,
        environ={"NSCOUT_EXPERIMENTAL_PKTMON": "1"},
    )
    probe = _provider(result, "windows_pktmon_probe")
    assert probe["available"] is True
    assert probe["requested"] is True
    assert probe["selectable"] is False
    assert probe["capabilities"]["continuous_capture"] == "not_verified"


def test_every_provider_reports_the_required_feature_matrix():
    result = provider_inventory(system_name="Windows", which=lambda _: None, environ={})
    assert result["migration_policy"] == "npcap_fallback_until_verified_parity"
    for provider in result["providers"]:
        assert set(provider["capabilities"]) == set(REQUIRED_FEATURES)
