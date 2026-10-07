import subprocess

import pytest

from etherlens.windows_pktmon import PktmonCapturePrototype, PktmonPrototypeError


def test_prototype_requires_explicit_opt_in(tmp_path):
    capture = PktmonCapturePrototype(
        executable="pktmon.exe", system_name="Windows", environ={}
    )
    with pytest.raises(PktmonPrototypeError, match="disabled"):
        capture.start(tmp_path)


def test_prototype_builds_argument_arrays_without_shell(tmp_path):
    calls = []

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, "ok", "")

    capture = PktmonCapturePrototype(
        executable=r"C:\\Windows\\System32\\pktmon.exe",
        runner=runner,
        system_name="Windows",
        environ={"NSCOUT_EXPERIMENTAL_PKTMON": "1"},
    )
    etl_path = capture.start(tmp_path, max_megabytes=64)
    pcapng_path = capture.stop_and_convert()

    assert calls[0][0][1:6] == ["start", "--capture", "--comp", "nics", "--pkt-size"]
    assert "--file-size" in calls[0][0]
    assert calls[0][1]["check"] is False
    assert calls[1][0][1:] == ["stop"]
    assert calls[2][0][1:3] == ["etl2pcap", str(etl_path)]
    assert pcapng_path.suffix == ".pcapng"
    assert capture.started is False


def test_prototype_rejects_unbounded_capture_size(tmp_path):
    capture = PktmonCapturePrototype(
        executable="pktmon.exe",
        system_name="Windows",
        environ={"NSCOUT_EXPERIMENTAL_PKTMON": "true"},
    )
    with pytest.raises(ValueError, match="between 16 and 2048"):
        capture.start(tmp_path, max_megabytes=4096)
