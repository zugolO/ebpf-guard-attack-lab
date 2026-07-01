"""
Integration tests: encoding/obfuscation bypass attempts (issue #30).

Key question this file answers: does ebpf-guard see the *final* exec/network
event after shell expansion, or only the obfuscated source text of the
interpreter that constructed it?

Answer, confirmed by these tests: for comm/argv-based rules, obfuscating how
a command is *written* (hex-encoded `$(printf ...)`, env-var concatenation)
does not evade detection, because bash fully expands command substitution
and variable interpolation before calling execve() — the kernel-level exec
event ebpf-guard hooks always carries the real resulting binary name. The
same holds for network-layer, port-based rules: encoding the payload sent
over a connection does not change the connection's destination port.

The one place obfuscation *does* work in this ruleset is the DNS entropy/DGA
rule (exfil_dns_high_entropy_qname, rules/exfiltration-extended.yaml): it
only scores the per-label Shannon entropy / digit ratio / bigram rarity of
the qname, so fragmenting genuinely plaintext data across short, low-entropy
DNS labels evades it entirely. That gap is documented, not silently assumed.
"""

import pytest

from attacks.obfuscation_attacks import (
    base64_reverse_shell,
    hex_encoded_curl_exfil,
    env_var_split_command,
    fragmented_dns_exfil,
    dga_style_dns_beacon,
)


pytestmark = pytest.mark.integration


def test_hex_encoded_curl_still_fires_tool_transfer_rule(alerts):
    """`$(printf '\\x63\\x75\\x72\\x6c')` still resolves to a real execve of
    /usr/bin/curl before the network connection is made — comm-based
    detection is not defeated by hiding the literal string "curl" in the
    shell source."""
    proc = hex_encoded_curl_exfil()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "curl" in a.rule_id.lower() or "wget" in a.rule_id.lower()
                             or "tool_transfer" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_env_var_split_curl_still_fires_tool_transfer_rule(alerts):
    """`A=cu; B=rl; $A$B ...` — same result: the shell must fully expand and
    exec the real "curl" binary, so comm-based detection still catches it."""
    proc = env_var_split_command()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "curl" in a.rule_id.lower() or "wget" in a.rule_id.lower()
                             or "tool_transfer" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_base64_encoded_reverse_shell_connection_still_fires_port_rule(alerts):
    """The reverse-shell payload is hidden behind `base64 -d | python3`, but
    the resulting connect() to port 4444 is not obfuscated — a port-based
    exfiltration rule doesn't care what interpreter produced the connection
    or how its source was encoded."""
    proc = base64_reverse_shell()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "exfil" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_fragmented_plaintext_dns_exfil_evades_entropy_rule(alerts):
    """Known gap: splitting un-encoded ASCII data across many short DNS
    labels keeps every individual label's entropy and digit ratio low,
    so exfil_dns_high_entropy_qname never fires even though data is
    genuinely leaving via DNS."""
    proc = fragmented_dns_exfil()
    pid = proc.pid
    proc.wait(timeout=15)

    alerts.wait_for_no_alert(
        predicate=lambda a: "entropy" in a.rule_id.lower() or "dga" in a.rule_id.lower(),
        pid=pid,
        window=3,
    )


def test_dga_style_dns_query_fires_entropy_rule(alerts):
    """Positive control for the test above: a single genuinely random-
    looking, digit-heavy label must still fire the entropy/DGA rule,
    proving the fragmentation test's negative result is a real gap and
    not a broken assertion."""
    proc = dga_style_dns_beacon()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "entropy" in a.rule_id.lower() or "dga" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid
