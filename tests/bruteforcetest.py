"""Brute force: the attempt limits per name and per address, simultaneous requests and the limit on registering
(MIT-06, MIT-10, MIT-30). Runs through securitytest.py."""
import securitytest
from securitytest import *


def run():
    print("== limits")
    unlock()
    _, secb, _ = account("testacc6")
    sql("INSERT INTO auth_throttle (key, failures, window_start) VALUES ('old', 1, now() - interval '2 days'), ('fresh', 1, now())")
    check("5 wrong passwords, the 6th attempt refused", tries([req(client(), "/login", {"username": "testacc6", "password": f"wrong{i}"}) for i in range(6)]), LOCKED)
    check("  old counter cleaned up, fresh one stays", sql("SELECT string_agg(key, ',' ORDER BY key) FROM auth_throttle WHERE key IN ('old', 'fresh')"), "fresh")
    check("right password during the lockout", req(client(), "/login", {"username": "testacc6", "password": PW})[0], 429)
    unlock()
    d = password_step("testacc6")
    st = [req(d, "/login/2fa", {"code": f"{i:06d}"}) for i in range(6)]
    check("5 wrong codes, the 6th refused", (*tries(st), msg(st[-1][1])[:24]), (*LOCKED, "Too many failed attempts"))
    check("right code during the lockout", req(d, "/login/2fa", {"code": fresh(secb, "testacc6")})[0], 429)
    check("5 wrong recovery codes, the 6th refused", tries([req(d, "/login/recover", {"code": f"{i:032d}"}) for i in range(6)]), LOCKED)
    unlock()
    pair, same = (password_step("testacc6"), password_step("testacc6")), fresh(secb, "testacc6")
    check("two at the same time with the same code", sorted(together([lambda x=x: req(x, "/login/2fa", {"code": same})[0] for x in pair])), [302, 400])
    unlock()
    res = together([lambda i=i: req(client(), "/login", {"username": "testacc6", "password": f"together{i}"})[0] for i in range(40)])
    check("40 at once: exactly 5 checked, the rest refused", sorted(res), [400] * 5 + [429] * 35)
    check("  doubling counter up only once", sql("SELECT max(lock_count) FROM auth_throttle"), "1")
    unlock()
    check("IPv4 behind IPv6, IPv6 per /64, plain IPv4", in_app(
        "import throttle; print(*(throttle.client_ip(a) for a in ('::ffff:203.0.113.7', '2001:db8::1', '192.0.2.1')))").stdout.strip(),
        "203.0.113.7 2001:db8::/64 192.0.2.1")
    unlock()

    print("== registering (MIT-30)")
    securitytest.count_registrations = True
    sql(f"DELETE FROM auth_throttle WHERE key = '{registration_counter()}'")
    regs = [req(client(), "/register", {"username": f"limit_{i}", "password": PW}) for i in range(11)]
    check("registering: 10 per hour per address, the 11th 429", ([r[0] for r in regs], regs[-1][2].get("Retry-After")), ([302] * 10 + [429], "3600"))
    check("  with a message", msg(regs[-1][1]), "Too many new accounts from this address. Try again in 60 minutes.")
    check("  no 11th account", sql("SELECT count(*) FROM users WHERE username LIKE 'limit\\_%'"), "10")
    securitytest.count_registrations = False
    sql("DELETE FROM users WHERE username LIKE 'limit\\_%'")
    unlock()
