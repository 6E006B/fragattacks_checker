#!/usr/bin/env python3

import argparse
import logging
import subprocess


class BColors:
    OK = "\033[92m"
    FAIL = "\033[91m"
    END = "\033[0m"


class Markup:
    OK = BColors.OK + "OK" + BColors.END
    FAIL = BColors.FAIL + "FAIL" + BColors.END


def exec_check(cmd: list[str], max_retries: int, retry: int = 0):
    success = False
    logging.debug(f"[>] $ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, check=True)
        logging.debug(f"STDOUT:\n{result.stdout.decode('utf-8')}")
        if result.stderr:
            logging.debug(f"STDERR:{result.stderr.decode('utf-8')}")
        if b"TEST COMPLETED SUCCESSFULLY" in result.stdout:
            success = True
        elif retry < max_retries and b"Retry to be sure, or manually check result" in result.stdout:
            success = exec_check(cmd, max_retries, retry + 1)
    except subprocess.CalledProcessError as e:
        if retry < max_retries and b"Retry to be sure, or manually check result" in e.stdout:
            success = exec_check(cmd, max_retries, retry + 1)
        else:
            logging.debug(f"Error while execution ({e.returncode}):")
            logging.debug(e.stdout.decode("utf-8"))
            logging.debug(e.stderr.decode("utf-8"))
    logging.info(Markup.OK if success else Markup.FAIL)
    return success


ATTACKS = {
    "amsdu": ["amsdu-inject"],
    "amsdu_bad": ["amsdu-inject-bad"],
    "cache_1": ["ping", "I,E,R,AE"],
    "cache_2": ["ping", "I,E,R,E"],
    "cache_3": ["ping", "I,E,R,AE", "--full-recon"],
    "cache_4": ["ping", "I,E,R,E", "--full-recon"],
    "nc_pns": ["ping", "I,E,E", "--inc-pn", "2"],
    "mixed_plain_1": ["ping", "I,E,P"],
    "mixed_plain_2": ["ping", "I,P,E"],
    "mixed_plain_3": ["ping", "I,P"],
    "mixed_plain_4": ["ping", "I,P,P"],
    "mixed_plain_5": ["linux-plain"],
    "bcast": ["ping", "I,D,P", "--bcast-ra"],
    "eapol_amsdu": ["eapol-amsdu", "I,P"],
    "eapol_amsdu_bad": ["eapol-amsdu-bad", "I,P"],
}

MIXED_KEY_ATTACKS = {
    "mixed_key": ["ping", "I,F,BE,AE"],
    "mixed_key_consecutive": ["ping", "I,F,BE,AE", "--pn-per-qos"],
}


def perform_checks(script: str, interface: str, retries: int, do_mixed_keys: bool = True) -> dict[str, bool]:
    checks = {}
    base_cmd = [script, interface]

    # Sanity checks
    logging.info("[*] Performing sanity checks...")
    cmd = base_cmd + ["ping"]
    if not exec_check(cmd, max_retries=retries):
        raise Exception("Sanity check failed! Check your setup.")
    cmd = base_cmd + ["ping", "I,E,E"]
    if not exec_check(cmd, max_retries=retries):
        cmd += ["--icmp-size", "100"]
        if not exec_check(cmd, max_retries=retries):
            raise Exception("Sanity check failed! Check your setup.")
        else:
            logging.info("[*] Need to set ICMP size to 100")
            base_cmd += ["--icmp-size", "100"]

    for name, params in ATTACKS.items():
        logging.info(f"[*] Checking {name}")
        checks[name] = exec_check(base_cmd + params, max_retries=retries)

    if do_mixed_keys:
        logging.info("[*] Executing mixed key attacks")
        for name, params in MIXED_KEY_ATTACKS.items():
            logging.info(f"[*] Checking {name}")
            checks[name] = exec_check(base_cmd + params, max_retries=retries)
    else:
        logging.info("[ ] Skipping mixed key attacks")

    return checks


def print_entry(name: str, result: bool):
    print("|"+"-"*40)
    print(f"| {' '.join(ATTACKS[name])} | {Markup.FAIL if result else Markup.OK}")


def print_results(checks: dict[str, bool]):
    print("\n| A-MSDU")
    print_entry("amsdu", checks["amsdu"])
    print_entry("amsdu_bad", checks["amsdu_bad"])
    print("\n| Mixed Key")
    if "mixed_key" in checks:
        print_entry("mixed_key", checks["mixed_key"])
        print_entry("mixed_key_consecutive", checks["mixed_key_consecutive"])
    else:
        print("| Skipped...")
    print("\n| Cache")
    print_entry("cache_1", checks["cache_1"])
    print_entry("cache_2", checks["cache_2"])
    print_entry("cache_3", checks["cache_3"])
    print_entry("cache_4", checks["cache_4"])
    print("\n| Non-consecutive PNs")
    print_entry("nc_pns", checks["nc_pns"])
    print("\n| Mixed Plain / Encrypted")
    print_entry("mixed_plain_1", checks["mixed_plain_1"])
    print_entry("mixed_plain_2", checks["mixed_plain_2"])
    print_entry("mixed_plain_3", checks["mixed_plain_3"])
    print_entry("mixed_plain_4", checks["mixed_plain_4"])
    print_entry("mixed_plain_5", checks["mixed_plain_5"])
    print("\n| Broadcast Fragment")
    print_entry("bcast", checks["bcast"])
    print("\n| A-MSDU EAPOL")
    print_entry("eapol_amsdu", checks["eapol_amsdu"])
    print_entry("eapol_amsdu_bad", checks["eapol_amsdu_bad"])


def main():
    parser = argparse.ArgumentParser("""
Wrapper script for fragattack.py to execute all checks in batch.
Remember to call from the appropriate env, i.e. root and activated venv.
""")
    parser.add_argument("-s", "--script", default="./fragattack.py",
                        help="fragattacks script (default: ./fragattack.py)")
    parser.add_argument("-v", "--verbose", action='count', default=0)
    parser.add_argument("-n", "--no-mixed-keys", action="store_true",
                        help="skip the mixed key attacks, which might hang during execution")
    parser.add_argument("-r", "--retries", default=2, type=int,
                        help="number of retries if retry is suggested by script for assurance")
    parser.add_argument("interface", help="interface to use for checks")
    args = parser.parse_args()

    if args.verbose > 0:
        level = logging.INFO if args.verbose == 1 else logging.DEBUG
        logging.basicConfig(level=level)

    results = perform_checks(args.script, args.interface, retries=args.retries, do_mixed_keys=not args.no_mixed_keys)
    print_results(results)


if __name__ == "__main__":
    main()
