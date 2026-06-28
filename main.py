#!/usr/bin/env python3
import argparse, sys
from core.config import load_config
from core.logger import setup_logger
from core.safety import confirm_legal_target

def build_parser():
    p = argparse.ArgumentParser(prog="pentest-toolkit", description="Modular Web App Pentesting Toolkit")
    p.add_argument("--target", "-t", required=True)
    p.add_argument("--config", "-c", default="config/default.yaml")
    p.add_argument("--output", "-o", default="reports/")
    p.add_argument("--confirm-legal", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="module")

    # recon
    recon = sub.add_parser("recon")
    rs = recon.add_subparsers(dest="recon_module")
    db = rs.add_parser("dirbrute")
    db.add_argument("--wordlist", default="wordlists/common.txt")
    db.add_argument("--threads", type=int, default=10)
    se = rs.add_parser("subdomains")
    se.add_argument("--domain", required=True)
    se.add_argument("--no-resolve", action="store_true")

    # vuln
    vuln = sub.add_parser("vuln")
    vs = vuln.add_subparsers(dest="vuln_module")
    sq = vs.add_parser("sqli")
    sq.add_argument("--param")
    sq.add_argument("--method", choices=["GET","POST"], default="GET")
    xs = vs.add_parser("xss")
    xs.add_argument("--param")
    xs.add_argument("--method", choices=["GET","POST"], default="GET")

    # auth
    auth = sub.add_parser("auth")
    aus = auth.add_subparsers(dest="auth_module")

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.module:
        parser.print_help(); sys.exit(0)

    config = load_config(args.config)
    logger = setup_logger(args.verbose)

    if args.module in {"vuln", "auth"}:
        if not confirm_legal_target(args.target, args.confirm_legal):
            logger.error("Use --confirm-legal to acknowledge you have permission to test this target.")
            sys.exit(1)

    logger.info(f"Target: {args.target} | Module: {args.module}")

    if args.module == "recon":
        if args.recon_module == "dirbrute":
            from modules.recon.dir_bruteforce import DirBruteforcer
            m = DirBruteforcer(args.target, config, logger)
            m.report(m.run(wordlist=args.wordlist, threads=args.threads), args.output)
        elif args.recon_module == "subdomains":
            from modules.recon.subdomain_enum import SubdomainEnumerator
            m = SubdomainEnumerator(args.target, config, logger)
            m.report(m.run(domain=args.domain, resolve=not args.no_resolve), args.output)

    elif args.module == "vuln":
        if args.vuln_module == "sqli":
            from modules.vulns.sqli import SQLiTester
            m = SQLiTester(args.target, config, logger)
            m.report(m.run(param=args.param, method=args.method), args.output)
        elif args.vuln_module == "xss":
            from modules.vulns.xss import XSSTester
            m = XSSTester(args.target, config, logger)
            m.report(m.run(param=args.param, method=args.method), args.output)

if __name__ == "__main__":
    main()
