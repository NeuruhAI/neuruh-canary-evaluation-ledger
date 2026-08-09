import argparse,json
from pathlib import Path
from .core import CanaryLedger
def main(argv=None):
    p=argparse.ArgumentParser(prog="neuruh-canary-evaluation-ledger")
    sp=p.add_subparsers(dest="cmd",required=True)
    for n in ("verify","digest","inspect"):
        x=sp.add_parser(n); x.add_argument("file")
    a=p.parse_args(argv); o=CanaryLedger.from_jsonl(Path(a.file).read_text())
    if a.cmd=="verify": print(json.dumps({"ok":True,"length":len(o.entries),"tip":o.tip},sort_keys=True))
    elif a.cmd=="digest": print(o.digest())
    else: print(json.dumps([x.to_dict() for x in o.entries],indent=2,sort_keys=True))
if __name__=="__main__":main()
