import argparse
import json
from pathlib import Path

from .analyzer import analyze_policy, policy_edges


def main():
    p=argparse.ArgumentParser(); p.add_argument("policy",type=Path); a=p.parse_args()
    data=json.loads(a.policy.read_text(encoding="utf-8"))
    print(json.dumps({"findings":analyze_policy(data),"edges":policy_edges(data)},indent=2))
if __name__=="__main__": main()
