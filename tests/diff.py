import json, sys
base_p, test_p, name = sys.argv[1], sys.argv[2], sys.argv[3]
def load(p):
    try: return json.load(open(p))
    except Exception as e: return {"error": str(e)}
b, t = load(base_p), load(test_p)
if "error" in b or "error" in t or "functions" not in b or "functions" not in t:
    print("  [%s] FAILED base=%s test=%s" % (name, b.get("error","?"), t.get("error","?")))
    sys.exit(0)
tb = {f["ea"]: f for f in b["functions"]}
tt = {f["ea"]: f for f in t["functions"]}
tot_g0=tot_g1=tot_s0=tot_s1=improved=0
rows=[]
for ea in sorted(set(tb)&set(tt)):
    m0=tb[ea].get("metrics",{}); m1=tt[ea].get("metrics",{})
    g0,g1=m0.get("gotos",0),m1.get("gotos",0)
    s0,s1=m0.get("switches",0),m1.get("switches",0)
    l0,l1=m0.get("lines",0),m1.get("lines",0)
    tot_g0+=g0; tot_g1+=g1; tot_s0+=s0; tot_s1+=s1
    if g1<g0 or s1<s0: improved+=1
    if g0 or g1 or s0 or s1:
        rows.append("    %s %-24s goto %d->%d  switch %d->%d  lines %d->%d" %
                    (ea, tb[ea]["name"][:24], g0,g1,s0,s1,l0,l1))
print("  [%s] %d funcs compared | gotos %d->%d | switches %d->%d | improved %d" %
      (name, len(set(tb)&set(tt)), tot_g0,tot_g1, tot_s0,tot_s1, improved))
for r in rows[:10]: print(r)
