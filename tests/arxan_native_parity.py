"""Compare C++ discovery with the independent Python implementation on a sample.
Usage: python3 tests/arxan_native_parity.py native_driver binary output.json
"""
import json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from arxan_reference import MachO,analyze

def compare(driver,binary,output):
    image=MachO(binary);report=analyze(image)
    command=[driver,str(binary),hex(image.text[0]),hex(image.text[1])]
    command += [','.join(str(v) for v in (va,fo,fs,prot)) for va,vs,fo,fs,prot in image.segments]
    text=subprocess.check_output(command,text=True)
    actual=set()
    for line in text.splitlines():
        site,target,start,pattern=line.split()
        actual.add((int(site,16),int(target,16),int(start,16),pattern))
    expected={(int(r['ea'],16),int(r['target'],16),int(r['window']['ea'],16),r['pattern']) for r in report['records']}
    if actual!=expected:raise AssertionError(dict(missing=len(expected-actual),extra=len(actual-expected)))
    result=dict(sha256=image.sha,cpp_matches=len(actual),python_matches=len(expected),identical=True,counts=report['counts'])
    Path(output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':compare(*sys.argv[1:])
