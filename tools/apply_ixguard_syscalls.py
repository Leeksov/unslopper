"""Validate and append syscall evidence to IDA; never patch instructions.

Import and call apply(report) from IDAPython. All records are preflighted before
any comments are changed. Existing user comments are preserved.
"""
def validate(report,read,sha,base):
    if report['sha256']!=sha or int(report['base'],16)!=base:
        raise ValueError('input identity/base differs from the report')
    rows=[r for r in report['records'] if r['status']!='unresolved']
    for row in rows:
        if read(int(row['ea'],16),4)!=bytes.fromhex('011000d4'):
            raise ValueError('SVC bytes changed at '+row['ea'])
        for evidence in [row['window']]+row['reads']:
            expected=bytes.fromhex(evidence['bytes'])
            if read(int(evidence['ea'],16),len(expected))!=expected:
                raise ValueError('slice/data bytes changed at '+evidence['ea'])
    return rows

def comment(row):
    reads=', '.join(r['ea']+'='+r['bytes'] for r in row['reads'] if r['writable'])
    args=', '.join(k+'='+v['value'] for k,v in row.get('arguments',{}).items())
    return ('[Unslopper syscall/'+row['status']+'] '+str(row['number'])+' ('+
            (row.get('name') or 'name unknown')+'); '+args+
            ('; conditional on file reads: '+reads if reads else ''))

def apply(report):
    import ida_bytes,ida_nalt
    rows=validate(report,ida_bytes.get_bytes,ida_nalt.retrieve_input_file_sha256().hex(),
                  ida_nalt.get_imagebase())
    changed=0
    for row in rows:
        ea=int(row['ea'],16);old=ida_bytes.get_cmt(ea,False) or '';addition=comment(row)
        if addition in old:continue
        if not ida_bytes.set_cmt(ea,old+'\n'+addition if old else addition,False):
            raise RuntimeError('failed comment at '+row['ea'])
        changed+=1
    return {'validated':len(rows),'appended':changed}
