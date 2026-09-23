"""Fail-closed publication boundary. No network, warehouse, or writes here."""
import hashlib,json,re
from pathlib import Path

CONTACT=re.compile(r'email|e_mail|phone|telephone|mobile|address|contact|password|secret|credential|cookie|espn_s2|swid',re.I)
EMAIL=re.compile(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}')
PHONE=re.compile(r'(?<![\w-])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])')
FIELD=re.compile(r'(?:^|[{,])\s*["\x27]([\w -]*(?:email|phone|telephone|address|contact)[\w -]*)["\x27]\s*:',re.I)
GUID=re.compile(r'\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?',re.I)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def text_gate(text,path):
    if EMAIL.search(text) or PHONE.search(text):raise ValueError('Contact-like value in '+path+' (value withheld)')
def field_gate(key,path):
    if CONTACT.search(key):raise ValueError('Forbidden contact field: '+path+'.'+key)
def fields(value,path='$',result=None):
    result=set() if result is None else result
    if isinstance(value,dict):
        for k,v in value.items():
            field_gate(k,path)
            # Only these maps have entity-ID keys. Everything beneath stays declared.
            normalized='*' if path in ('$.current','$.current_eligibility','$.cases') else k
            child=path+'.'+normalized
            result.add(child);fields(v,child,result)
    elif isinstance(value,list):
        for v in value:fields(v,path+'[]',result)
    elif isinstance(value,str):text_gate(value,path)
    return result
def parquet_schema(con,path):
    return [[r[0],r[1]] for r in con.execute('describe select * from read_parquet(?)',[str(path)]).fetchall()]
def parquet_gate(con,path,declared):
    observed=parquet_schema(con,path)
    for name,kind in observed:field_gate(name,str(path.name))
    if observed!=declared:raise ValueError('Undeclared Parquet column/type: '+path.name)
    # Scan every nonnumeric column, including nested/JSON contents. Never print values.
    for name,kind in observed:
        if any(t in kind for t in ('VARCHAR','JSON','STRUCT','MAP')):
            quoted='"'+name.replace('"','""')+'"'
            for (v,) in con.execute(f'select distinct cast({quoted} as varchar) from read_parquet(?)',[str(path)]).fetchall():
                if v is None:continue
                text_gate(v,path.name+'.'+name)
                if FIELD.search(v):raise ValueError('Contact field nested in '+path.name+'.'+name)
    return len(observed)
def validate(path,spec,con):
    if path.is_symlink():raise ValueError('Symlink not publishable: '+path.name)
    if path.suffix=='.parquet':return parquet_gate(con,path,spec['columns'])
    data=path.read_bytes()
    if path.suffix=='.json':
        observed=fields(json.loads(data))
        if observed!=set(spec['fields']):
            raise ValueError('Undeclared JSON fields in '+path.name+': '+', '.join(sorted(observed^set(spec['fields']))[:8]))
        return len(observed)
    if path.suffix!='.wasm':
        source=data.decode('utf-8');text_gate(source,path.name)
        match=FIELD.search(source)
        if match:raise ValueError('Forbidden contact field in '+path.name+': '+match[1])
    if sha(data)!=spec['sha256']:raise ValueError('Unreviewed asset bytes: '+path.name)
    return 0
