"""Offline composition of the entire Pages artifact; never deploys it.

The baseline's existing Kyle contact links are explicitly consented. New
dashboard payloads still go through the strict contact/schema gate.
"""
import argparse,json,zipfile,re,stat
from pathlib import Path,PurePosixPath
from gate import read,sha,fields,text_gate,FIELD
HERE=Path(__file__).resolve().parent
def safe_name(name):
    p=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or p.is_absolute() or '..' in p.parts or str(p)!=name:
        raise ValueError('Unsafe archive path')
    return p
def unpack_payload(archive,expected_sha):
    if not re.fullmatch(r'[0-9a-f]{64}',expected_sha) or sha(Path(archive).read_bytes())!=expected_sha:
        raise ValueError('Release asset checksum mismatch')
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        if len(names)!=len(set(names)):raise ValueError('Duplicate archive path')
        if sum(x.file_size for x in entries)>512*1024*1024:raise ValueError('Archive exceeds ESPN lane budget')
        for entry in entries:
            safe_name(entry.filename)
            mode=entry.external_attr>>16
            if stat.S_ISLNK(mode) or entry.is_dir():raise ValueError('Links/directories not accepted in bundle')
        if 'bundle.json' not in names:raise ValueError('Missing bundle manifest')
        manifest=json.loads(z.read('bundle.json'))
        if manifest.get('schema_version')!=1 or manifest.get('privacy_mode')!='buns-consented':raise ValueError('Wrong reviewed lane')
        if manifest.get('contact_gate')!='PASS':raise ValueError('Missing contact gate')
        allowed=set(read(HERE/'reviewed-contract.json')['files'])|{'vendor/'+n for n in read(HERE/'runtime-lock.json')}|{'integrity.mjs','runtime-loader.mjs','runtime-lock.mjs'}
        if set(manifest['files'])!=allowed:raise ValueError('Bundle differs from independently reviewed public-file allowlist')
        expected={'site/'+n for n in manifest['files']}|{'bundle.json'}
        if set(names)!=expected:raise ValueError('Unexpected archive file')
        payload={}
        for name,spec in manifest['files'].items():
            safe_name(name);data=z.read('site/'+name)
            if sha(data)!=spec['sha256'] or len(data)!=spec['bytes']:raise ValueError('Published file integrity mismatch: '+name)
            if name.endswith('.json'):fields(json.loads(data))
            elif name.endswith(('.html','.css','.js','.mjs')):
                text=data.decode();text_gate(text,name)
                if FIELD.search(text):raise ValueError('Contact field in '+name)
            payload[name]=data
    return manifest,payload
def compose(archive,expected_sha,portfolio,baseline_path,destination,mount='almanac/buns',release=False):
    if mount!='almanac/buns':raise ValueError('Only Buns mount reviewed; demo gets its own source/name-gate contract')
    baseline=read(baseline_path);portfolio=Path(portfolio);destination=Path(destination)
    if destination.exists():raise ValueError('Destination exists; use a fresh dated directory')
    # Include every declared existing page, byte-for-byte. Reject unknown live
    # assets rather than silently omit a newly added page during a later deploy.
    actual={p.relative_to(portfolio).as_posix() for p in portfolio.rglob('*') if p.is_file() and not any(part.startswith('.') for part in p.relative_to(portfolio).parts)}
    actual={n for n in actual if not n.startswith('publication-tools/')}
    if actual!=set(baseline['files']):raise ValueError('Portfolio baseline stale: re-review the full current site inventory')
    old={}
    for name,spec in baseline['files'].items():
        p=portfolio/name
        if p.is_symlink() or sha(p.read_bytes())!=spec['sha256']:raise ValueError('Portfolio baseline changed: '+name)
        old[name]=p.read_bytes()
    manifest,payload=unpack_payload(archive,expected_sha)
    if release and manifest.get('release_ready') is not True:raise ValueError('Candidate is not release-approved; Chrome and final go still required')
    # A mount can never shadow any existing file or contain an existing page.
    if any(n==mount or n.startswith(mount+'/') or mount.startswith(n+'/') for n in old):raise ValueError('Mount collides with existing site')
    destination.mkdir(parents=True)
    for name,data in {**old,**{mount+'/'+n:d for n,d in payload.items()}}.items():
        p=destination/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    if any(sha((destination/n).read_bytes())!=s['sha256'] for n,s in baseline['files'].items()):raise ValueError('Existing page changed during composition')
    report={'baseline_revision':baseline['revision'],'preserved_files':len(old),'dashboard_files':len(payload),'mount':mount,'snapshot':manifest['snapshot'],'deployed':False,'existing_kyle_contact_links':'preserved by explicit consent'}
    destination.with_name(destination.name+'-composition.json').write_text(json.dumps(report,indent=2))
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bundle',required=True);p.add_argument('--sha256',required=True);p.add_argument('--portfolio',required=True);p.add_argument('--baseline',required=True);p.add_argument('--out',required=True);p.add_argument('--release',action='store_true')
    a=p.parse_args();print(json.dumps(compose(a.bundle,a.sha256,a.portfolio,a.baseline,a.out,release=a.release),indent=2))
