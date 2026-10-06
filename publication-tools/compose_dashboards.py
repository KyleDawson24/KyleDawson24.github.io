"""Compose the approved dashboard artifacts without committing their contents.

The private builder performs the player/name/Parquet gates. Its sealed archive
digest binds that evidence to these exact bytes. This step additionally checks
the independent public inventory, contact fields, vendor pins and portfolio.

Three lanes, each at its own mount: the consented league (almanac/buns), the
anonymous demo (almanac/demo) and the second consented league (almanac/bsb,
Amendment 1 of the real-name decision, 2026-09-27). No lane may reference
another lane's mount, and no portfolio page may reference a consented mount:
the real-name sites stay unlinked. The BSB lane is explicit and optional: a
caller passes its bundle, or the literal "none" to compose without it, so a
dispatch can never drop a deployed BSB by omission.
"""
import argparse,json,re,stat,zipfile
from pathlib import Path,PurePosixPath
from gate import read,sha,fields,text_gate,FIELD
HERE=Path(__file__).resolve().parent
MOUNTS={'buns-consented':'almanac/buns','anonymous-espn':'almanac/demo','bsb-consented':'almanac/bsb'}
PRIVATE_MOUNTS=('almanac/buns','almanac/bsb')

def cross_links(text,mode):
    # A lane names no other lane's mount; the public demo names no consented one.
    for other,mount in MOUNTS.items():
        if other!=mode and mount in text:
            raise ValueError('Private dashboard link in demo' if mode=='anonymous-espn' and mount in PRIVATE_MOUNTS else 'Cross-link between dashboards')

def safe_name(name):
    p=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or p.is_absolute() or '..' in p.parts or str(p)!=name:
        raise ValueError('Unsafe archive path')

def unpack(archive,digest,mode,contracts):
    if mode not in MOUNTS or not re.fullmatch('[0-9a-f]{64}',digest) or sha(Path(archive).read_bytes())!=digest:
        raise ValueError('Bundle identity or checksum mismatch')
    contract=contracts[mode]
    with zipfile.ZipFile(archive) as z:
        entries=z.infolist();names=[e.filename for e in entries]
        if len(names)!=len(set(names)) or sum(e.file_size for e in entries)>512*1024*1024:
            raise ValueError('Invalid archive inventory')
        for e in entries:
            safe_name(e.filename)
            if e.is_dir() or stat.S_ISLNK(e.external_attr>>16):raise ValueError('Archive link or directory')
        m=json.loads(z.read('bundle.json'))
        if m.get('schema_version')!=1 or m.get('privacy_mode')!=mode:raise ValueError('Wrong privacy boundary')
        if m.get('release_ready') is not True or m.get('contact_gate')!='PASS':raise ValueError('Unsealed or failed contact gate')
        if mode=='anonymous-espn':
            g=m.get('privacy_gate',{})
            if g.get('status')!='PASS':raise ValueError('Anonymous privacy gate missing')
            for key in ('contact_values','contact_fields','real_name_matches','member_guid_matches','guid_values','forbidden_strings','player_identity_mismatches','vendor_checksum_mismatches'):
                if g.get(key)!=0:raise ValueError('Anonymous privacy evidence incomplete or failed')
        allowed=set(contract['files'])
        if set(m['files'])!=allowed or set(names)!=({'bundle.json'}|{'site/'+n for n in allowed}):
            raise ValueError('Archive differs from independently reviewed allowlist')
        result={}
        for name,spec in m['files'].items():
            safe_name(name);data=z.read('site/'+name)
            if sha(data)!=spec['sha256'] or len(data)!=spec['bytes']:raise ValueError('Member integrity mismatch')
            if name.startswith('vendor/'):
                # Approved upstream license contacts/constants apply only to
                # the independently pinned, unchanged vendor bytes.
                if sha(data)!=contract['vendor_sha256'].get(name):raise ValueError('Vendor pin mismatch')
            elif name.endswith('.json'):fields(json.loads(data));cross_links(data.decode(),mode)
            elif name.endswith(('.html','.css','.js','.mjs')):
                text=data.decode();text_gate(text,name)
                if FIELD.search(text):raise ValueError('Forbidden contact field')
                cross_links(text,mode)
            result[name]=data
        return result

def compose(buns_bundle,buns_sha,demo_bundle,demo_sha,portfolio,baseline_path,destination,contracts_path=None,bsb_bundle=None,bsb_sha=None):
    # BSB is explicit: both 'none', or a bundle and its digest. Never one without the other.
    if (bsb_bundle in (None,'none'))!=(bsb_sha in (None,'none')):raise ValueError('BSB bundle and digest must be given together, or both none')
    lanes=[('buns-consented',buns_bundle,buns_sha),('anonymous-espn',demo_bundle,demo_sha)]
    if bsb_bundle not in (None,'none'):lanes.append(('bsb-consented',bsb_bundle,bsb_sha))
    contracts=read(contracts_path or HERE/'dashboard-contracts.json')
    baseline=read(baseline_path);portfolio=Path(portfolio);destination=Path(destination)
    if destination.exists():raise ValueError('Use a fresh output directory')
    actual={p.relative_to(portfolio).as_posix() for p in portfolio.rglob('*') if p.is_file() and not any(part.startswith('.') for part in p.relative_to(portfolio).parts)}
    actual={n for n in actual if not n.startswith('publication-tools/')}
    if actual!=set(baseline['files']):raise ValueError('Portfolio inventory changed; re-review required')
    combined={}
    for name,spec in baseline['files'].items():
        safe_name(name);p=portfolio/name
        if p.is_symlink() or not p.resolve().is_relative_to(portfolio.resolve()) or sha(p.read_bytes())!=spec['sha256']:
            raise ValueError('Portfolio baseline mismatch')
        combined[name]=p.read_bytes()
        if any(m.encode() in combined[name] for m in PRIVATE_MOUNTS):raise ValueError('Portfolio links a consented dashboard')
    counts={}
    for mode,archive,digest in lanes:
        mount=MOUNTS[mode]
        if any(n==mount or n.startswith(mount+'/') or mount.startswith(n+'/') for n in combined):raise ValueError('Mount collision')
        payload=unpack(archive,digest,mode,contracts);counts[mode]=len(payload)
        combined.update({mount+'/'+n:data for n,data in payload.items()})
    destination.mkdir(parents=True)
    for name,data in combined.items():
        out=destination/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
    if any(sha((destination/n).read_bytes())!=sha(data) for n,data in combined.items()):raise ValueError('Composed bytes differ')
    report={'status':'COMPOSED_NOT_DEPLOYED','portfolio_files_preserved':len(baseline['files']),'dashboard_files':counts,'total_files':len(combined),'buns_sha256':buns_sha,'demo_sha256':demo_sha,'bsb_sha256':bsb_sha if 'bsb-consented' in counts else 'none'}
    destination.with_name(destination.name+'-composition.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('buns-bundle','buns-sha','demo-bundle','demo-sha','bsb-bundle','bsb-sha','portfolio','baseline','out'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    print(json.dumps(compose(a.buns_bundle,a.buns_sha,a.demo_bundle,a.demo_sha,a.portfolio,a.baseline,a.out,bsb_bundle=a.bsb_bundle,bsb_sha=a.bsb_sha),indent=2))
