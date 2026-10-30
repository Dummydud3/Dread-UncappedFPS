import argparse
import json
import statistics
import struct
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'sax_multiplayer'))
from read_guest_memory import Reader,find_mapping

def relative_target(image,got):
    marker=struct.pack('<QQ',got,0x403)
    at=image.find(marker)
    assert at>=0 and image.find(marker,at+1)<0
    return struct.unpack_from('<Q',image,at+16)[0]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--pid',type=int,required=True)
    ap.add_argument('--seconds',type=float,default=15)
    ap.add_argument('--label',default='baseline')
    ap.add_argument('--patched',action='store_true')
    args=ap.parse_args()
    image=(ROOT.parent/'dread_workbench/output/main.image.bin').read_bytes()
    reader=Reader(args.pid)
    module=0x8504000
    try:
        records=[]
        if args.patched:
            patch=next((ROOT/'dist/DreadDeltaTime/exefs').glob('*.ips')).read_bytes()
            assert patch[:5]==b'IPS32' and patch[-4:]==b'EEOF'
            cursor=5
            while patch[cursor:cursor+4]!=b'EEOF':
                address=int.from_bytes(patch[cursor:cursor+4],'big')-0x100
                size=int.from_bytes(patch[cursor+4:cursor+6],'big')
                code=patch[cursor+6:cursor+6+size]
                records.append(dict(address=hex(address),patched=code.hex()))
                cursor+=6+size
        verify=records[0] if records else None
        verify_address=module+int(verify['address'],16) if verify else module+0x80A38
        verify_bytes=bytes.fromhex(verify['patched']) if verify else image[0x80A38:0x80A58]
        cache=ROOT/'research'/f'mapping-{args.pid}.json'
        mapping=json.loads(cache.read_text())['mapping'] if cache.exists() else None
        if mapping is None or reader.read(mapping+verify_address,len(verify_bytes))!=verify_bytes:
            mapping=find_mapping(reader,verify_address,verify_bytes)
            cache.parent.mkdir(exist_ok=True)
            cache.write_text(json.dumps(dict(pid=args.pid,mapping=mapping)))
        def data(g,n):
            b=reader.read(mapping+g,n)
            if len(b)!=n:raise ValueError(f'Cannot read guest {g:x}')
            return b
        def ptr(g):return struct.unpack('<Q',data(g,8))[0]
        def got(g):return module+relative_target(image,g)
        timer=ptr(got(0x1C62718))
        render=ptr(got(0x1C6CDB0))
        counter=got(0x1C648D8)
        present=got(0x1C6E398)
        cinematic_manager=ptr(got(0x1C62720))
        if args.patched:
            for record in records:
                assert data(module+int(record['address'],16),len(bytes.fromhex(record['patched'])))==bytes.fromhex(record['patched'])
        samples=[]
        start=time.perf_counter()
        while True:
            now=time.perf_counter()-start
            b=data(timer,0x50)
            cinematic=ptr(cinematic_manager+0x58)
            cinematic_bytes=data(cinematic+0x4B0,16) if cinematic else bytes(16)
            samples.append(dict(wall=now,frame=struct.unpack('<I',data(counter,4))[0],
                raw_us=struct.unpack_from('<q',b,0x20)[0],
                elapsed=struct.unpack_from('<f',b,0x2C)[0],
                delta=struct.unpack_from('<f',b,0x30)[0],
                nominal_fps=struct.unpack_from('<f',b,0x40)[0],
                nominal_step=struct.unpack_from('<f',b,0x44)[0],
                wait_ms=struct.unpack_from('<q',b,0x38)[0],
                clamp_enabled=b[0x48],
                present_interval=struct.unpack('<i',data(present,4))[0],
                half_rate_flag=data(render+0x3183660,1)[0],
                cinematic=hex(cinematic),
                cinematic_state=struct.unpack_from('<I',cinematic_bytes)[0],
                cinematic_seconds=struct.unpack_from('<f',cinematic_bytes,12)[0],
                audio_position_seconds=struct.unpack('<f',data(module+0x729AF890,4))[0]))
            if now>=args.seconds:break
            time.sleep(0.02)
        duration=samples[-1]['wall']-samples[0]['wall']
        frame_diff=(samples[-1]['frame']-samples[0]['frame'])&0xFFFFFFFF
        elapsed=samples[-1]['elapsed']-samples[0]['elapsed']
        report=dict(pid=args.pid,label=args.label,patched_records_verified=args.patched,
            timer=hex(timer),renderer=hex(render),wall_seconds=duration,
            simulation_seconds=elapsed,simulation_to_wall_ratio=elapsed/duration,
            engine_updates=frame_diff,average_engine_update_rate=frame_diff/duration,
            delta_median=statistics.median(s['delta'] for s in samples),
            nominal_rates=sorted(set(s['nominal_fps'] for s in samples)),
            present_intervals=sorted(set(s['present_interval'] for s in samples)),
            half_rate_flags=sorted(set(s['half_rate_flag'] for s in samples)),
            samples=samples)
        segments=[];begin=0
        for i in range(1,len(samples)+1):
            if i==len(samples) or any(samples[i][k]!=samples[begin][k] for k in ('cinematic','cinematic_state','half_rate_flag')):
                a,b=samples[begin],samples[i-1];span=b['wall']-a['wall']
                if span>=1:
                    drift=[s['audio_position_seconds']-s['cinematic_seconds'] for s in samples[begin:i]]
                    segments.append(dict(seconds=span,cinematic=a['cinematic'],state=a['cinematic_state'],
                        half_rate_flag=a['half_rate_flag'],
                        engine_updates_per_second=((b['frame']-a['frame'])&0xFFFFFFFF)/span,
                        simulation_ratio=(b['elapsed']-a['elapsed'])/span,
                        cinematic_ratio=(b['cinematic_seconds']-a['cinematic_seconds'])/span,
                        audio_minus_timeline_median=statistics.median(drift),
                        audio_minus_timeline_range=[min(drift),max(drift)]))
                begin=i
        report['segments']=segments
        (ROOT/'research').mkdir(exist_ok=True)
        (ROOT/'research'/f'{args.label}.json').write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2))
    finally:reader.close()

if __name__=='__main__':main()
