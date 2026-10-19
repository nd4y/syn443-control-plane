from pathlib import Path
import json,os,socket,subprocess,sys,time,urllib.request
binary=str(Path(sys.argv[1]).resolve())
env=os.environ.copy()
env["SYN443_PREVIEW_LISTEN"]="0.0.0.0:8080"
rejected=subprocess.run([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
assert rejected.returncode!=0,"Public bind was accepted"
with socket.socket() as sock:
    sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
base=f"http://127.0.0.1:{port}"
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
env["SYN443_PREVIEW_LISTEN"]=f"127.0.0.1:{port}"
p=subprocess.Popen([binary],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+15
    while True:
        try:
            with opener.open(base+"/healthz",timeout=1) as r: health=json.load(r)
            break
        except OSError:
            if p.poll() is not None or time.monotonic()>=deadline: raise
            time.sleep(.1)
    assert health["productionReady"] is False
    cases=json.loads(Path("contracts/v1/decision-vectors.json").read_text())["cases"]
    for case in cases:
        req=urllib.request.Request(base+"/v1/decision-preview",data=json.dumps(case["input"]).encode(),headers={"Content-Type":"application/json"})
        with opener.open(req,timeout=5) as r: got=json.load(r)
        assert got==case["expected"],case["name"]
finally:
    p.terminate()
    try: code=p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill();p.wait();raise
    if os.name!="nt": assert code==0,code
print("Real API binary: loopback bind, public-bind rejection, health, all30 vectors and shutdown passed")

