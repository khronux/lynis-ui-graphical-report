#!/usr/bin/env python3
"""
Lynis Audit Console - single-file local web app (Python stdlib only).

Run:   python3 lynis_audit_ui.py        (run as your normal user, NOT with sudo)
It opens http://127.0.0.1:<port>. Your root password is asked in the browser,
sent only to this local process, piped to `sudo -S`, and never stored or logged.
Requires: lynis (e.g. sudo pacman -S lynis | apt install lynis | dnf install lynis | zypper in lynis)
"""
import http.server, json, os, platform, re, secrets, shutil, socket, subprocess, sys, threading, webbrowser

TOKEN = secrets.token_urlsafe(24)
PROC = None
LOCK = threading.Lock()
SAFE = re.compile(r"^[A-Za-z0-9_,\- ]{1,200}$")


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""


def sysinfo():
    osr = {}
    try:
        for l in open("/etc/os-release"):
            if "=" in l:
                k, v = l.strip().split("=", 1)
                osr[k] = v.strip('"')
    except Exception:
        pass
    plasma = sh(["plasmashell", "--version"])
    lynis = shutil.which("lynis") or ""
    ver = sh([lynis, "show", "version"]) if lynis else ""
    pm = next((p for p in ("pacman", "apt", "dnf", "zypper") if shutil.which(p)), "")
    hint = {"pacman": "sudo pacman -S lynis", "apt": "sudo apt install lynis",
            "dnf": "sudo dnf install lynis", "zypper": "sudo zypper install lynis"}.get(pm, "install the 'lynis' package")
    return {"os": osr.get("PRETTY_NAME", platform.platform()), "kernel": platform.release(),
            "arch": platform.machine(), "host": socket.gethostname(), "plasma": plasma,
            "lynis_path": lynis, "lynis_version": ver, "install_hint": hint}


def sudo_ok(pw):
    r = subprocess.run(["sudo", "-S", "-k", "-p", "", "-v"], input=pw + "\n", capture_output=True, text=True, timeout=20)
    return r.returncode == 0


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _host_ok(self):
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self._host_ok():
            return self.send_error(403)
        if self.path == "/":
            b = PAGE.replace("__TOKEN__", TOKEN).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif self.path == "/info":
            self._json(sysinfo())
        else:
            self.send_error(404)

    def do_POST(self):
        global PROC
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            return self.send_error(403)
        if self.path == "/stop":
            if PROC and PROC.poll() is None:
                PROC.terminate()
            return self._json({"ok": True})
        if self.path != "/run":
            return self.send_error(404)
        try:
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except Exception:
            return self._json({"error": "Bad request."}, 400)
        lynis = shutil.which("lynis")
        if not lynis:
            return self._json({"error": "Lynis is not installed. Install it with: " + sysinfo()["install_hint"]}, 400)
        pw = d.get("password", "")
        if not pw or not sudo_ok(pw):
            return self._json({"error": "Wrong root/sudo password."}, 401)
        cmd = ["sudo", "-S", "-k", "-p", "", lynis, "audit", "system", "--no-colors"]
        if d.get("quick"):
            cmd.append("--quick")
        if d.get("warnings"):
            cmd.append("--warnings-only")
        if d.get("testmode"):
            t = (d.get("tests") or "").replace(",", " ").strip()
            if not SAFE.match(t):
                return self._json({"error": "Test IDs/groups may only contain letters, digits, - and _."}, 400)
            cmd += ["--tests-from-group" if d.get("group") else "--tests", t]
        with LOCK:
            if PROC and PROC.poll() is None:
                return self._json({"error": "An audit is already running."}, 409)
            PROC = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env={**os.environ, "LANG": "C", "LC_ALL": "C"}, bufsize=0)
        PROC.stdin.write((pw + "\n").encode())
        PROC.stdin.close()
        pw = None
        d = None
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Command", " ".join(cmd[5:]))
        self.end_headers()
        try:
            while True:
                chunk = PROC.stdout.read1(4096) if hasattr(PROC.stdout, "read1") else PROC.stdout.read(1)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
            PROC.wait()
        except (BrokenPipeError, ConnectionResetError):
            if PROC.poll() is None:
                PROC.terminate()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lynis Audit Console</title>
<style>
:root{--bg:#1b1e20;--panel:#232629;--line:#3a3f44;--txt:#eff0f1;--mut:#9aa1a7;--acc:#3daee9;
--ok:#27ae60;--warn:#f67400;--bad:#da4453;--info:#8e44ad}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 "Noto Sans","Segoe UI",system-ui,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:16px 32px;align-items:center;background:var(--panel)}
h1{font-size:20px;margin:0 24px 0 0;font-weight:600}
.kv{display:flex;flex-direction:column}.kv span:first-child{color:var(--mut);font-size:12px}.kv span:last-child{font-weight:600}
main{padding:20px 24px;max-width:1200px;margin:auto}
.bar{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px}
.opt{display:flex;align-items:center;gap:8px;cursor:pointer}
.opt small{color:var(--mut)}
input[type=text],input[type=password]{background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:7px 10px;font:inherit}
input:focus,button:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
button{font:inherit;border:1px solid var(--line);background:#2f343a;color:var(--txt);padding:8px 16px;border-radius:4px;cursor:pointer}
button.go{background:var(--acc);border-color:var(--acc);color:#0b1a22;font-weight:600}
button.stop{border-color:var(--bad);color:#ff8a95}
button:disabled{opacity:.45;cursor:not-allowed}
.tabs{display:flex;gap:4px;margin:18px 0 0}.tabs button{border-radius:4px 4px 0 0;border-bottom:none}
.tabs button.on{background:var(--panel);border-color:var(--acc);color:var(--acc)}
#status{margin-left:auto;color:var(--mut)}
#live{background:#14161a;border:1px solid var(--line);border-radius:0 6px 6px 6px;height:58vh;overflow:auto;padding:12px 14px;font:13px/1.45 "JetBrains Mono","Noto Sans Mono",monospace;white-space:pre-wrap}
#live .sec{color:var(--acc);font-weight:700;margin-top:8px}
.g{color:var(--ok)}.w{color:var(--warn)}.b{color:var(--bad)}.n{color:var(--mut)}
#live .bl{color:var(--bad);font-weight:600}#live .sg{color:var(--warn)}
#reportWrap{display:none}
#bar2{display:none;margin:12px 0;gap:10px}
dialog{background:var(--panel);color:var(--txt);border:1px solid var(--acc);border-radius:8px;padding:22px;width:min(420px,92vw)}
dialog::backdrop{background:rgba(0,0,0,.6)}
dialog h2{margin:0 0 6px;font-size:18px}dialog p{color:var(--mut);margin:0 0 14px}
dialog input{width:100%}#err{color:#ff8a95;min-height:22px;margin:8px 0}
.row{display:flex;gap:10px;justify-content:flex-end}
/* ---------- report (paper style, used on screen + PDF) ---------- */
#report{background:#fff;color:#1d2125;border-radius:6px;padding:28px;font:13px/1.5 "Noto Sans","Segoe UI",sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
#report h1{font-size:26px;margin:0 0 4px;color:#14425e}
#report .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:6px 20px;margin:14px 0;padding:12px;background:#eef3f7;border-radius:6px}
#report .meta b{display:block;font-size:11px;color:#5b6b78;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.card{border-radius:6px;padding:10px 14px;color:#fff}.card b{font-size:26px;display:block;line-height:1.1}
.sec-r{margin:16px 0;border:1px solid #d5dbe0;border-radius:6px;overflow:hidden;break-inside:auto}
.sec-r h3{margin:0;padding:7px 12px;color:#fff;font-size:14px;display:flex;justify-content:space-between;gap:10px;break-after:avoid}
.chips span{background:rgba(255,255,255,.25);border-radius:10px;padding:1px 8px;margin-left:4px;font-size:11px}
.it{display:flex;justify-content:space-between;gap:12px;padding:3px 12px;border-top:1px solid #eef1f3;break-inside:avoid}
.it.g{background:#eaf7ef}.it.w{background:#fff3e6}.it.b{background:#fdebed}.it.n{background:#fff}
.st{font-weight:700;white-space:nowrap}.it.g .st{color:#1e8449}.it.w .st{color:#c25e00}.it.b .st{color:#c0392b}.it.n .st{color:#6b7782}
.fb{padding:6px 12px;border-top:1px solid #eef1f3;break-inside:avoid}
.fb.b{background:#fdebed;border-left:4px solid #da4453}.fb.w{background:#fff3e6;border-left:4px solid #f67400}
.fb a{color:#1b6ca8;font-size:11px;word-break:break-all}
@media print{
 @page{size:A4;margin:12mm}
 body{background:#fff}header,.bar,.tabs,#live,#bar2,dialog{display:none!important}
 main{padding:0;max-width:none}#reportWrap{display:block!important}#report{padding:0;border-radius:0}
}
</style></head><body>
<header>
 <h1>Lynis Audit Console</h1>
 <div class="kv"><span>Operating system</span><span id="iOs">…</span></div>
 <div class="kv"><span>Kernel</span><span id="iKern">…</span></div>
 <div class="kv"><span>Host</span><span id="iHost">…</span></div>
 <div class="kv"><span>Lynis</span><span id="iLy">…</span></div>
</header>
<main>
 <div class="bar">
  <label class="opt"><input type="checkbox" id="oQuick"> Quick mode <small>(no pauses)</small></label>
  <label class="opt"><input type="checkbox" id="oWarn"> Warning mode <small>(warnings only)</small></label>
  <label class="opt"><input type="checkbox" id="oTest"> Test mode</label>
  <input type="text" id="tIds" placeholder="e.g. SSH-7440 AUTH-9262" disabled size="26" aria-label="Test IDs or groups">
  <label class="opt"><input type="checkbox" id="oGroup" disabled> by group <small>(ssh, firewalls…)</small></label>
  <button class="go" id="start">Start audit</button>
  <button class="stop" id="stop" disabled>Stop</button>
  <span id="status">Ready. With no options, a full system audit runs.</span>
 </div>
 <div class="tabs"><button class="on" id="tLive">Live output</button><button id="tRep">Report</button></div>
 <div id="live" aria-live="polite"></div>
 <div id="reportWrap">
  <div id="bar2" style="display:flex">
   <button class="go" id="pdf">Download PDF report</button>
   <button id="raw">Save raw log (.txt)</button>
   <span style="color:var(--mut);align-self:center">In the print window choose “Save as PDF”.</span>
  </div>
  <div id="report"></div>
 </div>
</main>
<dialog id="dlg">
 <form method="dialog" id="pwForm" onsubmit="return false">
  <h2>Root password required</h2>
  <p>Lynis needs root to inspect the whole system. The password is sent only to this local app and is not stored.</p>
  <input type="password" id="pw" autocomplete="current-password" placeholder="Password" aria-label="Root password">
  <div id="err"></div>
  <div class="row"><button type="button" id="cancel">Cancel</button><button type="submit" class="go" id="ok">Run audit</button></div>
 </form>
</dialog>
<script>
const TOKEN="__TOKEN__",$=id=>document.getElementById(id);
let INFO={},RAW="",ctl=null,running=false,startedAt=null,cmdUsed="";
const esc=s=>s.replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const GOOD=/^(OK|DONE|YES|ENABLED|ACTIVE|PROTECTED|HARDENED|STRONG|RUNNING|FOUND|SECURE|PASSED|COMPILED)$/;
const BAD=/^(WARNING|WEAK|UNSAFE|EXPOSED|VULNERABLE|BAD|FAILED|INSECURE)$/;
const WARN=/^(SUGGESTION|NO|NOT FOUND|MEDIUM|DEFAULT|NOT ENABLED|DISABLED|NONE|NOT RUNNING|OFF|PARTIALLY HARDENED|LIMITED|SKIPPED|UNKNOWN|NON DEFAULT)$/;
const cls=s=>BAD.test(s)?"b":GOOD.test(s)?"g":WARN.test(s)?"w":"n";
const ST=/\[\s*([A-Z][A-Z ]*?)\s*\]\s*$/;

fetch("/info").then(r=>r.json()).then(i=>{INFO=i;
 $("iOs").textContent=i.os;$("iKern").textContent=i.kernel+" ("+i.arch+")";$("iHost").textContent=i.host;
 $("iLy").textContent=i.lynis_path?("v"+i.lynis_version):"not installed";
 if(!i.lynis_path)$("status").textContent="Lynis not found. Install: "+i.install_hint;});

$("oTest").onchange=e=>{$("tIds").disabled=$("oGroup").disabled=!e.target.checked;if(e.target.checked)$("tIds").focus()};
function tab(live){$("live").style.display=live?"block":"none";$("reportWrap").style.display=live?"none":"block";
 $("tLive").classList.toggle("on",live);$("tRep").classList.toggle("on",!live)}
$("tLive").onclick=()=>tab(true);
$("tRep").onclick=()=>{buildReport();tab(false)};
$("start").onclick=()=>{
 if($("oTest").checked&&!$("tIds").value.trim()){$("status").textContent="Enter at least one test ID or group for test mode.";$("tIds").focus();return}
 $("err").textContent="";$("pw").value="";$("dlg").showModal();$("pw").focus()};
$("cancel").onclick=()=>{$("pw").value="";$("dlg").close()};
$("pwForm").onsubmit=e=>{e.preventDefault();run();return false};
$("stop").onclick=()=>fetch("/stop",{method:"POST",headers:{"X-Token":TOKEN}});

function lineHtml(l){
 if(/^\[\+\]/.test(l))return'<div class="sec">'+esc(l)+"</div>";
 if(/^\s*!\s/.test(l))return'<div class="bl">'+esc(l)+"</div>";
 if(/^\s*\*\s/.test(l))return'<div class="sg">'+esc(l)+"</div>";
 const m=l.match(ST);
 if(m){const i=l.lastIndexOf("[");return"<div>"+esc(l.slice(0,i))+'<span class="'+cls(m[1])+'">'+esc(l.slice(i))+"</span></div>"}
 return"<div>"+(esc(l)||"&nbsp;")+"</div>"}

async function run(){
 const pw=$("pw").value;$("ok").disabled=true;
 const body=JSON.stringify({password:pw,quick:$("oQuick").checked,warnings:$("oWarn").checked,
  testmode:$("oTest").checked,tests:$("tIds").value,group:$("oGroup").checked});
 $("pw").value="";
 let res;
 try{res=await fetch("/run",{method:"POST",headers:{"X-Token":TOKEN,"Content-Type":"application/json"},body})}
 catch(e){$("err").textContent="Cannot reach the local server.";$("ok").disabled=false;return}
 $("ok").disabled=false;
 if(!res.ok){const j=await res.json().catch(()=>({error:"Request failed."}));$("err").textContent=j.error;$("pw").focus();return}
 $("dlg").close();tab(true);$("live").innerHTML="";RAW="";running=true;startedAt=new Date();
 cmdUsed="lynis audit system "+(res.headers.get("X-Command")||"").replace(/^.*?--no-colors\s*/,"");
 $("start").disabled=true;$("stop").disabled=false;$("pdf").disabled=true;$("status").textContent="Audit running…";
 const rd=res.body.getReader(),dec=new TextDecoder();let buf="";
 const flush=(final)=>{const parts=buf.split("\n");buf=final?"":parts.pop();
  let h="";for(const p of parts){const c=p.replace(/\x1b\[[0-9;]*[A-Za-z]/g,"").replace(/\r/g,"");RAW+=c+"\n";h+=lineHtml(c);
   const s=c.match(/^\[\+\]\s*(.*)/);if(s)$("status").textContent="Running: "+s[1]}
  if(h){const L=$("live"),at=L.scrollTop+L.clientHeight>=L.scrollHeight-40;L.insertAdjacentHTML("beforeend",h);if(at)L.scrollTop=L.scrollHeight}};
 try{for(;;){const{done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});flush(false)}}catch(e){}
 flush(true);running=false;$("start").disabled=false;$("stop").disabled=true;$("pdf").disabled=false;
 $("status").textContent="Audit finished. Open the Report tab to export a PDF.";buildReport();tab(false)}

/* ---------- parse output into a structured report ---------- */
function parse(raw){
 const R={sections:[],warnings:[],suggestions:[],details:[],follow:[]};let cur=null,mode="sect",last=null;
 for(let l of raw.split("\n")){const t=l.trim();
  const sm=t.match(/^\[\+\]\s*(.+)$/);
  if(sm){cur={name:sm[1],items:[]};R.sections.push(cur);mode="sect";continue}
  if(/-\[\s*Lynis.*Results\s*\]-/.test(t)){mode="none";continue}
  let m;
  if((m=t.match(/^Warnings \((\d+)\)/))){mode="warn";continue}
  if((m=t.match(/^Suggestions \((\d+)\)/))){mode="sugg";continue}
  if(/^Follow-up:/.test(t)){mode="follow";continue}
  if(/^Lynis security scan details/.test(t)){mode="details";continue}
  if(!t||/^[-=]{4,}$/.test(t)||/^(Components|Scan mode|Lynis modules|Files):?$/.test(t)&&mode!=="details")continue;
  if(mode==="sect"&&cur){const s=t.match(ST);cur.items.push({text:s?t.slice(0,t.lastIndexOf("[")).trim():t,st:s?s[1]:"",c:s?cls(s[1]):"n"})}
  else if(mode==="warn"||mode==="sugg"){
   if(/^[!*]\s/.test(t)){last={text:t.slice(2),link:""};(mode==="warn"?R.warnings:R.suggestions).push(last)}
   else if(/^https?:/.test(t)&&last)last.link=t;else if(last&&!/^https?:/.test(t))last.text+=" "+t}
  else if(mode==="details"){R.details.push(t)}
  else if(mode==="follow"){R.follow.push(t)}}
 return R}
const hue=i=>(i*47+200)%360;
function buildReport(){
 if(!RAW.trim()){$("report").innerHTML="<p>No audit output yet. Start an audit first.</p>";return}
 const R=parse(RAW),d=INFO,now=startedAt||new Date();
 const grab=re=>{const m=RAW.match(re);return m?m[1]:"n/a"};
 const hi=grab(/Hardening index\s*:\s*(\d+)/),tests=grab(/Tests performed\s*:\s*(\d+)/);
 let good=0,warn=0,bad=0;R.sections.forEach(s=>s.items.forEach(i=>{if(i.c==="g")good++;else if(i.c==="w")warn++;else if(i.c==="b")bad++}));
 const hiN=+hi,hiCol=isNaN(hiN)?"#6b7782":hiN>=75?"#27ae60":hiN>=50?"#f67400":"#da4453";
 let h='<h1>Lynis Security Audit Report</h1><div class="meta">'+
 [["Date",now.toLocaleString()],["Host",d.host],["Operating system",d.os],["Kernel",d.kernel+" ("+d.arch+")"],
  ["Desktop",d.plasma||"n/a"],["Lynis version",d.lynis_version||"n/a"],["Command",cmdUsed]]
  .map(([k,v])=>"<div><b>"+k+"</b>"+esc(String(v))+"</div>").join("")+"</div>";
 h+='<div class="cards"><div class="card" style="background:'+hiCol+'">Hardening index<b>'+esc(hi)+'</b></div>'+
  '<div class="card" style="background:#34495e">Tests performed<b>'+esc(tests)+"</b></div>"+
  '<div class="card" style="background:#da4453">Warnings<b>'+R.warnings.length+"</b></div>"+
  '<div class="card" style="background:#f67400">Suggestions<b>'+R.suggestions.length+"</b></div>"+
  '<div class="card" style="background:#27ae60">Checks OK<b>'+good+"</b></div></div>";
 const fb=(arr,c,title,col)=>arr.length?'<div class="sec-r"><h3 style="background:'+col+'">'+title+'<span class="chips"><span>'+arr.length+"</span></span></h3>"+
  arr.map(x=>'<div class="fb '+c+'">'+esc(x.text)+(x.link?'<br><a href="'+esc(x.link)+'">'+esc(x.link)+"</a>":"")+"</div>").join("")+"</div>":"";
 h+=fb(R.warnings,"b","Warnings","#c0392b")+fb(R.suggestions,"w","Suggestions","#d35400");
 R.sections.forEach((s,i)=>{const c={g:0,w:0,b:0};s.items.forEach(x=>{if(c[x.c]!==undefined)c[x.c]++});
  h+='<div class="sec-r"><h3 style="background:hsl('+hue(i)+',55%,36%)"><span>'+esc(s.name)+'</span><span class="chips">'+
   (c.g?"<span>"+c.g+" ok</span>":"")+(c.w?"<span>"+c.w+" notice</span>":"")+(c.b?"<span>"+c.b+" issue</span>":"")+"</span></h3>"+
   (s.items.length?s.items.map(x=>'<div class="it '+x.c+'"><span>'+esc(x.text)+'</span><span class="st">'+esc(x.st)+"</span></div>").join(""):'<div class="it n"><span>No output for this section</span></div>')+"</div>"});
 if(R.details.length)h+='<div class="sec-r"><h3 style="background:#2c3e50">Scan details</h3>'+R.details.map(x=>'<div class="it n"><span>'+esc(x)+"</span></div>").join("")+"</div>";
 $("report").innerHTML=h}

$("pdf").onclick=()=>{buildReport();tab(false);const t=document.title;
 document.title="lynis-report-"+(INFO.host||"host")+"-"+new Date().toISOString().slice(0,10);
 window.print();setTimeout(()=>document.title=t,500)};
$("raw").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([RAW],{type:"text/plain"}));
 a.download="lynis-raw-"+new Date().toISOString().slice(0,10)+".txt";a.click()};
tab(true);
</script></body></html>
"""


def main():
    if os.geteuid() == 0:
        print("Run this as your normal user (not with sudo); it asks for the password in the browser.")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"Lynis Audit Console running at {url}  (Ctrl+C to quit)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if PROC and PROC.poll() is None:
            PROC.terminate()


if __name__ == "__main__":
    main()
