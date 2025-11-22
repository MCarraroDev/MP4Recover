# (c) 2025 ActiveTK.
# ------------------------------------------------------------
# Repairs potentially broken MP4 files using various methods.
# Implements an API using FastAPI (called from the PHP side).
# ------------------------------------------------------------

import os
import re
import json
import time
import shutil
import uuid
import tempfile
import threading
import subprocess
from datetime import datetime
from typing import Dict, Optional, List, Tuple

import fcntl
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

SHARED_DIR = "/data"                         # Shared directory (shared with container/host)
IN_DIR  = os.path.join(SHARED_DIR, "in")     # Input reception location
OUT_DIR = os.path.join(SHARED_DIR, "out")    # Result output location
LOG_DIR = os.path.join(SHARED_DIR, "logs")   # Status/Log (JSON) save location
WORK_ROOT = "/work"                          # Work root (temporary files, etc.)
WORK_DIR  = os.path.join(WORK_ROOT, "jobs")  # Working directory for jobs
STATE_FILE = os.path.join(LOG_DIR, "state.json")  # JSON to save state
LOCK_FILE  = STATE_FILE + ".lock"                 # Lock file for state.json

# Minimum seconds to consider "salvaged"
# Exceeding this is considered "partial success"
SALVAGE_MIN_SEC = 0.1

# Minimum seconds to consider "completely successful"
# Exceeding this is considered "success"
SUCCESS_MIN_SEC = 10.0

# Max concurrency limit
MAX_CONCURRENCY = 8

ALLOWED_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

def which(x: str, default: Optional[str] = None) -> str:
    p = shutil.which(x)
    return p if p else (default if default else x)

# External command paths
BIN_MP4DUMP = which("mp4dump", "/usr/local/bin/mp4dump")
BIN_MP4BOX  = which("MP4Box", "MP4Box")
BIN_FFMPEG  = which("ffmpeg", "ffmpeg")
BIN_FFPROBE = which("ffprobe", "ffprobe")
BIN_UNTRUNC = which("untrunc", "untrunc")
BIN_REMOOVER = "node /opt/remoover/index.js"

app = FastAPI(title="MP4 Repair Orchestrator")

def ensure_dirs():
    # Create necessary directories at once
    for d in (SHARED_DIR, IN_DIR, OUT_DIR, LOG_DIR, WORK_ROOT, WORK_DIR):
        os.makedirs(d, exist_ok=True)

def now_iso() -> str:
    # Create timestamp for state recording
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize_basename(name: str) -> str:
    base = os.path.basename(name or "")
    if not base or not ALLOWED_NAME.match(base):
        raise HTTPException(status_code=400, detail="Invalid basename")
    return base

def write_json_atomic(path: str, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def read_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def shell(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int,str,str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate()
        return -1, out, err
    return p.returncode, out, err

def shell_str(cmdline: str, timeout: Optional[int] = None) -> Tuple[int,str,str]:
    p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, executable="/bin/bash")
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate()
        return -1, out, err
    return p.returncode, out, err

ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def sanitize_log(s: Optional[str], limit: int = 40000) -> str:
    # Format log. Remove ANSI/control chars, truncate if too long.
    if not s:
        return ""
    s = ANSI_RE.sub('', s)
    s = CTRL_RE.sub('', s)
    if len(s) > limit:
        s = s[:limit] + "\n…(truncated)…"
    return s

def probe_json(path: str) -> Optional[dict]:
    # Get meta info as JSON using ffprobe. Returns None on failure.
    rc, out, _ = shell([BIN_FFPROBE, "-v", "error", "-show_streams", "-show_format", "-of", "json", path])
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None

def duration_from_probe(pj: dict) -> float:
    # Extract video duration (seconds) from ffprobe result.
    # Returns stream.duration if format.duration is missing.
    d = 0.0
    if not pj:
        return 0.0
    fmt = pj.get("format") or {}
    if "duration" in fmt:
        try:
            return max(0.0, float(fmt["duration"]))
        except:
            pass
    for st in pj.get("streams", []):
        if "duration" in st:
            try:
                d = max(d, float(st["duration"]))
            except:
                pass
    return d

def relaxed_ok(path: str, min_sec: float = SALVAGE_MIN_SEC) -> Tuple[bool, float, str, bool]:
    # Determine failure/partial success/success
    # Should be quite lenient
    det = probe_media_details(path, sample_secs=3.0)
    dur = det["dur_total"] or 0.0
    has_v = det["has_v"]; has_a = det["has_a"]

    if dur < max(0.0, min_sec - 1e-6):
        return (False, dur, f"streams: V={has_v} A={has_a}, duration={dur:.3f}s < {min_sec:.3f}s", False)

    msg = [f"streams: V={has_v} A={has_a}, duration={dur:.3f}s >= {min_sec:.3f}s"]

    # Check if decodable
    v_ok = True
    if has_v:
        vp = det["v_packets"]; vf = det["v_frames"]; vd = det["v_dur"]
        v_ok = ((vp is not None and vp > 0) or (vf is not None and vf > 0))
        msg.append(f"v_packets={vp} v_frames={vf} v_dur={vd}")

    return (True, dur, "; ".join(msg) + ("" if v_ok else " [video not decodable in sampled offsets]"), v_ok)


def unique_temp(prefix: str, suffix: str) -> str:
    rid = uuid.uuid4().hex[:8]
    return os.path.join(WORK_ROOT, f"{prefix}-{rid}{suffix}")

class Step(BaseModel):
    name: str
    status: str 
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    message: Optional[str] = None
    output: Optional[str] = None

class Job(BaseModel):
    job_id: str
    status: str
    created_at: str
    updated_at: str
    src_basename: str
    orig_filename: Optional[str] = None
    ref_basename: Optional[str] = None
    ref_orig_filename: Optional[str] = None
    work_dir: str
    input_path: str
    result_path: Optional[str] = None
    fail_reason: Optional[str] = None
    steps: List[Step] = []

# Lock for state saving & keep job list in memory
STATE_LOCK = threading.RLock()
JOBS: Dict[str, Job] = {}

def _save_state_locked():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(LOCK_FILE, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        data = {k: json.loads(v.model_dump_json()) for k,v in JOBS.items()}
        write_json_atomic(STATE_FILE, data)
        fcntl.flock(lf, fcntl.LOCK_UN)

def save_state():
    with STATE_LOCK:
        _save_state_locked()

def load_state():
    ensure_dirs()
    data = read_json(STATE_FILE, {})
    with STATE_LOCK:
        JOBS.clear()
        for k,v in data.items():
            try:
                JOBS[k] = Job(**v)
            except Exception:
                continue

def update_job(job: Job):
    with STATE_LOCK:
        job.updated_at = now_iso()
        JOBS[job.job_id] = job
        _save_state_locked()

def get_job(job_id: str) -> Job:
    with STATE_LOCK:
        if job_id not in JOBS:
            raise HTTPException(status_code=404, detail="Job not found")
        return JOBS[job_id]

# On server start -> Try loading past state via load_state()
load_state()

def classify_candidate(out_path: str) -> Tuple[str, float, str]:
    # Simple check if output file is not broken
    ok, dur, why, v_ok = relaxed_ok(out_path)
    if not ok:
        return ("reject", dur, why)
    if dur >= SUCCESS_MIN_SEC and (v_ok or not probe_json(out_path) or not any(st.get("codec_type")=="video" for st in (probe_json(out_path) or {}).get("streams", []))):
        return ("success", dur, f"{why}; >= {SUCCESS_MIN_SEC:.3f}s absolute")
    return ("part_success", dur, why)


def finalize(job: Job, candidate: str) -> str:
    # Move file determined as success or partial success to /data/out as final artifact
    dst = os.path.join(OUT_DIR, f"{job.job_id}.mp4")
    os.makedirs(OUT_DIR, exist_ok=True)
    shutil.move(candidate, dst)
    return dst

def step_record(job: Job, step: Step, kind: str, outpath: Optional[str], msg: str):
    # Common processing at step end. Log formatting, state saving
    step.finished_at = now_iso()
    step.status  = "success" if kind=="success" else ("part_success" if kind=="part_success" else "failed")
    step.output  = outpath
    step.message = sanitize_log(msg)
    update_job(job)

def step_begin(job: Job, name: str) -> Step:
    st = Step(name=name, status="pending", started_at=now_iso())
    with STATE_LOCK:
        job.steps.append(st)
        _save_state_locked()
    st.status = "running"
    update_job(job)
    return st

def run_ffmpeg(args: List[str]) -> Tuple[int,str,str]:
    return shell([BIN_FFMPEG] + args)

def strat_fix_avcc(in_path: str) -> Tuple[str, Optional[str], str]:
    # Fix lengthSizeMinusOne in avcC box to 2bit=0b11.
    # Might fix header corruption (wishful thinking)
    with open(in_path, "rb") as f:
        buf = bytearray(f.read())
    hits = []
    i, n = 0, len(buf)
    while i + 8 <= n:
        if buf[i+4:i+8] == b"avcC":
            sz = int.from_bytes(buf[i:i+4], "big")
            if sz >= 8 and i + sz <= n:
                hits.append((i, sz)); i += sz; continue
        i += 1
    if not hits:
        return ("reject", None, "No avcC boxes")
    changed = 0
    for off, sz in hits:
        if sz >= 6:
            b = buf[off+4]
            nb = (b & 0b11111100) | 0b11
            if nb != b:
                buf[off+4] = nb; changed += 1
    if changed == 0:
        return ("reject", None, "avcC looked OK")
    out = unique_temp("fix-avcc", ".mp4")
    with open(out, "wb") as f:
        f.write(buf)
    return ("probe", out, f"Patched avcC in {changed} box(es)")

def strat_ffmpeg_remux(in_path: str) -> Tuple[str, Optional[str], str]:
    out = unique_temp("ffmpeg-remux", ".mp4")
    rc, _o, err = run_ffmpeg(["-hide_banner","-y","-nostdin","-i", in_path, "-map","0","-c","copy","-movflags","+faststart", out])
    if rc == 0 and os.path.exists(out):
        return ("probe", out, "ffmpeg remux")
    return ("reject", None, err)

def strat_mp4box(in_path: str) -> Tuple[str, Optional[str], str]:
    out = unique_temp("mp4box", ".mp4")
    rc, _o, err = shell([BIN_MP4BOX, "-noprog", "-logs=iso@warning", "-add", in_path, "-new", out])
    if rc == 0 and os.path.exists(out):
        return ("probe", out, "MP4Box remux")
    return ("reject", None, err)

def strat_remoover(in_path: str) -> Tuple[str, Optional[str], str]:
    out = unique_temp("remoover", ".mp4")
    rc, _o, e1 = shell_str(f'{BIN_REMOOVER} "{in_path}" "{out}" || true')
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return ("probe", out, "Remoover")
    return ("reject", None, e1)

def strat_untrunc(ref_path: str, in_path: str) -> Tuple[str, Optional[str], str]:
    tmpdir = tempfile.mkdtemp(prefix="untrunc-", dir=WORK_ROOT)
    broken_copy = os.path.join(tmpdir, "broken.mp4")
    shutil.copy2(in_path, broken_copy)

    rc, _o, err = shell([BIN_UNTRUNC, ref_path, broken_copy])

    base, ext = os.path.splitext(broken_copy)
    default_out = f"{base}_fixed{ext if ext else '.mp4'}"
    candidates: List[str] = []

    if os.path.exists(default_out) and os.path.getsize(default_out) > 0:
        candidates.append(default_out)
    else:
        try:
            for name in os.listdir(tmpdir):
                ln = name.lower()
                if "_fixed" in ln and os.path.isfile(os.path.join(tmpdir, name)):
                    p = os.path.join(tmpdir, name)
                    if os.path.getsize(p) > 0:
                        candidates.append(p)
        except Exception:
            pass

    if candidates:
        out = max(candidates, key=lambda p: os.path.getsize(p))
        return ("probe", out, f"untrunc: rc={rc}, picked={os.path.basename(out)}")
    else:
        note = f"untrunc produced no output (rc={rc})"
        if err:
            note += f": {err.strip()[:4000]}"
        return ("reject", None, note)

def strat_reencode_video(in_path: str) -> Tuple[str, Optional[str], str]:
    # Re-decode video only, re-encode with libx264 and output. Audio is removed.
    out = unique_temp("vreenc", ".mp4")
    rc, _o, err = run_ffmpeg(["-hide_banner","-y","-nostdin",
                              "-err_detect","ignore_err","-fflags","+discardcorrupt",
                              "-i", in_path,
                              "-map","0:v:0","-c:v","libx264","-preset","veryfast",
                              "-movflags","+faststart","-an", out])
    if rc == 0 and os.path.exists(out):
        return ("probe", out, "reencode video-only")
    return ("reject", None, err)

def strat_reencode_av(in_path: str) -> Tuple[str, Optional[str], str]:
    # Try re-encoding both video and audio. Ignore all errors.
    out = unique_temp("avreenc", ".mp4")
    rc, _o, err = run_ffmpeg(["-hide_banner","-y","-nostdin",
                              "-err_detect","ignore_err","-fflags","+discardcorrupt",
                              "-i", in_path,
                              "-map","0:v:0?","-c:v","libx264","-preset","veryfast",
                              "-map","0:a:0?","-c:a","aac","-b:a","128k","-ar","44100","-ac","2",
                              "-af","aresample=async=1:first_pts=0",
                              "-movflags","+faststart", out])
    if rc == 0 and os.path.exists(out):
        return ("probe", out, "reencode AV")
    return ("reject", None, err)

def probe_media_details(path: str, sample_secs: float = 3.0) -> dict:
    # Get MP4 details via ffprobe, check packet/frame existence at multiple offsets
    # Numerically evaluate "how much can be recovered"
    pj = probe_json(path) or {}
    fmt = pj.get("format") or {}
    streams = pj.get("streams") or []
    dur_total = duration_from_probe(pj)

    def _flt(x):
        try: return float(x)
        except: return None

    fmt_start = _flt(fmt.get("start_time")) or 0.0
    v_start = None
    a_start = None
    has_v = any(st.get("codec_type") == "video" for st in streams)
    has_a = any(st.get("codec_type") == "audio" for st in streams)
    for st in streams:
        if st.get("codec_type") == "video" and v_start is None:
            v_start = _flt(st.get("start_time"))
        if st.get("codec_type") == "audio" and a_start is None:
            a_start = _flt(st.get("start_time"))
    v_start = v_start or 0.0
    a_start = a_start or 0.0

    # Sample start offset candidates
    offsets = []
    offsets.append(0.0)
    offsets.append(max(0.0, fmt_start))
    if has_v: offsets.append(max(0.0, v_start))
    if dur_total and dur_total > 0:
        offsets.append(max(0.0, dur_total * 0.10))
        offsets.append(max(0.0, dur_total * 0.50))

    # Remove duplicates and sort chronologically
    seen = set()
    cand_offsets = []
    for x in offsets:
        key = round(x, 3)
        if key not in seen:
            seen.add(key)
            cand_offsets.append(key)
    cand_offsets.sort()

    def _num(x):
        try: return int(x)
        except: return None

    def _probe_packets(sel: str, off: float) -> Optional[int]:
        # Read only for a short time from specified offset, count packets
        rc, out, _ = shell([
            BIN_FFPROBE, "-v","error",
            "-probesize","50M","-analyzeduration","50M",
            "-ss", f"{max(0.0, off):.3f}",
            "-t",  f"{max(0.1, sample_secs):.3f}",
            "-select_streams", sel,
            "-count_packets","1",
            "-show_entries","stream=nb_read_packets",
            "-of","json", path
        ])
        if rc == 0:
            try:
                j = json.loads(out)
                if j.get("streams"):
                    s = j["streams"][0]
                    return _num(s.get("nb_read_packets"))
            except:
                pass
        return None

    def _probe_frames(sel: str, off: float) -> Optional[int]:
        # Alternative when packets cannot be picked up, get frame count
        rc, out, _ = shell([
            BIN_FFPROBE, "-v","error",
            "-probesize","50M","-analyzeduration","50M",
            "-ss", f"{max(0.0, off):.3f}",
            "-t",  f"{max(0.1, sample_secs):.3f}",
            "-select_streams", sel,
            "-count_frames","1",
            "-show_entries","stream=nb_read_frames",
            "-of","json", path
        ])
        if rc == 0:
            try:
                j = json.loads(out)
                if j.get("streams"):
                    s = j["streams"][0]
                    return _num(s.get("nb_read_frames"))
            except:
                pass
        return None

    v_packets = None; a_packets = None; v_frames = None
    for off in cand_offsets:
        if has_v and v_packets in (None, 0):
            v_packets = _probe_packets("v:0", off)
        if has_a and a_packets in (None, 0):
            a_packets = _probe_packets("a:0", off)
        # Video undetected -> Try with frame count
        if has_v and (v_packets in (None, 0)) and v_frames in (None, 0):
            v_frames = _probe_frames("v:0", off)
        if (not has_v or (v_packets and v_packets > 0) or (v_frames and v_frames > 0)) and \
           (not has_a or (a_packets and a_packets > 0)):
            break

    # Originally obtained from file info, but
    # broken MP4 file meta info is completely unreliable nonsense so stopped
    v_dur = None
    a_dur = None

    return {
        "has_v": has_v, "has_a": has_a,
        "dur_total": dur_total,
        "v_dur": v_dur, "a_dur": a_dur,
        "v_packets": v_packets, "a_packets": a_packets,
        "v_frames": v_frames,
        "fmt_start": fmt_start, "v_start": v_start, "a_start": a_start,
    }


def iter_atoms(buf: bytes):
    # Look at MP4 atoms (boxes) from the beginning
    i, n = 0, len(buf)
    while i + 8 <= n:
        size = int.from_bytes(buf[i:i+4], "big")
        typ  = buf[i+4:i+8]
        if size == 0:
            yield i, n - i, typ; return
        elif size == 1:
            # 64bit extended size
            if i + 16 > n: return
            size = int.from_bytes(buf[i+8:i+16], "big")
            if size < 16 or i + size > n: return
            yield i, size, typ; i += size
        else:
            if size < 8 or i + size > n: return
            yield i, size, typ; i += size

def find_mdat_ranges(buf: bytes) -> List[Tuple[int,int]]:
    # Get list of offset and length of mdat payload area
    out = []
    for off, sz, typ in iter_atoms(buf):
        if typ == b"mdat":
            out.append((off+8, sz-8))
    return out

def looks_like_annexb(buf: bytes, i: int) -> bool:
    # Detection of AnnexB start code (0x000001 or 0x00000001)
    if i+3 < len(buf) and buf[i]==0 and buf[i+1]==0 and buf[i+2]==1: return True
    if i+4 < len(buf) and buf[i]==0 and buf[i+1]==0 and buf[i+2]==0 and buf[i+3]==1: return True
    return False

def extract_h264_annexb(mdat: bytes) -> bytes:
    # Extract AnnexB format H.264 NAL sequence from mdat (concatenate found start code sections)
    out = bytearray(); i, n = 0, len(mdat)
    while i < n-3:
        if looks_like_annexb(mdat, i):
            j = i + (4 if mdat[i+2]==0 else 3); k = j
            while k < n-3 and not looks_like_annexb(mdat, k): k += 1
            out += mdat[i:k]; i = k
        else:
            i += 1
    return bytes(out)

def extract_h264_lenpref(mdat: bytes, nal_len_size: int) -> bytes:
    # Convert length-prefixed (HVCC/avcC type) H.264 to AnnexB and extract
    out = bytearray(); i, n = 0, len(mdat)
    while i + nal_len_size <= n:
        ln = int.from_bytes(mdat[i:i+nal_len_size], "big"); i += nal_len_size
        if ln <= 0 or i + ln > n: break
        out += b"\x00\x00\x00\x01"; out += mdat[i:i+ln]; i += ln
    return bytes(out)

def is_plausible_h264(raw: bytes, min_bytes: int = 1024) -> bool:
    # Simple check if extracted byte sequence is "plausible H.264"
    # Confirm there is a certain amount of NAL arrays, and a certain percentage are normal NALs like SPS/PPS/non-IDR
    if len(raw) < min_bytes: return False
    cnt = 0; good = 0; i, n = 0, len(raw)
    while i+4 < n:
        if looks_like_annexb(raw, i):
            j = i + (4 if raw[i+2]==0 else 3)
            if j < n:
                nal_type = raw[j] & 0x1F
                if 1 <= nal_type <= 23: good += 1
                cnt += 1
            i = j + 1
        else:
            i += 1
        if cnt > 2000: break
    return cnt >= 20 and (good / max(1,cnt)) > 0.3

def extract_adts_aac(mdat: bytes) -> bytes:
    # Extract only ADTS AAC frames from mdat
    out = bytearray(); i, n = 0, len(mdat)
    while i+7 <= n:
        if (mdat[i] == 0xFF) and (mdat[i+1] & 0xF0) == 0xF0:
            flen = ((mdat[i+3] & 0x03) << 11) | (mdat[i+4] << 3) | ((mdat[i+5] & 0xE0) >> 5)
            if flen < 7 or i + flen > n: i += 1; continue
            out += mdat[i:i+flen]; i += flen
        else:
            i += 1
    return bytes(out)

def strat_rawscan_wrap(in_path: str) -> Tuple[str, Optional[str], str]:
    # Scan mdat directly, extract as ES if H.264/AAC found
    # Seems reckless but giving it a try
    with open(in_path, "rb") as f:
        buf = f.read()
    mdats = find_mdat_ranges(buf)
    if not mdats:
        return ("reject", None, "no mdat")
    raw_h264 = bytearray(); raw_aac = bytearray()
    for off, sz in mdats:
        chunk = buf[off:off+sz]
        ab = extract_h264_annexb(chunk)
        if is_plausible_h264(ab): raw_h264 += ab
        else:
            for L in (4,2,1):
                lp = extract_h264_lenpref(chunk, L)
                if is_plausible_h264(lp):
                    raw_h264 += lp; break
        ad = extract_adts_aac(chunk)
        if ad: raw_aac += ad
    wrote_v = wrote_a = False
    tmpd = tempfile.mkdtemp(prefix="rawscan-", dir=WORK_ROOT)
    h264p = os.path.join(tmpd, "raw.h264")
    aacp  = os.path.join(tmpd, "raw.aac")
    if len(raw_h264) >= 1024:
        with open(h264p, "wb") as f: f.write(raw_h264); wrote_v = True
    if len(raw_aac) >= 64:
        with open(aacp, "wb") as f: f.write(raw_aac);  wrote_a = True
    if not wrote_v and not wrote_a:
        return ("reject", None, "raw ES not found")
    out = unique_temp("rawwrap", ".mp4")
    fps_list = [60, 30, 24]
    for fps in fps_list:
        if wrote_v and wrote_a:
            rc, _o, _e = run_ffmpeg(["-hide_banner","-y","-nostdin",
                                     "-r", str(fps), "-f","h264","-i", h264p,
                                     "-f","adts","-i", aacp,
                                     "-c:v","libx264","-preset","veryfast",
                                     "-c:a","aac","-b:a","128k",
                                     "-shortest","-movflags","+faststart", out])
            if rc == 0 and os.path.exists(out):
                return ("probe", out, f"raw-scan wrap V+A @{fps}fps")
        if wrote_v:
            rc, _o, _e = run_ffmpeg(["-hide_banner","-y","-nostdin",
                                     "-r", str(fps), "-f","h264","-i", h264p,
                                     "-c:v","libx264","-preset","veryfast",
                                     "-movflags","+faststart","-an", out])
            if rc == 0 and os.path.exists(out):
                return ("probe", out, f"raw-scan wrap V-only @{fps}fps")
    if wrote_a:
        rc, _o, _e = run_ffmpeg(["-hide_banner","-y","-nostdin",
                                 "-f","adts","-i", aacp,
                                 "-c:a","aac","-b:a","128k",
                                 "-movflags","+faststart","-vn", out])
        if rc == 0 and os.path.exists(out):
            return ("probe", out, "raw-scan wrap A-only")
    return ("reject", None, "raw-scan failed")

FAIL_TEXT = "All recovery methods failed. If you have another video shot in the same environment, selecting it may increase recovery chances."

def run_pipeline(job: Job, ref_abs: Optional[str]) -> None:
    # Pipeline execution. If ref is present, try untrunc first,
    # then proceed with meta repair -> remux -> re-encode -> raw scan
    in_path = job.input_path
    best_partial = {"path": None, "dur": 0.0, "msg": "", "step": ""}

    def try_step(name: str, strat_fn, *args):
        # Common processing for each step. Execute -> Evaluate candidate -> Finalize if success -> Record partial success.
        nonlocal best_partial
        st = step_begin(job, name)
        kind, outp, note = strat_fn(*args)
        if kind == "probe" and outp:
            ck, dur, why = classify_candidate(outp)
            step_record(job, st, ck, outp, f"{note}: {why}")
            if ck == "success":
                job.result_path = finalize(job, outp)
                job.status = "success"
                update_job(job)
                return "final"
            elif ck == "part_success":
                if dur > best_partial["dur"]:
                    best_partial = {"path": outp, "dur": dur, "msg": f"{note}: {why}", "step": name}
                return "cont"
            else:
                return "cont"
        else:
            step_record(job, st, "failed", None, note)
            return "cont"

    # untrunc is success/fail only
    if ref_abs and os.path.exists(ref_abs):
        st = step_begin(job, "untrunc")
        kind, outp, note = strat_untrunc(ref_abs, in_path)
        if kind == "probe" and outp:
            dst = finalize(job, outp)
            job.result_path = dst
            job.status = "success"
            step_record(job, st, "success", dst, f"{note}: accepted as success (untrunc produced fixed file)")
            update_job(job)
            return
        else:
            step_record(job, st, "failed", None, note)

    for fn, name in (
        (strat_fix_avcc,     "fix_avcC"),
        (strat_ffmpeg_remux, "ffmpeg_remux"),
        (strat_mp4box,       "mp4box_remux"),
        (strat_remoover,     "remoover"),
    ):
        r = try_step(name, fn, in_path)
        if r == "final":
            return

    for fn, name in (
        (strat_reencode_av,   "reencode_av"),
        (strat_reencode_video,"reencode_video"),
    ):
        r = try_step(name, fn, in_path)
        if r == "final":
            return

    r = try_step("rawscan_wrap", strat_rawscan_wrap, in_path)
    if r == "final":
        return

    # If no success so far, adopt partial success as final result
    if best_partial["path"]:
        job.result_path = finalize(job, best_partial["path"])
        job.status = "part_success"
        update_job(job)
        return

    # If that also fails, end with failure
    job.status = "failed"
    job.result_path = None
    job.fail_reason = FAIL_TEXT
    update_job(job)

EXECUTOR = threading.BoundedSemaphore(value=MAX_CONCURRENCY)
HALT_NEW = threading.Event()

def worker(job: Job, ref_abs: Optional[str]):
    with EXECUTOR:
        try:
            job.status = "running"; update_job(job)
            run_pipeline(job, ref_abs)
        except Exception as e:
            job.status = "failed"
            job.fail_reason = FAIL_TEXT + f"\n(Internal Exception: {e})"
            update_job(job)

class StatusResponse(BaseModel):
    job_id: str
    status: str
    result_path: Optional[str]
    src_basename: str
    orig_filename: Optional[str]
    ref_basename: Optional[str]
    ref_orig_filename: Optional[str]
    fail_reason: Optional[str]
    steps: List[Step]

@app.get("/healthz")
def healthz():
    # For operation check
    return {"ok": True, "time": now_iso()}

@app.get("/start", response_model=StatusResponse)
def start(
    src: str = Query(..., description="basename under /data/in"),
    ref: Optional[str] = Query(None, description="optional basename under /data/in"),
    orig: Optional[str] = Query(None, description="original filename (display only)"),
    reforig: Optional[str] = Query(None, description="reference original filename (display only)"),
):
    if HALT_NEW.is_set():
        raise HTTPException(status_code=503, detail="Service is currently resetting")
    ensure_dirs()
    src_b = sanitize_basename(src)
    ref_b = sanitize_basename(ref) if ref else None
    src_abs = os.path.join(IN_DIR, src_b)
    if not os.path.exists(src_abs):
        raise HTTPException(status_code=404, detail="Input not found")

    job_id = uuid.uuid4().hex
    work_dir = os.path.join(WORK_DIR, job_id)
    os.makedirs(work_dir, exist_ok=True)
    input_path = os.path.join(work_dir, "input.mp4")
    shutil.copy2(src_abs, input_path)

    job = Job(
        job_id=job_id, status="queued",
        created_at=now_iso(), updated_at=now_iso(),
        src_basename=src_b, orig_filename=(orig or None),
        ref_basename=(ref_b or None), ref_orig_filename=(reforig or None),
        work_dir=work_dir, input_path=input_path, steps=[]
    )
    with STATE_LOCK:
        JOBS[job.job_id] = job
        _save_state_locked()

    ref_abs_path = os.path.join(IN_DIR, ref_b) if ref_b else None
    threading.Thread(target=worker, args=(job, ref_abs_path), daemon=True).start()

    return StatusResponse(
        job_id=job.job_id, status=job.status, result_path=job.result_path,
        src_basename=job.src_basename, orig_filename=job.orig_filename,
        ref_basename=job.ref_basename, ref_orig_filename=job.ref_orig_filename,
        fail_reason=job.fail_reason, steps=job.steps
    )

@app.get("/status", response_model=StatusResponse)
def status(job: str = Query(..., description="job_id")):
    try:
        j = get_job(job)
    except HTTPException as e:
        if e.status_code == 404:
            load_state()
            j = get_job(job)
        else:
            raise
    return StatusResponse(
        job_id=j.job_id, status=j.status, result_path=j.result_path,
        src_basename=j.src_basename, orig_filename=j.orig_filename,
        ref_basename=j.ref_basename, ref_orig_filename=j.ref_orig_filename,
        fail_reason=j.fail_reason, steps=j.steps
    )

@app.get("/list")
def list_jobs():
    # 管理者用
    # 基本的にはコマンドラインからcurlかwgetで叩いてほしい
    with STATE_LOCK:
        return {"jobs":[{"job_id":j.job_id,"status":j.status,"result_path":j.result_path,"created_at":j.created_at,"updated_at":j.updated_at} for j in JOBS.values()]}

@app.get("/logs")
def logs(job: str = Query(...)):
    try:
        j = get_job(job)
    except HTTPException as e:
        if e.status_code == 404:
            load_state()
            j = get_job(job)
        else:
            raise
    return JSONResponse(content=json.loads(j.model_dump_json()))

def _wipe_children(path: str) -> Dict[str,int]:
    files=0; dirs=0
    if not os.path.isdir(path): return {"files":0,"dirs":0}
    for name in os.listdir(path):
        p = os.path.join(path, name)
        try:
            if os.path.isfile(p) or os.path.islink(p):
                os.unlink(p); files += 1
            else:
                shutil.rmtree(p, ignore_errors=True); dirs += 1
        except Exception:
            continue
    return {"files":files,"dirs":dirs}

@app.get("/resetswitch")
def resetswitch():
    # 全部の一時データを削除
    ensure_dirs()
    HALT_NEW.set()
    stats = {"in": {"files":0,"dirs":0}, "out": {"files":0,"dirs":0}, "logs": {"files":0,"dirs":0}, "work": {"files":0,"dirs":0}}
    errors: List[str] = []
    try:
        with STATE_LOCK:
            JOBS.clear()
            try:
                _save_state_locked()
            except Exception as e:
                errors.append(f"save_state(empty) failed: {e}")
        try: stats["in"]   = _wipe_children(IN_DIR)
        except Exception as e: errors.append(f"wipe in: {e}")
        try: stats["out"]  = _wipe_children(OUT_DIR)
        except Exception as e: errors.append(f"wipe out: {e}")
        try: stats["logs"] = _wipe_children(LOG_DIR)
        except Exception as e: errors.append(f"wipe logs: {e}")
        try: stats["work"] = _wipe_children(WORK_DIR)
        except Exception as e: errors.append(f"wipe work: {e}")
        try: write_json_atomic(STATE_FILE, {})
        except Exception as e: errors.append(f"write empty state: {e}")
        return {"ok": True, "time": now_iso(), "wiped": stats, "errors": errors}
    finally:
        HALT_NEW.clear()
