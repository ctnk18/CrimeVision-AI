"""CrimeVision AI - Intelligent Multimodal Forensic Analysis Platform
Run: streamlit run app.py
"""
import datetime as dt
import hashlib
import io
import os
import random
import tempfile
import uuid

import requests
import streamlit as st
from PIL import Image, ImageDraw

st.set_page_config(page_title="CrimeVision AI", page_icon="🕵️", layout="wide")
st.markdown("""<style>
.stApp{background:#0b0f17;color:#d6dde8}
h1,h2,h3{color:#4fc3f7!important}
[data-testid=stSidebar]{background:#111827;border-right:1px solid #1f2a3d}
.badge{padding:3px 12px;border-radius:12px;font-weight:700;color:#fff}
.Low{background:#2e7d32}.Medium{background:#f9a825;color:#000}
.High{background:#ef6c00}.Critical{background:#c62828}
.card{background:#111827;border:1px solid #1f2a3d;border-radius:8px;padding:12px;margin:6px 0}
</style>""", unsafe_allow_html=True)

# ---------------------------------------------------------------- state
S = st.session_state
S.setdefault("ledger", [])
S.setdefault("chat", [])
S.setdefault("scene", None)
S.setdefault("evidence_id", f"CV-{dt.date.today():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}")
S.setdefault("opened", dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def add_ledger(src, prefix, t, text, conf=None):
    """Replace-safe ledger insert; IDs are assigned per source."""
    n = sum(1 for e in S.ledger if e["id"].startswith(prefix)) + 1
    S.ledger.append({"id": f"{prefix}-{n:03d}", "source": src, "t": float(t),
                     "event": text, "conf": conf})


def clear_source(prefix):
    S.ledger = [e for e in S.ledger if not e["id"].startswith(prefix)]


def sorted_ledger():
    return sorted(S.ledger, key=lambda e: (e["t"], e["id"]))


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🕵️ CrimeVision AI")
    provider = st.selectbox("LLM provider", ["Groq", "Gemini"])
    api_key = st.text_input(f"{provider} API key", type="password",
                            value=os.environ.get(f"{provider.upper()}_API_KEY", ""))
    DEMO = not api_key
    st.info("🧪 Demo mode (no key): simulated analysis" if DEMO else "🟢 Live LLM mode")
    st.divider()
    st.subheader("⛓ Chain of Custody")
    st.text_input("Evidence ID", S.evidence_id, disabled=True)
    st.text_input("Opened", S.opened, disabled=True)
    investigator = st.text_input("Investigator", "Det. A. Sharma")
    signed = st.checkbox("Investigator sign-off")
    st.caption("✅ Signed" if signed else "⚠️ Unsigned - report will be marked DRAFT")


def llm(system, user):
    """Return LLM text or None on any failure (caller falls back)."""
    if DEMO:
        return None
    try:
        if provider == "Groq":
            r = requests.post("https://api.groq.com/openai/v1/chat/completions",
                              headers={"Authorization": f"Bearer {api_key}"},
                              json={"model": "llama-3.3-70b-versatile", "temperature": 0,
                                    "messages": [{"role": "system", "content": system},
                                                 {"role": "user", "content": user}]},
                              timeout=45)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        r = requests.post("https://generativelanguage.googleapis.com/v1beta/models/"
                          f"gemini-2.0-flash:generateContent?key={api_key}",
                          json={"systemInstruction": {"parts": [{"text": system}]},
                                "contents": [{"parts": [{"text": user}]}],
                                "generationConfig": {"temperature": 0}}, timeout=45)
        r.raise_for_status()
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:  # noqa: BLE001
        st.warning(f"LLM call failed, using demo fallback: {e}")
        return None


# ---------------------------------------------------------------- Tab 1 logic
CLASSES = ["person", "firearm", "edged weapon", "blood spatter", "forced entry point"]
COLORS = {"person": "#4fc3f7", "firearm": "#ff1744", "edged weapon": "#ff9100",
          "blood spatter": "#d500f9", "forced entry point": "#ffea00"}
LEADS = {"firearm": "Secure weapon; request ballistics & serial trace",
         "edged weapon": "Bag blade; swab for DNA/fingerprints",
         "blood spatter": "Photograph pattern; collect samples for DNA profiling",
         "forced entry point": "Cast tool marks; canvass for neighbourhood CCTV",
         "person": "Identify individuals; cross-check against witness statements"}


def detect_objects(data, w, h):
    """Deterministic RT-DETR-style simulation seeded by image hash.
    Swap in a real model (ultralytics RTDETR) here if GPU/weights are available."""
    rng = random.Random(hashlib.sha256(data).hexdigest())
    picks = ["person"] + rng.choices(CLASSES, weights=[3, 2, 2, 2, 2], k=rng.randint(2, 5))
    out = []
    for c in picks:
        bw, bh = rng.uniform(.1, .3) * w, rng.uniform(.12, .35) * h
        x, y = rng.uniform(0, w - bw), rng.uniform(0, h - bh)
        out.append({"class": c, "conf": round(rng.uniform(.62, .98), 2),
                    "box": [int(x), int(y), int(x + bw), int(y + bh)]})
    return out


def assess(dets):
    cs = {d["class"] for d in dets}
    if "firearm" in cs:
        threat = "Critical"
    elif cs & {"edged weapon", "blood spatter"}:
        threat = "High"
    elif "forced entry point" in cs:
        threat = "Medium"
    else:
        threat = "Low"
    if cs & {"firearm", "blood spatter"}:
        scene = "Homicide"
    elif "edged weapon" in cs:
        scene = "Assault"
    elif "forced entry point" in cs:
        scene = "Burglary"
    else:
        scene = "Vandalism"
    leads = [LEADS[c] for c in ["firearm", "edged weapon", "blood spatter",
                                "forced entry point", "person"] if c in cs]
    return threat, scene, leads


# ---------------------------------------------------------------- Tab 2 logic
KEYWORDS = {"gun": "Firearm mentioned", "knife": "Edged weapon mentioned",
            "shot": "Gunshot reported", "ran": "Suspect fled", "fled": "Suspect fled",
            "car": "Vehicle involved", "door": "Entry/door activity", "window": "Window breach",
            "blood": "Blood reported", "scream": "Screaming heard", "mask": "Suspect masked",
            "hit": "Physical assault"}
DEMO_SEGMENTS = [
    (0.0, 6.0, "911, what's your emergency?"),
    (6.0, 14.0, "Someone just broke the back door. I saw a man in a mask with a gun."),
    (14.0, 21.0, "I heard a shot and a scream, then he ran toward a dark car."),
    (21.0, 27.0, "There's blood on the porch. Please hurry."),
]


def transcribe(file):
    """Whisper via Groq when a key exists, else demo transcript."""
    if provider == "Groq" and not DEMO:
        try:
            r = requests.post("https://api.groq.com/openai/v1/audio/transcriptions",
                              headers={"Authorization": f"Bearer {api_key}"},
                              files={"file": (file.name, file.getvalue())},
                              data={"model": "whisper-large-v3",
                                    "response_format": "verbose_json"}, timeout=120)
            r.raise_for_status()
            return [(s["start"], s["end"], s["text"].strip()) for s in r.json()["segments"]]
        except Exception as e:  # noqa: BLE001
            st.warning(f"Whisper API failed, using demo transcript: {e}")
    return DEMO_SEGMENTS


def speaker_for(i, text):
    return "DISPATCHER" if text.endswith("?") or i == 0 else "WITNESS"


# ---------------------------------------------------------------- Tab 3 logic
def classify_motion(speed, still_frames):
    if speed > 60:
        return "Flight from Scene / Escape"
    if speed > 15:
        return "Suspicious Movement / Possible Trespass"
    if still_frames >= 2:
        return "Loitering / Surveillance of Premises"
    return "Subject Present"


DEMO_VIDEO = [(1, "Subject enters frame, slow approach", "Criminal Trespass"),
              (3, "Subject stationary near entrance, handling object", "Loitering"),
              (5, "Weapon-like object visible in subject's hand", "Armed Threat (possible)"),
              (7, "Rapid movement out of frame toward vehicle", "Flight from Scene / Escape")]


def analyze_video(file):
    try:
        import cv2
    except ImportError:
        st.warning("opencv not installed - using demo analysis.")
        return [(t, d, c, None) for t, d, c in DEMO_VIDEO]
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(file.getvalue())
        path = tmp.name
    events, prev, still = [], None, 0
    try:
        cap = cv2.VideoCapture(path)
        fps = cap.get(cv2.CAP_PROP_FPS) or 25
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        bg = cv2.createBackgroundSubtractorMOG2(history=50, varThreshold=40)
        for idx in range(0, total, max(int(fps // 2), 1)):  # 2 samples / second
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ok, frame = cap.read()
            if not ok:
                break
            frame = cv2.resize(frame, (640, int(640 * frame.shape[0] / frame.shape[1])))
            mask = cv2.threshold(bg.apply(frame), 200, 255, cv2.THRESH_BINARY)[1]
            cnts, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            cnts = [c for c in cnts if cv2.contourArea(c) > 800]
            if not cnts:
                prev = None
                continue
            m = cv2.moments(max(cnts, key=cv2.contourArea))
            c = (m["m10"] / max(m["m00"], 1), m["m01"] / max(m["m00"], 1))
            speed = 0 if prev is None else ((c[0] - prev[0]) ** 2 + (c[1] - prev[1]) ** 2) ** .5
            still = still + 1 if speed < 5 else 0
            label = classify_motion(speed, still)
            if not events or events[-1][2] != label:
                events.append((round(idx / fps, 1),
                               f"Tracked subject at ({int(c[0])},{int(c[1])}), speed {speed:.0f}px/step",
                               label, c))
            prev = c
        cap.release()
    except Exception as e:  # noqa: BLE001
        st.warning(f"Video processing error ({e}); using demo analysis.")
        return [(t, d, c, None) for t, d, c in DEMO_VIDEO]
    finally:
        os.unlink(path)
    return events or [(t, d, c, None) for t, d, c in DEMO_VIDEO]


# ---------------------------------------------------------------- Tab 4 logic
SYN = {"weapon": ["firearm", "gun", "knife", "edged", "weapon", "shot"],
       "fled": ["fled", "flight", "ran", "escape"], "flee": ["fled", "flight", "ran", "escape"],
       "blood": ["blood"], "suspect": ["person", "subject", "man", "suspect"],
       "entry": ["entry", "door", "window", "trespass", "breach"]}


def retrieve(q, k=5):
    toks = set(w.strip("?.,!").lower() for w in q.split())
    terms = set(toks)
    for t in toks:
        for key, vals in SYN.items():
            if t.startswith(key[:4]):
                terms |= set(vals)
    scored = [(sum(t in e["event"].lower() for t in terms), e) for e in S.ledger]
    return [e for s, e in sorted(scored, key=lambda x: -x[0]) if s > 0][:k]


def ledger_text(entries):
    return "\n".join(f"[{e['id']}] t={e['t']:.1f}s ({e['source']}): {e['event']}"
                     for e in sorted(entries, key=lambda e: e["t"]))


def answer(q):
    if not S.ledger:
        return "No evidence in the ledger yet. Run analysis in Tabs 1-3 first."
    out = llm("You are a forensic evidence assistant. Answer ONLY from the evidence ledger "
              "provided. Cite evidence IDs in [brackets] for every claim. If the ledger does "
              "not contain the answer, reply exactly: 'Insufficient evidence in ledger.' "
              "Never speculate.", f"LEDGER:\n{ledger_text(S.ledger)}\n\nQUESTION: {q}")
    if out:
        return out
    hits = retrieve(q)
    if not hits:
        return "Insufficient evidence in ledger."
    return "Relevant evidence (chronological):\n" + "\n".join(
        f"- [{e['id']}] t={e['t']:.1f}s - {e['event']}" for e in sorted(hits, key=lambda e: e["t"]))


# ---------------------------------------------------------------- Tab 5 logic
def build_pdf():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Forensic Report {S.evidence_id}")
    st_ = getSampleStyleSheet()
    P = lambda t, s="BodyText": Paragraph(t.replace("&", "&amp;"), st_[s])  # noqa: E731
    f = [P("CrimeVision AI - Forensic Summary Report", "Title"),
         P(f"Evidence ID: {S.evidence_id}<br/>Opened: {S.opened}<br/>"
           f"Generated: {dt.datetime.now():%Y-%m-%d %H:%M:%S}<br/>Investigator: {investigator}<br/>"
           f"Status: {'SIGNED OFF' if signed else 'DRAFT - UNSIGNED'}")]
    if S.scene:
        f += [Spacer(1, 10), P("Scene Analysis", "Heading2"),
              P(f"Threat level: {S.scene['threat']} | Classification: {S.scene['scene']}")]
        f += [P(f"- {l}") for l in S.scene["leads"]]
    f += [Spacer(1, 10), P("Master Event Ledger", "Heading2")]
    rows = [["ID", "T (s)", "Source", "Event"]] + [
        [e["id"], f"{e['t']:.1f}", e["source"], P(e["event"])] for e in sorted_ledger()]
    t = Table(rows, colWidths=[55, 40, 60, 360], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a3d")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), .4, colors.grey),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    f += [t, Spacer(1, 20),
          P("Automated analysis is investigative support and must be verified by a qualified "
            "examiner before use as evidence. Signature: ______________________")]
    doc.build(f)
    return buf.getvalue()


# ================================================================ UI
st.title("CrimeVision AI")
st.caption("Intelligent Multimodal Forensic Analysis Platform")
tabs = st.tabs(["📷 Scene Evidence", "🎙 Witness Audio", "🎥 CCTV Video",
                "🧩 Fusion & Evidence Chat", "📄 PDF Report"])

with tabs[0]:
    up = st.file_uploader("Crime scene photograph", type=["jpg", "jpeg", "png"])
    if up and st.button("Analyze scene", type="primary"):
        try:
            data = up.getvalue()
            img = Image.open(io.BytesIO(data)).convert("RGB")
            dets = detect_objects(data, *img.size)
            threat, scene, leads = assess(dets)
            S.scene = {"threat": threat, "scene": scene, "leads": leads, "dets": dets,
                       "img": data}
            clear_source("IMG")
            for d in dets:
                add_ledger("image", "IMG", 0, f"{d['class']} detected at box {d['box']}",
                           d["conf"])
        except Exception as e:  # noqa: BLE001
            st.error(f"Could not process image: {e}")
    if S.scene:
        sc = S.scene
        img = Image.open(io.BytesIO(sc["img"])).convert("RGB")
        dr = ImageDraw.Draw(img)
        for d in sc["dets"]:
            dr.rectangle(d["box"], outline=COLORS[d["class"]], width=4)
            dr.text((d["box"][0] + 4, d["box"][1] + 4), f"{d['class']} {d['conf']}",
                    fill=COLORS[d["class"]])
        c1, c2 = st.columns([3, 2])
        c1.image(img, use_container_width=True)
        c2.markdown(f"**Threat level** <span class='badge {sc['threat']}'>{sc['threat']}</span>",
                    unsafe_allow_html=True)
        c2.markdown(f"**Scene classification:** {sc['scene']}")
        c2.markdown("**Prioritized leads**")
        for i, l in enumerate(sc["leads"], 1):
            c2.markdown(f"{i}. {l}")
        st.dataframe([{"Item": d["class"], "Confidence": d["conf"], "BBox (x1,y1,x2,y2)": str(d["box"])}
                      for d in sc["dets"]], use_container_width=True)

with tabs[1]:
    au = st.file_uploader("Witness statement / 911-112 call",
                          type=["mp3", "wav", "m4a", "ogg", "flac"])
    if st.button("Transcribe & extract timeline", type="primary"):
        segs = transcribe(au) if au else DEMO_SEGMENTS
        if not au:
            st.info("No file uploaded - showing demo transcript.")
        clear_source("AUD")
        rows = []
        for i, (a, b, text) in enumerate(segs):
            sp = speaker_for(i, text)
            rows.append({"Start": f"{a:.1f}s", "End": f"{b:.1f}s", "Speaker": sp, "Text": text})
            hits = sorted({v for k, v in KEYWORDS.items() if k in text.lower().split() or
                           (len(k) > 3 and k in text.lower())})
            if hits and sp == "WITNESS":
                add_ledger("audio", "AUD", a, f"{'; '.join(hits)} - \"{text}\"")
        S["audio_rows"] = rows
    if S.get("audio_rows"):
        st.dataframe(S["audio_rows"], use_container_width=True)
        st.markdown("**Extracted key events**")
        for e in [e for e in sorted_ledger() if e["source"] == "audio"]:
            st.markdown(f"- `{e['id']}` @ {e['t']:.1f}s - {e['event']}")

with tabs[2]:
    vd = st.file_uploader("CCTV footage", type=["mp4", "avi", "mov", "mkv"])
    if st.button("Analyze video", type="primary"):
        evs = analyze_video(vd) if vd else [(t, d, c, None) for t, d, c in DEMO_VIDEO]
        if not vd:
            st.info("No file uploaded - showing demo analysis.")
        clear_source("VID")
        for t, d, cat, _ in evs:
            add_ledger("video", "VID", t, f"{d} -> {cat}")
    vids = [e for e in sorted_ledger() if e["source"] == "video"]
    if vids:
        st.dataframe([{"ID": e["id"], "Time (s)": e["t"], "Event / Classification": e["event"]}
                      for e in vids], use_container_width=True)

with tabs[3]:
    st.subheader("Master Forensic Ledger")
    if S.ledger:
        st.dataframe([{"ID": e["id"], "T (s)": e["t"], "Source": e["source"],
                       "Event": e["event"], "Conf": e["conf"]} for e in sorted_ledger()],
                     use_container_width=True)
    else:
        st.info("Run analysis in Tabs 1-3 to populate the ledger.")
    st.subheader("Grounded Evidence Chat")
    for role, msg in S.chat:
        st.chat_message(role).markdown(msg)
    if q := st.chat_input("e.g. Was a weapon visible before the suspect fled?"):
        S.chat.append(("user", q))
        S.chat.append(("assistant", answer(q)))
        st.rerun()

with tabs[4]:
    st.write("Generate a court-oriented summary of all evidence, ledger and chain of custody.")
    if not signed:
        st.warning("Investigator sign-off missing: report will be watermarked as DRAFT.")
    if st.button("Generate PDF", type="primary"):
        try:
            S["pdf"] = build_pdf()
        except ImportError:
            st.error("reportlab is not installed.")
        except Exception as e:  # noqa: BLE001
            st.error(f"PDF generation failed: {e}")
    if S.get("pdf"):
        st.download_button("⬇️ Download PDF", S["pdf"],
                           file_name=f"{S.evidence_id}_forensic_report.pdf",
                           mime="application/pdf")
