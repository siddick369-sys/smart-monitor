import argparse
import json
import math
import time
import threading
import cv2
import numpy as np
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# État du simulateur
sim_state = {
    "torch": False,
    "motion_active": False,
    "proximity_val": 100.0,  # cm (loin)
    "sound_val": 42.0,       # dB (calme)
    "accel_x": 0.05,
    "accel_y": -0.02,
    "accel_z": 9.81,
    "ball_x": 100,
    "ball_y": 100,
    "ball_dx": 5,
    "ball_dy": 4
}
state_lock = threading.Lock()

def generate_mock_frame():
    """Génère une frame synthétique animée pour simuler la caméra d'un smartphone."""
    global sim_state
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    
    with state_lock:
        motion = sim_state["motion_active"]
        torch = sim_state["torch"]
        prox = sim_state["proximity_val"]
        sound = sim_state["sound_val"]

        # Mise à jour position de l'objet mobile
        if motion:
            # Mouvement rapide pour déclencher la détection OpenCV
            sim_state["ball_x"] += sim_state["ball_dx"] * 3
            sim_state["ball_y"] += sim_state["ball_dy"] * 3
        else:
            # Mouvement très lent ou statique
            sim_state["ball_x"] += sim_state["ball_dx"]
            sim_state["ball_y"] += sim_state["ball_dy"]

        if sim_state["ball_x"] <= 40 or sim_state["ball_x"] >= 600:
            sim_state["ball_dx"] *= -1
        if sim_state["ball_y"] <= 40 or sim_state["ball_y"] >= 440:
            sim_state["ball_dy"] *= -1

        bx = int(sim_state["ball_x"])
        by = int(sim_state["ball_y"])

    # Fond de décor (simulateur pièce / laboratoire)
    img[:, :] = (30, 30, 35)
    cv2.rectangle(img, (50, 80), (590, 420), (50, 50, 55), -1)
    cv2.rectangle(img, (50, 80), (590, 420), (80, 80, 90), 2)

    # Si la torche est allumée, simuler un flash lumineux
    if torch:
        cv2.circle(img, (580, 50), 30, (0, 255, 255), -1)
        cv2.putText(img, "TORCHE ACTIVE", (420, 55), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 2)
        # Éclaircir l'image
        img = cv2.add(img, np.full_like(img, 60))

    # Objet en mouvement (cible mobile pour la détection)
    color = (0, 0, 255) if motion else (0, 200, 100)
    radius = 35 if motion else 25
    cv2.circle(img, (bx, by), radius, color, -1)
    cv2.putText(img, "CIBLE" if not motion else "INTRUSION!", (bx - 30, by - 40),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)

    # Bandeau supérieur
    cv2.rectangle(img, (0, 0), (640, 40), (20, 20, 20), -1)
    cv2.putText(img, "IP WEBCAM ANDROID (SIMULATEUR TP4)", (15, 25), cv2.FONT_HERSHEY_DUPLEX, 0.6, (0, 255, 200), 1)

    # Télémétrie en incrustation
    info_txt = f"Proximite: {prox:.1f}cm | Bruit: {sound:.1f}dB | Torche: {'ON' if torch else 'OFF'}"
    cv2.putText(img, info_txt, (15, 460), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
    cv2.putText(img, time.strftime("%H:%M:%S"), (550, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)

    return img

@app.route("/")
def index():
    return jsonify({
        "service": "Mock IP Webcam Android",
        "endpoints": ["/video", "/shot.jpg", "/sensors.json", "/enabletorch", "/disabletorch", "/simulate_trigger"],
        "state": sim_state
    })

@app.route("/video")
def video_feed():
    def _gen():
        while True:
            frame = generate_mock_frame()
            ret, jpeg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 65])
            if ret:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n')
            time.sleep(0.08) # ~12 fps
    return Response(_gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/shot.jpg")
def shot():
    frame = generate_mock_frame()
    ret, jpeg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
    return Response(jpeg.tobytes(), mimetype='image/jpeg')

@app.route("/sensors.json")
def sensors():
    """Format exact retourné par IP Webcam."""
    now_ms = int(time.time() * 1000)
    with state_lock:
        prox = sim_state["proximity_val"]
        sound = sim_state["sound_val"]
        # Léger bruit naturel si non forcé
        noise_sound = sound + (math.sin(time.time() * 5) * 1.5)
        ax = sim_state["accel_x"]
        ay = sim_state["accel_y"]
        az = sim_state["accel_z"]

    payload = {
        "proximity": {
            "unit": "cm",
            "data": [[now_ms, [round(prox, 1)]]]
        },
        "sound": {
            "unit": "dB",
            "data": [[now_ms, [round(noise_sound, 1)]]]
        },
        "accel": {
            "unit": "m/s2",
            "data": [[now_ms, [round(ax, 2), round(ay, 2), round(az, 2)]]]
        },
        "light": {
            "unit": "lx",
            "data": [[now_ms, [150.0]]]
        },
        "battery_level": {
            "unit": "%",
            "data": [[now_ms, [95.0]]]
        }
    }
    return jsonify(payload)

@app.route("/enabletorch")
def enable_torch():
    with state_lock:
        sim_state["torch"] = True
    return jsonify({"status": "ok", "torch": True})

@app.route("/disabletorch")
def disable_torch():
    with state_lock:
        sim_state["torch"] = False
    return jsonify({"status": "ok", "torch": False})

@app.route("/simulate_trigger", methods=["GET", "POST"])
def simulate_trigger():
    """Endpoint pratique pour injecter des événements de test sur le mock phone."""
    trigger_type = request.args.get("type") or request.form.get("type", "motion")
    val = request.args.get("val") or request.form.get("val")

    with state_lock:
        if trigger_type == "proximity":
            sim_state["proximity_val"] = float(val) if val is not None else 0.0
        elif trigger_type == "sound":
            sim_state["sound_val"] = float(val) if val is not None else 92.0
        elif trigger_type == "accel":
            sim_state["accel_z"] = float(val) if val is not None else 25.0
        elif trigger_type == "motion":
            sim_state["motion_active"] = (val.lower() == "true") if val else True
        elif trigger_type == "reset":
            sim_state["proximity_val"] = 100.0
            sim_state["sound_val"] = 42.0
            sim_state["accel_z"] = 9.81
            sim_state["motion_active"] = False
            sim_state["torch"] = False

    return jsonify({"status": "ok", "updated_type": trigger_type, "state": sim_state})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock IP Webcam Server")
    parser.add_argument("--port", type=int, default=8081, help="Port d'écoute (défaut: 8081)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Hôte (défaut: 127.0.0.1)")
    args = parser.parse_args()

    print(f"[*] Démarrage du Simulateur IP Webcam sur http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
