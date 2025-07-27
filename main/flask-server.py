from flask import Flask, request, render_template_string, jsonify
import base64
import os

app = Flask(__name__)
FIRMWARE_PATH = "firmware.bin"
VERSION_PATH = "firmware.version"

HTML_FORM = """
<!doctype html>
<title>ESP32 OTA Firmware Upload</title>
<h2>Upload new firmware (.bin)</h2>
<form method=post enctype=multipart/form-data>
  <input type=file name=firmware>
  <input type=submit value=Upload>
</form>
{% if message %}
  <p><b>{{ message }}</b></p>
{% endif %}
"""

@app.route('/', methods=['GET', 'POST'])
def upload_firmware():
    message = ""
    if request.method == 'POST':
        file = request.files.get('firmware')
        version = request.form.get('version', '').strip()
        if file and file.filename.endswith('.bin'):
            file.save(FIRMWARE_PATH)
            # Save version if provided
            if version:
                with open(VERSION_PATH, "w") as vf:
                    vf.write(version)
            message = "Firmware uploaded successfully!"
        else:
            message = "Please upload a .bin file."
    return render_template_string(
        HTML_FORM + """
        <form method=post enctype=multipart/form-data>
            <input type=file name=firmware>
            <input type=text name=version placeholder="Firmware version (optional)">
            <input type=submit value=Upload>
        </form>
        """,
        message=message
    )

@app.route('/firmware', methods=['GET'])
def serve_firmware():
    if not os.path.exists(FIRMWARE_PATH):
        return jsonify({"error": "No firmware available"}), 404
    with open(FIRMWARE_PATH, "rb") as f:
        bin_content = f.read()
    b64 = base64.b64encode(bin_content).decode('utf-8')
    version = ""
    if os.path.exists(VERSION_PATH):
        with open(VERSION_PATH, "r") as vf:
            version = vf.read().strip()
    return jsonify({"bin_content_base64": b64, "version": version})

@app.route('/device_version', methods=['POST'])
def device_version():
    data = request.get_json()
    device_version = data.get("version", "")
    print(f"ESP32 reported version: {device_version}")
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
