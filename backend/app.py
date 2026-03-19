from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from pcap_parser import PcapParser

app = Flask(__name__, template_folder='../frontend/templates')
CORS(app)

UPLOAD_FOLDER = '/tmp/pcap_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
CAPTURE_PATH = os.path.join(UPLOAD_FOLDER, 'capture.pcap')


def _require_pcap():
    """Return a PcapParser if a capture is loaded, else None."""
    if not os.path.exists(CAPTURE_PATH):
        return None
    return PcapParser(CAPTURE_PATH)


@app.route('/')
def index():
    return send_from_directory('../frontend/templates', 'index.html')


@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        return jsonify({'error': 'Invalid file type — must be .pcap, .pcapng, or .cap'}), 400
    file.save(CAPTURE_PATH)
    return jsonify(PcapParser(CAPTURE_PATH).parse_all())


@app.route('/api/cert/<int:stream_index>')
def get_cert_detail(stream_index):
    parser = _require_pcap()
    if not parser:
        return jsonify({'error': 'No PCAP loaded'}), 404
    return jsonify(parser.get_cert_detail(stream_index))


@app.route('/api/sip/frame/<int:frame_no>')
def get_sip_frame(frame_no):
    parser = _require_pcap()
    if not parser:
        return jsonify({'error': 'No PCAP loaded'}), 404
    return jsonify(parser.get_sip_frame(frame_no))


@app.route('/api/protocols')
def get_protocols():
    parser = _require_pcap()
    if not parser:
        return jsonify({'error': 'No PCAP loaded'}), 404
    return jsonify({'hierarchy': parser.get_protocol_hierarchy()})


@app.route('/api/debug/t38')
def debug_t38():
    parser = _require_pcap()
    if not parser:
        return jsonify({'error': 'No PCAP loaded'}), 404
    return jsonify(parser.get_t38_debug())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
