import subprocess
import json
import base64
import tempfile
import os


class PcapParser:
    def __init__(self, filepath):
        self.filepath = filepath

    def run_tshark(self, args):
        cmd = ['tshark', '-r', self.filepath] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout, result.stderr

    def parse_all(self):
        return {
            'sip': self.parse_sip(),
            't38': self.parse_t38(),
            'tls': self.parse_tls(),
            'summary': self.parse_summary()
        }

    def parse_summary(self):
        frame_out, _ = self.run_tshark([
            '-T', 'fields', '-e', 'frame.number', '-E', 'separator=|'
        ])
        frame_lines = [l.strip() for l in frame_out.strip().split('\n') if l.strip()]
        return {
            'packet_count': len(frame_lines),
            'filepath': self.filepath
        }

    def parse_sip(self):
        """Extract SIP messages and build ladder diagram data."""
        out, _ = self.run_tshark([
            '-Y', 'sip',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'sip.Request-Line',
            '-e', 'sip.Status-Line',
            '-e', 'sip.Call-ID',
            '-e', 'sip.CSeq',
            '-e', 'sip.From',
            '-e', 'sip.To',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-E', 'separator=|',
            '-E', 'occurrence=f'
        ])

        messages = []
        endpoints = set()

        for line in out.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 9:
                continue

            frame_no     = parts[0].strip()
            time_rel     = parts[1].strip()
            src_ip       = parts[2].strip()
            dst_ip       = parts[3].strip()
            request_line = parts[4].strip()
            status_line  = parts[5].strip()
            call_id      = parts[6].strip()
            cseq         = parts[7].strip()
            from_hdr     = parts[8].strip()
            to_hdr       = parts[9].strip()  if len(parts) > 9  else ''
            udp_sport    = parts[10].strip() if len(parts) > 10 else ''
            udp_dport    = parts[11].strip() if len(parts) > 11 else ''
            tcp_sport    = parts[12].strip() if len(parts) > 12 else ''
            tcp_dport    = parts[13].strip() if len(parts) > 13 else ''

            sport = udp_sport or tcp_sport or '5060'
            dport = udp_dport or tcp_dport or '5060'
            src   = f"{src_ip}:{sport}" if src_ip else src_ip
            dst   = f"{dst_ip}:{dport}" if dst_ip else dst_ip

            if request_line:
                label  = request_line
                method = request_line.split(' ')[0]
            elif status_line:
                label  = status_line
                method = 'response'
            else:
                continue

            if not src or not dst:
                continue

            endpoints.add(src)
            endpoints.add(dst)

            try:
                ts = float(time_rel)
            except Exception:
                ts = 0.0

            messages.append({
                'frame': frame_no,
                'time': ts,
                'src': src,
                'dst': dst,
                'label': label,
                'method': method,
                'call_id': call_id,
                'cseq': cseq,
                'from': from_hdr,
                'to': to_hdr,
                'is_request': bool(request_line),
                'is_response': bool(status_line)
            })

        calls = {}
        for msg in messages:
            cid = msg['call_id'] or 'unknown'
            calls.setdefault(cid, []).append(msg)

        return {
            'messages': messages,
            'endpoints': sorted(endpoints),
            'calls': calls
        }

    def get_sip_frame(self, frame_no):
        """Return the full decoded SIP message for a specific frame."""
        out, _ = self.run_tshark([
            '-Y', f'frame.number == {int(frame_no)}',
            '-V', '-O', 'sip,sdp'
        ])
        if not out.strip():
            out, _ = self.run_tshark([
                '-Y', f'frame.number == {int(frame_no)}',
                '-V'
            ])
        return {'text': out.strip()}

    # ── T.38 ──────────────────────────────────────────────────────────────────

    # Field types carrying raw fax image data (non-ECM)
    _NON_ECM_TYPES = {'6', '7', 't4-non-ecm-data', 't4-non-ecm-sig-end'}
    # Field types carrying HDLC-wrapped fax data (ECM)
    _ECM_DATA_TYPES = {
        '0', '1', '2', '3', '4', '5',
        'hdlc-data', 'hdlc-sig-end', 'hdlc-fcs-ok',
        'hdlc-fcs-ok-sig-end', 'hdlc-fcs-bad', 'hdlc-fcs-bad-sig-end'
    }

    def _t38_basic_filter(self):
        """Phase 1: locate T.38 packets using only guaranteed-valid tshark fields.
        Tries 't38' display filter first, falls back to 'udptl' for non-standard ports.
        Returns (lines, filter_used, stderr)."""
        args = [
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-E', 'separator=|'
        ]
        for display_filter in ('t38', 'udptl'):
            out, err = self.run_tshark(['-Y', display_filter] + args)
            lines = [l for l in out.strip().split('\n') if l.strip()]
            if lines:
                return lines, display_filter, err
        return [], 'none', ''

    def _t38_field_data(self, display_filter):
        """Phase 2: extract T.38 msg_type / field_type / field_data per frame.
        Tries two sets of named fields first (fast); falls back to JSON parsing
        (version-agnostic) if the named fields return no data.
        Returns (dict keyed by frame_no, method_name_used)."""

        # Attempt A — named field extraction
        candidate_sets = [
            ['t38.Type_of_msg', 't38.data_Field_Field_Type', 't38.data_Field_Field_Data'],
            ['t38.type_of_msg', 't38.data_field.field_type', 't38.data_field.field_data'],
        ]
        for fields in candidate_sets:
            out, _ = self.run_tshark([
                '-Y', display_filter,
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', fields[0],
                '-e', fields[1],
                '-e', fields[2],
                '-E', 'separator=|'
            ])
            lines = [l for l in out.strip().split('\n') if l.strip()]
            if not lines:
                continue
            has_data = any(
                len(l.split('|')) > 1 and any(p.strip() for p in l.split('|')[1:])
                for l in lines
            )
            if has_data:
                result = {}
                for line in lines:
                    parts = line.split('|')
                    fn = parts[0].strip()
                    if fn:
                        result[fn] = {
                            'msg_type':   parts[1].strip() if len(parts) > 1 else '',
                            'field_type': parts[2].strip() if len(parts) > 2 else '',
                            'field_data': parts[3].strip() if len(parts) > 3 else '',
                        }
                return result, fields[0]

        # Attempt B — JSON parsing (handles any tshark field naming scheme)
        out, _ = self.run_tshark(['-Y', display_filter, '-T', 'json'])
        if out.strip():
            try:
                result = {}
                for pkt in json.loads(out):
                    layers   = pkt.get('_source', {}).get('layers', {})
                    frame_no = str(layers.get('frame', {}).get('frame.number', '')).strip()
                    t38_layer = layers.get('t38', {})
                    if not frame_no or not t38_layer:
                        continue
                    flat = {}
                    self._flatten_dict(t38_layer, flat)
                    msg_type = field_type = field_data = ''
                    for k, v in flat.items():
                        kl = k.lower()
                        if not msg_type and ('type_of_msg' in kl or 'type-of-msg' in kl):
                            msg_type = str(v)
                        if not field_type and ('field_type' in kl or 'field-type' in kl):
                            field_type = str(v)
                        if not field_data and ('field_data' in kl or 'field-data' in kl) and v:
                            field_data = str(v)
                    result[frame_no] = {
                        'msg_type': msg_type,
                        'field_type': field_type,
                        'field_data': field_data,
                    }
                if result:
                    has_data = any(v['field_data'] for v in result.values())
                    return result, 'json' + ('+data' if has_data else '+no-data')
            except Exception:
                pass

        return {}, 'none'

    def _flatten_dict(self, d, out, prefix=''):
        """Flatten a nested dict/list into a flat dict (first element of lists)."""
        if isinstance(d, dict):
            for k, v in d.items():
                self._flatten_dict(v, out, k)
        elif isinstance(d, list):
            if d:
                self._flatten_dict(d[0], out, prefix)
        elif prefix:
            out[prefix] = d

    def _strip_hdlc(self, hex_list):
        """Strip HDLC framing (0x7e flags + 2-byte FCS) from ECM data chunks."""
        result = []
        for h in hex_list:
            try:
                raw = bytes.fromhex(h.replace(':', '').replace(' ', ''))
                while raw and raw[0] == 0x7e:
                    raw = raw[1:]
                while raw and raw[-1] == 0x7e:
                    raw = raw[:-1]
                if len(raw) > 3:
                    raw = raw[:-2]  # remove FCS
                if raw:
                    result.append(raw.hex())
            except Exception:
                pass
        return result

    def _count_t4_lines(self, raw):
        """Estimate line count from T.4 data by counting EOL codes (≥11 zeros + 1)."""
        if len(raw) > 131072:
            raw = raw[:131072]
        bits  = ''.join(format(b, '08b') for b in raw)
        count = bits.count('0' * 11 + '1')
        return max(count - 5, 100)  # subtract RTC (6 trailing EOLs)

    def _create_t4_tiff(self, data_hex_list):
        """Build a TIFF (T.4 Group 3 1D) from hex data chunks.
        Returns base64-encoded TIFF bytes, or None if there is no data."""
        import struct
        raw = b''
        for h in data_hex_list:
            try:
                raw += bytes.fromhex(h.replace(':', '').replace(' ', ''))
            except Exception:
                pass
        if not raw:
            return None

        width  = 1728                       # standard T.4 fax width in pixels
        height = self._count_t4_lines(raw)

        # TIFF layout (little-endian):
        #   offset 0   : 8-byte header
        #   offset 8   : IFD (2 + 13×12 + 4 = 162 bytes)
        #   offset 170 : XResolution rational (8 bytes)
        #   offset 178 : YResolution rational (8 bytes)
        #   offset 186 : strip data
        n_entries      = 13
        ifd_offset     = 8
        ifd_size       = 2 + n_entries * 12 + 4
        rational_offset = ifd_offset + ifd_size   # 170
        strip_offset    = rational_offset + 16    # 186

        entries = sorted([
            (256, 3, 1, width),
            (257, 3, 1, height),
            (258, 3, 1, 1),                   # BitsPerSample = 1
            (259, 3, 1, 3),                   # Compression = T.4 Group 3 Fax
            (262, 3, 1, 0),                   # PhotometricInterpretation (white=0)
            (266, 3, 1, 1),                   # FillOrder = MSB first
            (273, 4, 1, strip_offset),        # StripOffsets
            (278, 4, 1, height),              # RowsPerStrip
            (279, 4, 1, len(raw)),            # StripByteCounts
            (282, 5, 1, rational_offset),     # XResolution
            (283, 5, 1, rational_offset + 8), # YResolution
            (292, 4, 1, 0),                   # T4Options (1D, no fill bits)
            (296, 3, 1, 2),                   # ResolutionUnit = inch
        ])

        header    = b'II' + struct.pack('<H', 42) + struct.pack('<I', ifd_offset)
        ifd       = struct.pack('<H', n_entries)
        for tag, typ, count, val in entries:
            ifd  += struct.pack('<HHII', tag, typ, count, val)
        ifd      += struct.pack('<I', 0)  # no next IFD
        rationals = struct.pack('<II', 204, 1) + struct.pack('<II', 98, 1)

        return base64.b64encode(header + ifd + rationals + raw).decode()

    def parse_t38(self):
        """Extract T.38 fax sessions and attempt image reconstruction.

        Uses a two-phase approach:
          1. Locate packets with only guaranteed-valid tshark fields.
          2. Separately extract T.38 protocol fields and merge by frame number.
        This prevents invalid field names from silently suppressing all output."""

        basic_lines, filter_used, phase1_err = self._t38_basic_filter()

        t38_fields, t38_field_name = {}, 'none'
        if filter_used != 'none':
            t38_fields, t38_field_name = self._t38_field_data(filter_used)

        sessions    = {}
        raw_packets = []

        for line in basic_lines:
            parts = line.split('|')
            if len(parts) < 4:
                continue
            frame_no = parts[0].strip()
            time_rel = parts[1].strip()
            src_ip   = parts[2].strip()
            dst_ip   = parts[3].strip()
            src_port = parts[4].strip() if len(parts) > 4 else ''
            dst_port = parts[5].strip() if len(parts) > 5 else ''

            if not src_ip or not dst_ip:
                continue

            src = f"{src_ip}:{src_port}" if src_port else src_ip
            dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            t38  = t38_fields.get(frame_no, {})
            msg_type   = t38.get('msg_type', '')
            field_type = t38.get('field_type', '')
            field_data = t38.get('field_data', '')

            ep_pair     = sorted([src, dst])
            session_key = f"{ep_pair[0]}|{ep_pair[1]}"
            if session_key not in sessions:
                sessions[session_key] = {
                    'src': ep_pair[0], 'dst': ep_pair[1],
                    'packet_count': 0,
                    'data_chunks': [],
                    'packets': [],
                    '_non_ecm': [],
                    '_ecm': [],
                }

            sessions[session_key]['packet_count'] += 1
            sessions[session_key]['packets'].append({
                'frame': frame_no, 'time': time_rel,
                'src': src, 'dst': dst,
                'msg_type': msg_type, 'field_type': field_type
            })

            if field_data:
                sessions[session_key]['data_chunks'].append({
                    'frame': frame_no, 'type': field_type, 'data': field_data
                })
                if field_type in self._NON_ECM_TYPES:
                    sessions[session_key]['_non_ecm'].append(field_data)
                elif field_type in self._ECM_DATA_TYPES:
                    sessions[session_key]['_ecm'].append(field_data)

            raw_packets.append({
                'frame': frame_no, 'time': time_rel,
                'src': src, 'dst': dst,
                'msg_type': msg_type, 'field_type': field_type
            })

        phs_out, _ = self.run_tshark(['-q', '-z', 'io,phs'])
        debug_info  = {
            'filter_used':      filter_used,
            't38_field_name':   t38_field_name,
            'packets_found':    len(raw_packets),
            'tshark_stderr':    phase1_err.strip()[:500] if phase1_err else '',
            'protocol_hierarchy': phs_out.strip()
        }

        session_list = list(sessions.values())
        for s in session_list:
            s['packets'] = s['packets'][:200]
            non_ecm = s.pop('_non_ecm')
            ecm     = s.pop('_ecm')
            if non_ecm:
                s['tiff_b64']   = self._create_t4_tiff(non_ecm)
                s['image_mode'] = 'non-ecm'
            elif ecm:
                s['tiff_b64']   = self._create_t4_tiff(self._strip_hdlc(ecm))
                s['image_mode'] = 'ecm'
            else:
                s['tiff_b64']   = None
                s['image_mode'] = 'none'

        return {
            'sessions':     session_list,
            'packet_count': len(raw_packets),
            'packets':      raw_packets[:100],
            'has_fax_data': len(raw_packets) > 0,
            'debug':        debug_info
        }

    def get_t38_debug(self):
        """Return raw tshark output from multiple query variants for T.38 debugging."""
        results = {}

        out, _ = self.run_tshark(['-q', '-z', 'io,phs'])
        results['protocol_hierarchy'] = out.strip()

        for label, display_filter, extra_fields in [
            ('t38_filter_basic',     't38',   []),
            ('udptl_filter_basic',   'udptl', []),
            ('t38_filter_fields_v1', 't38',   ['t38.Type_of_msg', 't38.data_Field_Field_Type', 't38.data_Field_Field_Data']),
            ('t38_filter_fields_v2', 't38',   ['t38.type_of_msg', 't38.data_field.field_type', 't38.data_field.field_data']),
        ]:
            args = ['-Y', display_filter, '-T', 'fields',
                    '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst',
                    '-e', 'udp.srcport', '-e', 'udp.dstport']
            for f in extra_fields:
                args += ['-e', f]
            args += ['-E', 'separator=|']
            out, err = self.run_tshark(args)
            results[label] = {'stdout': out.strip()[:2000], 'stderr': err.strip()[:500]}

        out, _ = self.run_tshark(['-Y', 't38', '-T', 'fields', '-e', 'frame.number', '-E', 'separator=|'])
        results['t38_frame_count'] = len([l for l in out.strip().split('\n') if l.strip()])

        out, _ = self.run_tshark(['-Y', 't38', '-T', 'json', '-c', '3'])
        try:
            t38_layers = [
                pkt.get('_source', {}).get('layers', {}).get('t38', {})
                for pkt in json.loads(out)
            ]
            results['t38_json_sample'] = json.dumps(t38_layers, indent=2)[:4000]
        except Exception as e:
            results['t38_json_sample'] = f'parse error: {e}\nraw: {out[:500]}'

        try:
            gf = subprocess.run(
                ['tshark', '-G', 'fields'], capture_output=True, text=True, timeout=10
            )
            results['available_t38_fields'] = [
                l for l in gf.stdout.split('\n') if '\tt38.' in l
            ][:60]
        except Exception as e:
            results['available_t38_fields'] = [f'error: {e}']

        return results

    # ── TLS ───────────────────────────────────────────────────────────────────

    def parse_tls(self):
        """Extract TLS handshakes per stream. Certificates are fetched lazily."""
        out, _ = self.run_tshark([
            '-Y', 'tls.handshake',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tls.handshake.type',
            '-e', 'tls.handshake.version',
            '-e', 'tls.handshake.ciphersuite',
            '-e', 'tls.record.version',
            '-E', 'separator=|',
            '-E', 'occurrence=f'
        ])

        handshake_type_map = {
            '1': 'ClientHello', '2': 'ServerHello',
            '4': 'NewSessionTicket', '8': 'EncryptedExtensions',
            '11': 'Certificate', '12': 'ServerKeyExchange',
            '13': 'CertificateRequest', '14': 'ServerHelloDone',
            '15': 'CertificateVerify', '16': 'ClientKeyExchange',
            '20': 'Finished',
        }
        version_map = {
            '0x0301': 'TLS 1.0', '0x0302': 'TLS 1.1',
            '0x0303': 'TLS 1.2', '0x0304': 'TLS 1.3',
        }

        streams       = {}
        all_handshakes = []

        for line in out.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 7:
                continue

            frame_no    = parts[0].strip()
            time_rel    = parts[1].strip()
            src_ip      = parts[2].strip()
            dst_ip      = parts[3].strip()
            src_port    = parts[4].strip()
            dst_port    = parts[5].strip()
            hs_type_raw = parts[6].strip()
            hs_version  = parts[7].strip() if len(parts) > 7 else ''
            cipher      = parts[8].strip() if len(parts) > 8 else ''
            rec_version = parts[9].strip() if len(parts) > 9 else ''

            src        = f"{src_ip}:{src_port}"
            dst        = f"{dst_ip}:{dst_port}"
            stream_key = '|'.join(sorted([src, dst]))

            if stream_key not in streams:
                streams[stream_key] = {
                    'stream_key':  stream_key,
                    'endpoints':   sorted([src, dst]),
                    'handshakes':  [],
                    'tls_version': None,
                    'cipher_suite': None,
                    'has_cert':    False,
                    'cert_frames': []
                }

            for hs_type in [t.strip() for t in hs_type_raw.split(',') if t.strip()]:
                type_name = handshake_type_map.get(hs_type, f'Type({hs_type})')

                if type_name == 'Certificate':
                    streams[stream_key]['has_cert'] = True
                    streams[stream_key]['cert_frames'].append(frame_no)

                ver = version_map.get(hs_version, hs_version) or version_map.get(rec_version, rec_version)
                if ver and not streams[stream_key]['tls_version']:
                    streams[stream_key]['tls_version'] = ver
                if cipher and not streams[stream_key]['cipher_suite']:
                    streams[stream_key]['cipher_suite'] = cipher

                entry = {
                    'frame': frame_no, 'time': time_rel,
                    'src': src, 'dst': dst,
                    'type': type_name, 'type_num': hs_type,
                    'version': ver, 'cipher': cipher,
                    'stream_key': stream_key
                }
                streams[stream_key]['handshakes'].append(entry)
                all_handshakes.append(entry)

        stream_list = list(streams.values())
        for s in stream_list:
            s['certs'] = []  # populated lazily via GET /api/cert/<index>

        return {'streams': stream_list, 'total_handshakes': len(all_handshakes)}

    def get_cert_detail(self, stream_index):
        """Return full certificate chain for a TLS stream (lazy fetch)."""
        tls     = self.parse_tls()
        streams = tls.get('streams', [])
        if stream_index >= len(streams):
            return {'error': 'Stream not found'}

        stream    = streams[stream_index]
        endpoints = stream.get('endpoints', [])

        display_filter = 'tls.handshake.type == 11'
        if len(endpoints) == 2:
            try:
                ip1, port1 = endpoints[0].rsplit(':', 1)
                ip2, port2 = endpoints[1].rsplit(':', 1)
                display_filter = (
                    f"(tls.handshake.type == 11) && ("
                    f"(ip.src == {ip1} && tcp.srcport == {port1} && "
                    f"ip.dst == {ip2} && tcp.dstport == {port2}) || "
                    f"(ip.src == {ip2} && tcp.srcport == {port2} && "
                    f"ip.dst == {ip1} && tcp.dstport == {port1}))"
                )
            except Exception:
                pass

        cert_hex_list = []
        for field in ('tls.handshake.certificate', 'ssl.handshake.certificate'):
            out, _ = self.run_tshark([
                '-Y', display_filter,
                '-T', 'fields',
                '-e', field,
                '-E', 'separator=|',
                '-E', 'occurrence=a'
            ])
            if out.strip():
                for line in out.strip().split('\n'):
                    for hex_cert in line.split(','):
                        h = hex_cert.strip()
                        if h and h not in cert_hex_list:
                            cert_hex_list.append(h)
                break

        cert_texts = []
        for raw in cert_hex_list:
            hex_data = raw.replace(':', '').replace(' ', '')
            try:
                cert_bytes = bytes.fromhex(hex_data)
            except Exception as e:
                cert_texts.append({'error': f'Hex decode failed: {e}', 'raw': raw[:120]})
                continue

            b64 = base64.b64encode(cert_bytes).decode()
            pem = "-----BEGIN CERTIFICATE-----\n"
            pem += '\n'.join(b64[i:i+64] for i in range(0, len(b64), 64))
            pem += "\n-----END CERTIFICATE-----"

            pem_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            pem_file.write(pem)
            pem_file.close()
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', pem_file.name, '-text', '-noout'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    cert_texts.append({'pem': pem, 'text': result.stdout})
                else:
                    cert_texts.append({
                        'pem': pem,
                        'error': f'OpenSSL error: {result.stderr.strip()[:300]}'
                    })
            except Exception as e:
                cert_texts.append({'pem': pem, 'error': str(e)})
            finally:
                os.unlink(pem_file.name)

        return {'stream': stream, 'certs': cert_texts}

    def get_protocol_hierarchy(self):
        """Return tshark protocol hierarchy statistics."""
        out, _ = self.run_tshark(['-q', '-z', 'io,phs'])
        return out.strip()
