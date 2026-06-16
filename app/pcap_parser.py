import os
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np

def map_port_to_service(port, proto):
    # Map destination ports to KDD service names
    port_map = {
        80: 'http',
        443: 'http',
        21: 'ftp',
        20: 'ftp_data',
        23: 'telnet',
        25: 'smtp',
        53: 'domain_u',
        110: 'pop_3',
        143: 'imap4',
        79: 'finger',
        119: 'nntp',
        123: 'ntp_u',
        70: 'gopher',
        111: 'pm_dump',
        69: 'tftp_u',
        161: 'snmp',
        162: 'snmp',
        513: 'login',
        514: 'shell',
        520: 'route',
        194: 'irc',
        6667: 'irc',
    }
    
    srv = port_map.get(port)
    if srv:
        return srv
        
    if proto == 'icmp':
        return 'eco_i' if port == 8 else 'ecr_i'
        
    return 'private' if port < 1024 else 'other'

def get_tcp_flag_kdd(flags_list):
    # KDD flags are: SF, S0, REJ, RSTR, RSTO, SH, S1, S2, S3, RSTOS0, OTH
    # Default is SF for clean, REJ for rejected, S0 for SYN sent with no response
    has_syn = 'S' in flags_list
    has_ack = 'A' in flags_list
    has_rst = 'R' in flags_list
    has_fin = 'F' in flags_list
    
    if has_syn and not has_ack:
        return 'S0'
    if has_rst:
        return 'REJ'
    if has_fin or has_ack:
        return 'SF'
    return 'SF'

def parse_pcap(file_path):
    print(f"Reading PCAP file: {file_path}")
    
    flows = []
    flow_tracker = {} # Key: (proto, src_ip, src_port, dst_ip, dst_port) -> flow dict
    
    packet_count = 0
    
    # Read packets one-by-one to be memory-efficient
    with PcapReader(file_path) as pcap_reader:
        for pkt in pcap_reader:
            if not pkt.haslayer(IP):
                continue
                
            packet_count += 1
            ip_layer = pkt[IP]
            proto = 'other'
            sport = 0
            dport = 0
            tcp_flags = ''
            payload_len = 0
            
            if pkt.haslayer(TCP):
                proto = 'tcp'
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                tcp_flags = str(pkt[TCP].flags)
                if pkt.haslayer('Raw'):
                    payload_len = len(pkt['Raw'].load)
            elif pkt.haslayer(UDP):
                proto = 'udp'
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if pkt.haslayer('Raw'):
                    payload_len = len(pkt['Raw'].load)
            elif pkt.haslayer(ICMP):
                proto = 'icmp'
                sport = 0
                dport = int(pkt[ICMP].type) # map type to dport
            else:
                continue
                
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_time = float(pkt.time)
            
            # Identify flow key (standardizing direction based on which side saw the first packet)
            key_fwd = (proto, src_ip, sport, dst_ip, dport)
            key_rev = (proto, dst_ip, dport, src_ip, sport)
            
            flow = None
            direction = 'fwd'
            
            # Check if this packet belongs to an existing flow within 10 seconds timeout
            if key_fwd in flow_tracker:
                if pkt_time - flow_tracker[key_fwd]['last_pkt_time'] < 10.0:
                    flow = flow_tracker[key_fwd]
                    direction = 'fwd'
            elif key_rev in flow_tracker:
                if pkt_time - flow_tracker[key_rev]['last_pkt_time'] < 10.0:
                    flow = flow_tracker[key_rev]
                    direction = 'rev'
                    
            if flow is None:
                # Start a new connection flow
                service_name = map_port_to_service(dport, proto)
                
                # Check for wrong fragment
                wrong_frag = 1 if ip_layer.flags == 1 or ip_layer.frag > 0 else 0
                urgent = 1 if proto == 'tcp' and 'U' in tcp_flags else 0
                
                flow = {
                    'start_time': pkt_time,
                    'last_pkt_time': pkt_time,
                    'protocol_type': proto,
                    'service': service_name,
                    'flag_list': [tcp_flags] if proto == 'tcp' else [],
                    'src_bytes': payload_len if direction == 'fwd' else 0,
                    'dst_bytes': payload_len if direction == 'rev' else 0,
                    'land': 1 if (src_ip == dst_ip and sport == dport) else 0,
                    'wrong_fragment': wrong_frag,
                    'urgent': urgent,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'src_port': sport,
                    'dest_port': dport,
                    'pkt_count': 1
                }
                flow_tracker[key_fwd] = flow
                flows.append(flow)
            else:
                # Update existing flow
                flow['last_pkt_time'] = pkt_time
                flow['pkt_count'] += 1
                
                if direction == 'fwd':
                    flow['src_bytes'] += payload_len
                else:
                    flow['dst_bytes'] += payload_len
                    
                if proto == 'tcp':
                    flow['flag_list'].append(tcp_flags)
                    if 'U' in tcp_flags:
                        flow['urgent'] += 1
                        
                # Check wrong fragment
                if ip_layer.flags == 1 or ip_layer.frag > 0:
                    flow['wrong_fragment'] += 1
                    
    print(f"Parsed {packet_count} packets into {len(flows)} connection flows.")
    
    # 2. Compute KDD Features for each connection flow
    # Sort flows by start time for window calculations
    flows.sort(key=lambda x: x['start_time'])
    
    # KDD features template list
    kdd_records = []
    
    for i, f in enumerate(flows):
        duration = f['last_pkt_time'] - f['start_time']
        
        # Determine TCP flag code
        flag_str = 'SF'
        if f['protocol_type'] == 'tcp' and f['flag_list']:
            flag_str = get_tcp_flag_kdd("".join(f['flag_list']))
            
        # Logged in heuristics (successfully closed HTTP, SMTP or FTP connection that exchanged bytes)
        logged_in = 0
        if f['protocol_type'] == 'tcp' and f['service'] in ['http', 'ftp', 'smtp'] and f['src_bytes'] > 0 and f['dst_bytes'] > 0:
            logged_in = 1
            
        # Start building KDD feature dict
        kdd = {
            # Base features
            'duration': duration,
            'protocol_type': f['protocol_type'],
            'service': f['service'],
            'flag': flag_str,
            'src_bytes': f['src_bytes'],
            'dst_bytes': f['dst_bytes'],
            'land': f['land'],
            'wrong_fragment': f['wrong_fragment'],
            'urgent': f['urgent'],
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': logged_in,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
        }
        
        # Calculate time-based features (2-second sliding window)
        count = 0
        srv_count = 0
        serror_cnt = 0
        srv_serror_cnt = 0
        rerror_cnt = 0
        srv_rerror_cnt = 0
        same_srv_cnt = 0
        diff_srv_cnt = 0
        srv_diff_host_cnt = 0
        
        t_i = f['start_time']
        dst_i = f['dest_ip']
        srv_i = f['service']
        
        # Look back at flows in last 2 seconds
        j = i - 1
        while j >= 0:
            f_j = flows[j]
            if t_i - f_j['start_time'] > 2.0:
                break # out of window
                
            # Same destination host check
            if f_j['dest_ip'] == dst_i:
                count += 1
                
                # Check for SYN errors in same host
                f_j_flag = get_tcp_flag_kdd("".join(f_j['flag_list'])) if f_j['protocol_type'] == 'tcp' else 'SF'
                if f_j_flag in ['S0', 'S1', 'S2', 'S3']:
                    serror_cnt += 1
                # Check for reset errors in same host
                if f_j_flag == 'REJ':
                    rerror_cnt += 1
                    
                # Same service rate counts
                if f_j['service'] == srv_i:
                    same_srv_cnt += 1
                else:
                    diff_srv_cnt += 1
                    
            # Same service check
            if f_j['service'] == srv_i:
                # Same service counts
                srv_count += 1
                
                # Check for SYN errors in same service
                f_j_flag = get_tcp_flag_kdd("".join(f_j['flag_list'])) if f_j['protocol_type'] == 'tcp' else 'SF'
                if f_j_flag in ['S0', 'S1', 'S2', 'S3']:
                    srv_serror_cnt += 1
                # Check for reset errors in same service
                if f_j_flag == 'REJ':
                    srv_rerror_cnt += 1
                    
                # Different destination host check
                if f_j['dest_ip'] != dst_i:
                    srv_diff_host_cnt += 1
                    
            j -= 1
            
        kdd['count'] = count
        kdd['srv_count'] = srv_count
        kdd['serror_rate'] = serror_cnt / count if count > 0 else 0.0
        kdd['srv_serror_rate'] = srv_serror_cnt / srv_count if srv_count > 0 else 0.0
        kdd['rerror_rate'] = rerror_cnt / count if count > 0 else 0.0
        kdd['srv_rerror_rate'] = srv_rerror_cnt / srv_count if srv_count > 0 else 0.0
        kdd['same_srv_rate'] = same_srv_cnt / count if count > 0 else 0.0
        kdd['diff_srv_rate'] = diff_srv_cnt / count if count > 0 else 0.0
        kdd['srv_diff_host_rate'] = srv_diff_host_cnt / srv_count if srv_count > 0 else 0.0
        
        # Calculate host-based features (last 100 connections to same destination host)
        dst_host_count = 0
        dst_host_srv_count = 0
        dh_same_srv_cnt = 0
        dh_diff_srv_cnt = 0
        dh_same_src_port_cnt = 0
        dh_srv_diff_host_cnt = 0
        dh_serror_cnt = 0
        dh_srv_serror_cnt = 0
        dh_rerror_cnt = 0
        dh_srv_rerror_cnt = 0
        
        sport_i = f['src_port']
        src_i = f['source_ip']
        
        # Look back at last 100 flows
        history_limit = min(100, i)
        for idx in range(i - history_limit, i):
            f_hist = flows[idx]
            hist_flag = get_tcp_flag_kdd("".join(f_hist['flag_list'])) if f_hist['protocol_type'] == 'tcp' else 'SF'
            
            # Same destination host check
            if f_hist['dest_ip'] == dst_i:
                dst_host_count += 1
                
                # Check same service
                if f_hist['service'] == srv_i:
                    dh_same_srv_cnt += 1
                else:
                    dh_diff_srv_cnt += 1
                    
                # Check same source port
                if f_hist['src_port'] == sport_i:
                    dh_same_src_port_cnt += 1
                    
                # Check SYN errors
                if hist_flag in ['S0', 'S1', 'S2', 'S3']:
                    dh_serror_cnt += 1
                # Check REJ errors
                if hist_flag == 'REJ':
                    dh_rerror_cnt += 1
                    
            # Same service check
            if f_hist['service'] == srv_i:
                # Check same service
                dst_host_srv_count += 1
                
                # Check SYN errors
                if hist_flag in ['S0', 'S1', 'S2', 'S3']:
                    dh_srv_serror_cnt += 1
                # Check REJ errors
                if hist_flag == 'REJ':
                    dh_srv_rerror_cnt += 1
                    
                # Different destination host check
                if f_hist['dest_ip'] != dst_i:
                    dh_srv_diff_host_cnt += 1
                    
        kdd['dst_host_count'] = dst_host_count
        kdd['dst_host_srv_count'] = dst_host_srv_count
        kdd['dst_host_same_srv_rate'] = dh_same_srv_cnt / dst_host_count if dst_host_count > 0 else 0.0
        kdd['dst_host_diff_srv_rate'] = dh_diff_srv_cnt / dst_host_count if dst_host_count > 0 else 0.0
        kdd['dst_host_same_src_port_rate'] = dh_same_src_port_cnt / dst_host_count if dst_host_count > 0 else 0.0
        kdd['dst_host_srv_diff_host_rate'] = dh_srv_diff_host_cnt / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
        kdd['dst_host_serror_rate'] = dh_serror_cnt / dst_host_count if dst_host_count > 0 else 0.0
        kdd['dst_host_srv_serror_rate'] = dh_srv_serror_cnt / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
        kdd['dst_host_rerror_rate'] = dh_rerror_cnt / dst_host_count if dst_host_count > 0 else 0.0
        kdd['dst_host_srv_rerror_rate'] = dh_srv_rerror_cnt / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
        
        # Store metadata for flow logging
        timestamp_str = pd.Timestamp(f['start_time'], unit='s').strftime("%Y-%m-%d %H:%M:%S")
        
        kdd_records.append({
            'metadata': {
                'timestamp': timestamp_str,
                'source_ip': f['source_ip'],
                'dest_ip': f['dest_ip'],
                'src_port': f['src_port'],
                'dest_port': f['dest_port'],
                'pkt_count': f['pkt_count']
            },
            'features': kdd
        })
        
    return kdd_records
