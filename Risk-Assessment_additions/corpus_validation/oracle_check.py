"""Oracle vs passive discovery (Table 'oracle'): compares each simulation's ground-truth hidden-device
inventory with what passive discovery reported. Run from 'Code and Data/Support' (or pass the folder)."""
import json, os, sys
d0 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'simulation_results')
for net in ['standard_network', 'edge_hidden_network']:
    devs = json.load(open(os.path.join(d0, f'{net}_comprehensive_results.json')))['devices']
    hidden = {ip: v for ip, v in devs.items() if v.get('device_info', {}).get('hidden')}
    found = {ip: v['detection_info']['pcap_hidden_device']['confidence'] for ip, v in hidden.items() if 'pcap_hidden_device' in v.get('detection_info', {})}
    fp = [v['detection_info']['pcap_hidden_device']['confidence'] for ip, v in devs.items()
          if not v.get('device_info', {}).get('hidden') and 'pcap_hidden_device' in v.get('detection_info', {})]
    missed = [v['device_info']['type'] for ip, v in hidden.items() if ip not in found]
    tp = len(found)
    print(f"{net}: hidden={len(hidden)} found={tp} conf={[round(c, 2) for c in found.values()]} missed={missed} "
          f"false_pos={len(fp)} conf={[round(c, 2) for c in fp]} recall={tp/len(hidden):.2f} precision={tp/(tp+len(fp)):.2f}")
