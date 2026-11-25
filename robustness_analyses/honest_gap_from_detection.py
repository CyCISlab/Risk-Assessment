import json, os

# Map each device's REAL detection outcome -> LA, using calculate_asset_access_modifier's tiers:
#   active-detected -> 1.0 ; passive/specialised-detected -> 0.5 ; not detected -> 0.25
# From the results files we know, per device: hidden? and was it pcap-detected?
#   non-hidden            -> actively detected        -> LA 1.0
#   hidden + pcap-detected-> specialised/passive only -> LA = HID_DET (0.5 in code)
#   hidden + not detected -> not detected             -> LA = HID_UND (0.25 in code)

def mean_LA(fn, HID_DET, HID_UND):
    d=json.load(open(fn)); las=[]
    for ip,v in d['devices'].items():
        di=v.get('device_info',{})
        if not di: continue                      # skip unnamed pcap-only phantom IPs
        hidden=bool(di.get('hidden',False))
        pcap = 'pcap_hidden_device' in v.get('detection_info',{})
        if not hidden:      la=1.0
        elif pcap:          la=HID_DET
        else:               la=HID_UND
        las.append((di.get('type',''), di.get('network',''), hidden, pcap, la))
    m=sum(x[4] for x in las)/len(las)
    return m, las

STD=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','simulation_results','standard_network_comprehensive_results.json')
EDG=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','simulation_results','edge_hidden_network_comprehensive_results.json')

print("Per-device LA (code tiers: hidden+detected=0.5, hidden+undetected=0.25):\n")
for fn,label in [(STD,'STANDARD'),(EDG,'EDGE/HIDDEN')]:
    m,las=mean_LA(fn,0.5,0.25)
    print(f"--- {label}: mean LA = {m:.3f}  (n={len(las)}) ---")
    for t,net,h,p,la in las:
        tag = '' if not h else ('hidden,detected' if p else 'hidden,UNDETECTED')
        print(f"    LA={la:<4} {t:24} {net:18} {tag}")
    print()

ms,_=mean_LA(STD,0.5,0.25); me,_=mean_LA(EDG,0.5,0.25)
dLA=ms-me
print(f"mean LA  standard={ms:.3f}  edge={me:.3f}   dLA = {dLA:+.3f}")
print(f"honest standalone gap  ~= 0.04 (CP) + dLA*6.11  = {0.04 + dLA*6.11:+.3f}\n")

print("Sensitivity — vary how much 'hidden' suppresses LA (the only assumption):")
print(f"{'hidden_detected':>16}{'hidden_undet':>14}{'dLA':>8}{'honest gap':>12}")
for hd,hu in [(0.5,0.25),(0.25,0.25),(0.25,0.1),(0.5,0.5),(0.75,0.5),(1.0,1.0)]:
    ms,_=mean_LA(STD,hd,hu); me,_=mean_LA(EDG,hd,hu)
    d=ms-me
    print(f"{hd:>16}{hu:>14}{d:>8.3f}{0.04+d*6.11:>12.3f}")
print("\n(hardcoded lookup used LA_std=0.50, LA_edge=0.25 -> dLA=+0.25 -> gap=+1.57; that is the 2.13/1.53 the paper reports)")
