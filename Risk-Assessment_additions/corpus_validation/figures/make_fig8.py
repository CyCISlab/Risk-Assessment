import csv, os, numpy as np, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt
rows=[r for r in csv.DictReader(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','cve_bulk_scores.csv'))) if r['ivss_score']]
base=np.array([float(r['v4_0_score'] if r['ivss_basis']=='v4.0' else r['v3_1_score']) for r in rows])
hyb=np.array([float(r['ivss_score']) for r in rows])
v3=np.array([float(r['v3_1_score']) for r in rows if r['v3_1_score']]); v4=np.array([float(r['v4_0_score']) for r in rows if r['v4_0_score']])
kev=np.array([r['in_cisa_kev']=='1' for r in rows])
print('n',len(rows),'r',np.corrcoef(base,hyb)[0,1].round(3),'kev',kev.sum())
BLUE,ORANGE,AQUA,INK,MUTED='#2a78d6','#eb6834','#1baf7a','#1f1f1e','#8a8984'
plt.rcParams.update({'font.size':6.5,'font.family':'serif','font.serif':['Times New Roman','Times','Nimbus Roman','DejaVu Serif'],
 'axes.linewidth':0.5,'axes.edgecolor':MUTED,'xtick.major.width':0.5,'ytick.major.width':0.5,'xtick.major.size':2,'ytick.major.size':2,
 'axes.spines.top':False,'axes.spines.right':False,'legend.frameon':False,'legend.fontsize':6,'axes.labelsize':6.5,'xtick.labelsize':6,'ytick.labelsize':6,
 'axes.labelpad':1.5,'xtick.major.pad':1.5,'ytick.major.pad':1.5,'text.color':INK,'axes.labelcolor':INK,'xtick.color':INK,'ytick.color':INK})
W,H=100/72*1.0,80/72*1.0
def save(fig,n): fig.savefig(f'{n}.pdf',bbox_inches='tight',pad_inches=0.01); fig.savefig(f'{n}.png',dpi=600,bbox_inches='tight',pad_inches=0.01); plt.close(fig)
bins=np.arange(0,10.51,0.5)
# (a) distributions
fig,ax=plt.subplots(figsize=(W,H))
for d,c,ls,lab in [(v3,BLUE,'-','CVSS v3.1'),(v4,ORANGE,'--','CVSS v4.0'),(hyb,AQUA,':','Hybrid')]:
    ax.hist(d,bins=bins,histtype='step',color=c,lw=1.2,ls=ls,label=lab,density=True)
ax.set_xlabel('Score'); ax.set_ylabel('Density'); ax.set_xlim(0,10.5); ax.legend(loc='upper left',handlelength=1.6,borderaxespad=0.1)
save(fig,'fig8.1')
# (b) scatter
fig,ax=plt.subplots(figsize=(W,H))
jit=np.random.default_rng(0).normal(0,0.04,len(base))
up=hyb>base; dn=hyb<base
ax.scatter(base[~up&~dn]+jit[~up&~dn],hyb[~up&~dn],s=1.2,c=MUTED,lw=0,alpha=0.5,label='Same')
ax.scatter(base[up]+jit[up],hyb[up],s=1.2,c=ORANGE,lw=0,alpha=0.5,label='Higher')
ax.scatter(base[dn]+jit[dn],hyb[dn],s=1.2,c=BLUE,lw=0,alpha=0.5,label='Lower')
ax.plot([0,10],[0,10],color=INK,lw=0.6,ls='--')
ax.set_xlabel('CVSS base score'); ax.set_ylabel('Hybrid score'); ax.set_xlim(0,10.3); ax.set_ylim(0,10.3)
ax.text(0.3,9.4,f'r = {np.corrcoef(base,hyb)[0,1]:.2f}',fontsize=6.5)
lg=ax.legend(loc='upper left',bbox_to_anchor=(-0.02,0.9),markerscale=4,handletextpad=0.1,borderaxespad=0.1,labelspacing=0.2)
for h in lg.legend_handles: h.set_alpha(1)
save(fig,'fig8.2')
# (c) categories
def band(x): return np.where(x>=9,3,np.where(x>=7,2,np.where(x>=4,1,0)))
cats=['Low','Med.','High','Crit.']; cb=np.bincount(band(base),minlength=4); hb=np.bincount(band(np.round(hyb,1)),minlength=4)
fig,ax=plt.subplots(figsize=(W,H)); x=np.arange(4); w=0.38
ax.bar(x-w/2-0.01,cb,w,color=BLUE,label='CVSS'); ax.bar(x+w/2+0.01,hb,w,color=ORANGE,hatch='////',edgecolor='white',lw=0,label='Hybrid')
ax.set_xticks(x); ax.set_xticklabels(cats); ax.set_ylabel('CVEs'); ax.legend(loc='upper left',handlelength=1.2,borderaxespad=0.1)
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v,p:f'{int(v/1000)}k' if v else '0'))
save(fig,'fig8.3')
# (d) KEV vs rest
m=[[base[kev].mean(),base[~kev].mean()],[hyb[kev].mean(),hyb[~kev].mean()]]
fig,ax=plt.subplots(figsize=(W,H)); x=np.arange(2)
ax.bar(x-w/2-0.01,m[0],w,color=BLUE,label='CVSS'); ax.bar(x+w/2+0.01,m[1],w,color=ORANGE,hatch='////',edgecolor='white',lw=0,label='Hybrid')
for i in range(2):
    ax.text(i-w/2-0.01,m[0][i]+0.15,f'{m[0][i]:.1f}',ha='center',fontsize=5.5); ax.text(i+w/2+0.01,m[1][i]+0.15,f'{m[1][i]:.1f}',ha='center',fontsize=5.5)
ax.set_xticks(x); ax.set_xticklabels([f'KEV (n={kev.sum()})','Rest']); ax.set_ylabel('Mean score'); ax.set_ylim(0,14)
ax.set_yticks([0,5,10])
ax.legend(loc='upper center',handlelength=1.2,borderaxespad=0.0,ncol=2,columnspacing=0.8)
save(fig,'fig8.4')
