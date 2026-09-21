import matplotlib.pyplot as plt
import networkx as nx

# Dark theme settings for transparent embedding
plt.style.use('dark_background')
bg_color = '#12141a'
accent_blue = '#00beff'
accent_green = '#00ff8c'
accent_red = '#ff5050'

# 1. Problem Visual (One-Way Telemetry)
fig, ax = plt.subplots(figsize=(8, 2))
fig.patch.set_facecolor(bg_color)
ax.set_facecolor(bg_color)

ax.text(0.1, 0.5, "EXTERNAL\nNETWORK", ha='center', va='center', color='white', 
        bbox=dict(facecolor='#1f2430', edgecolor=accent_red, boxstyle='round,pad=1'), fontsize=14, fontweight='bold')
ax.text(0.5, 0.5, "ONE-WAY\nTELEMETRY", ha='center', va='center', color=accent_blue, fontsize=14, fontweight='bold')
ax.text(0.9, 0.5, "PASSIVE\nSENSOR", ha='center', va='center', color='white', 
        bbox=dict(facecolor='#1f2430', edgecolor=accent_green, boxstyle='round,pad=1'), fontsize=14, fontweight='bold')

# Arrow pointing right
ax.annotate('', xy=(0.8, 0.5), xytext=(0.2, 0.5),
            arrowprops=dict(facecolor=accent_blue, edgecolor=accent_blue, width=4, headwidth=15))
# Red cross indicating no return path
ax.text(0.5, 0.25, "NO RETURN PATH  |  NO PROBES", ha='center', va='center', color=accent_red, fontsize=12, fontweight='bold')

ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')
plt.tight_layout()
plt.savefig('visual_problem.png', dpi=200, facecolor=fig.get_facecolor(), transparent=True)
plt.close()

# 2. Pipeline / Architecture Diagram
fig, ax = plt.subplots(figsize=(10, 3.5))
fig.patch.set_facecolor(bg_color)
ax.set_facecolor(bg_color)

nodes = [
    "Traffic\n(PCAP)", "Packet\nParsing", "Flow\nAggregation", 
    "52 Canonical\nFeatures", "ML Inference\n(XGBoost + IF)", 
    "Evidence\n+ Risk", "SOC Command\nCenter"
]
G = nx.DiGraph()
for i in range(len(nodes)-1):
    G.add_edge(nodes[i], nodes[i+1])
    
pos = {n: (i, 0) for i, n in enumerate(nodes)}
nx.draw_networkx_edges(G, pos, edge_color=accent_blue, arrows=True, arrowsize=20, width=2.5)

for k, v in pos.items():
    ax.text(v[0], v[1], k, ha='center', va='center', color='white',
            bbox=dict(facecolor='#1f2430', edgecolor=accent_blue, boxstyle='round,pad=0.6', linewidth=1.5),
            fontsize=10, fontweight='bold')
    
ax.set_xlim(-0.5, len(nodes)-0.5)
ax.set_ylim(-0.5, 0.5)
ax.axis('off')
plt.tight_layout()
plt.savefig('visual_pipeline.png', dpi=200, facecolor=fig.get_facecolor(), transparent=True)
plt.close()

# 3. Scientific Results Chart
fig, ax = plt.subplots(figsize=(7, 4.5))
fig.patch.set_facecolor(bg_color)
ax.set_facecolor(bg_color)

metrics = ['XGBoost\nMacro-F1', 'LogReg\nMacro-F1', 'Unseen DDoS\nROC-AUC', 'Unseen DDoS\nPR-AUC', 'DoS-Wed\nLOSO F1']
values = [0.2675, 0.3389, 0.887, 0.776, 0.806]
colors = [accent_blue, accent_blue, accent_green, accent_green, accent_green]

bars = ax.bar(metrics, values, color=colors, edgecolor='none')
ax.set_ylim(0, 1.1)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color('#555566')
ax.spines['bottom'].set_color('#555566')
ax.tick_params(colors='white')

for bar in bars:
    yval = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, yval + 0.02, f'{yval:.4f}', ha='center', va='bottom', color='white', fontweight='bold', fontsize=11)

plt.title("Verified Scientific Results (Phase 7/8)", color='white', pad=20, fontweight='bold')
plt.tight_layout()
plt.savefig('visual_results.png', dpi=200, facecolor=fig.get_facecolor(), transparent=True)
plt.close()

# 4. Novel Threat Findings Diagram
fig, ax = plt.subplots(figsize=(8, 3))
fig.patch.set_facecolor(bg_color)
ax.set_facecolor(bg_color)

ax.text(0.2, 0.7, "SUPERVISED MODELS\n(XGBoost / RF / LR)", ha='center', va='center', color='white', 
        bbox=dict(facecolor='#1f2430', edgecolor=accent_blue, boxstyle='round,pad=0.8'), fontsize=12, fontweight='bold')
ax.text(0.2, 0.3, "Fails completely on unseen\nattack classes (e.g. C2 = 0% Recall)", ha='center', va='center', color=accent_red, fontsize=10, fontweight='bold')
ax.annotate('', xy=(0.2, 0.4), xytext=(0.2, 0.6), arrowprops=dict(facecolor=accent_red, edgecolor=accent_red, width=2, headwidth=10))

ax.text(0.8, 0.7, "ANOMALY DETECTION\n(Isolation Forest)", ha='center', va='center', color='white', 
        bbox=dict(facecolor='#1f2430', edgecolor=accent_green, boxstyle='round,pad=0.8'), fontsize=12, fontweight='bold')
ax.text(0.8, 0.3, "Provides novelty-ranking signal,\nbut operational FPR remains high.", ha='center', va='center', color=accent_green, fontsize=10, fontweight='bold')
ax.annotate('', xy=(0.8, 0.4), xytext=(0.8, 0.6), arrowprops=dict(facecolor=accent_green, edgecolor=accent_green, width=2, headwidth=10))

ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')
plt.tight_layout()
plt.savefig('visual_novelty.png', dpi=200, facecolor=fig.get_facecolor(), transparent=True)
plt.close()

print("Assets generated.")
