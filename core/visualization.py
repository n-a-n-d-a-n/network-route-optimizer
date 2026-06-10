"""
core/visualization.py — Enhanced NetworkX + matplotlib graph visualization (FIXED VERSION)
"""

import os

# Safe import handling
try:
    import networkx as nx
    import matplotlib
    matplotlib.use('Agg')  # Must be before pyplot
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


class NetworkVisualizer:
    def __init__(self, topology):
        self.topology = topology

    def generate_graph_image(self, highlight_path=None, filename="static/network.png"):
        # Ensure directory exists
        os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else ".", exist_ok=True)

        # If matplotlib/networkx missing → create placeholder
        if not HAS_MPL:
            self._write_placeholder(filename, "matplotlib/networkx not installed")
            return

        G = self.topology.get_nx_graph()

        if G.number_of_nodes() == 0:
            self._write_placeholder(filename, "Empty graph")
            return

        fig, ax = plt.subplots(figsize=(12, 8))
        fig.patch.set_facecolor('#1a1a2e')
        ax.set_facecolor('#16213e')

        # Layout selection
        try:
            if G.number_of_nodes() <= 20:
                pos = nx.planar_layout(G)
            else:
                pos = nx.spring_layout(G, seed=42, k=1.5)
        except Exception:
            pos = nx.spring_layout(G, seed=42, k=2.5)

        # Highlight path edges
        path_edges = set()
        if highlight_path and len(highlight_path) > 1:
            for i in range(len(highlight_path) - 1):
                u, v = highlight_path[i], highlight_path[i + 1]
                path_edges.add((u, v))
                if not G.is_directed():
                    path_edges.add((v, u))

        normal_edges = [(u, v) for u, v in G.edges() if (u, v) not in path_edges]
        opt_edges = [(u, v) for u, v in G.edges() if (u, v) in path_edges]

        # Draw edges
        nx.draw_networkx_edges(
            G, pos, edgelist=normal_edges, ax=ax,
            edge_color='#4a9eff', width=1.5, alpha=0.6,
            arrows=G.is_directed()
        )

        if opt_edges:
            nx.draw_networkx_edges(
                G, pos, edgelist=opt_edges, ax=ax,
                edge_color='#00ff88', width=3.5, alpha=0.95,
                arrows=True, arrowsize=20,
                connectionstyle='arc3,rad=0.1'
            )

        # Node colors
        highlight_set = set(highlight_path) if highlight_path else set()
        node_colors = []

        for n in G.nodes():
            if highlight_path and n == highlight_path[0]:
                node_colors.append('#ff6b6b')  # Source
            elif highlight_path and n == highlight_path[-1]:
                node_colors.append('#ffd93d')  # Destination
            elif n in highlight_set:
                node_colors.append('#00ff88')  # Path
            else:
                node_colors.append('#4a9eff')  # Normal

        # Dynamic node size
        node_size = max(300, 2000 // max(1, G.number_of_nodes()))

        nx.draw_networkx_nodes(
            G, pos, ax=ax,
            node_color=node_colors,
            node_size=node_size,
            alpha=0.92
        )

        nx.draw_networkx_labels(
            G, pos, ax=ax,
            font_color='white',
            font_weight='bold',
            font_size=9
        )

        # Edge weights
        edge_labels = {}
        for u, v, d in G.edges(data=True):
            try:
                w = float(d.get('weight', 0))
            except:
                w = 0.0
            edge_labels[(u, v)] = f"{w:.1f}"

        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            ax=ax,
            font_size=7,
            font_color='#aad4f5',
            bbox=dict(
                boxstyle='round,pad=0.2',
                facecolor='#1a1a2e',
                alpha=0.6
            )
        )

        # Legend
        legend_items = [
            mpatches.Patch(color='#4a9eff', label='Normal link'),
            mpatches.Patch(color='#00ff88', label='Optimal path'),
            mpatches.Patch(color='#ff6b6b', label='Source router'),
            mpatches.Patch(color='#ffd93d', label='Destination router'),
        ]

        ax.legend(
            handles=legend_items,
            loc='upper left',
            facecolor='#1a1a2e',
            labelcolor='white',
            fontsize=8
        )

        ax.set_title(
            f"Network Topology — {G.number_of_nodes()} Routers · {G.number_of_edges()} Links",
            color='white',
            fontsize=13,
            fontweight='bold',
            pad=14
        )

        ax.axis('off')
        plt.tight_layout()

        # Save image
        plt.savefig(
            filename,
            dpi=130,
            bbox_inches='tight',
            facecolor=fig.get_facecolor()
        )
        plt.close(fig)

    def _write_placeholder(self, filename, message="Visualization not available"):
        """Creates a valid fallback image instead of empty file"""
        try:
            import matplotlib.pyplot as plt

            fig, ax = plt.subplots(figsize=(6, 4))
            ax.text(0.5, 0.5, message,
                    ha='center', va='center',
                    fontsize=12, color='red')
            ax.axis('off')

            plt.savefig(filename, bbox_inches='tight')
            plt.close(fig)

        except Exception:
            # Absolute fallback → write minimal PNG header
            with open(filename, 'wb') as f:
                f.write(
                    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
                    b'\x00\x00\x00\x01\x00\x00\x00\x01'
                    b'\x08\x02\x00\x00\x00\x90wS\xde'
                    b'\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01'
                    b'\xe2!\xbc\x33\x00\x00\x00\x00IEND\xaeB`\x82'
                )
