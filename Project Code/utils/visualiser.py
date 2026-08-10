"""
Visualisation Tool

Provides data visualisation for comparing CVSS, IVSS, and CVSS+IVSS hybrid scoring results,
focusing on comprehensive dashboards and network comparisons.
"""

import matplotlib.pyplot as plt
import numpy as np
import os
import re
import json
import logging

class VulnerabilityVisualisation:
    """Creates visualizations of vulnerability scoring results."""
    
    def __init__(self, comparator=None):
        """Initialize visualization with optional comparator."""
        self.comparator = comparator
        
        # Define a consistent color scheme
        self.colours = {
            'cvss': '#1A5F7A',       # Blue for CVSS
            'ivss': '#A12D5F',        # Red/Pink for IVSS
            'hybrid': '#2E8B57',      # Green for Hybrid
            'background': '#F4F6F7',  # Light background
            'text': '#2C3E50'         # Dark text
        }
        
        # Set visualization style
        plt.style.use('seaborn-v0_8-whitegrid')
        self._set_custom_style()
    
    def _set_custom_style(self):
        """Configure consistent visualization style."""
        plt.rcParams['figure.figsize'] = (14, 10)
        plt.rcParams['font.family'] = 'DejaVu Sans'
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelcolor'] = self.colours['text']
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
        plt.rcParams['figure.titlesize'] = 16
        plt.rcParams['figure.facecolor'] = self.colours['background']
        plt.rcParams['axes.facecolor'] = 'white'
    
    # Helper methods for severity categories
    def _get_severity_category(self, score):
        """Get severity category based on score."""
        if score < 0.1:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"

    def _category_value(self, category):
        """Convert severity category to numerical value for comparison."""
        values = {
            "None": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }
        return values.get(category, 0)
    
    def create_dashboard(self, save_path=None):
        """
        Create a comprehensive dashboard with multiple visualizations.
        
        Args:
            save_path: Optional path to save the visualization
            
        Returns:
            Figure object
        """
        if not self.comparator or not self.comparator.results:
            logger = logging.getLogger("Visualization")
            logger.error("No results available for visualization")
            return None
        
        # Create a figure with a grid for different visualization panels
        fig = plt.figure(figsize=(24, 20))
        gs = plt.GridSpec(4, 2, height_ratios=[1.2, 1, 1, 1], hspace=0.5, wspace=0.4)
        
        # 1. Score comparison bar chart (top row)
        ax1 = fig.add_subplot(gs[0, :])
        self._create_score_comparison_panel(ax1)
        
        # 2. Score distribution histogram (second row, left)
        ax2 = fig.add_subplot(gs[1, 0])
        self._create_score_distribution_panel(ax2)
        
        # 3. Severity shifts pie chart (second row, right)
        ax3 = fig.add_subplot(gs[1, 1])
        self._create_severity_shifts_panel(ax3)
        
        # 4. CVSS vs IVSS correlation (third row, left)
        ax4 = fig.add_subplot(gs[2, 0])
        self._create_correlation_panel(ax4, 'cvss', 'standalone_ivss')
        
        # 5. CVSS vs Hybrid correlation (third row, right)
        ax5 = fig.add_subplot(gs[2, 1])
        self._create_correlation_panel(ax5, 'cvss', 'hybrid_ivss')
        
        # 6. IVSS vs Hybrid correlation (bottom row, left)
        ax6 = fig.add_subplot(gs[3, 0])
        self._create_correlation_panel(ax6, 'standalone_ivss', 'hybrid_ivss')
        
        # 7. Statistics panel (bottom row, right)
        ax7 = fig.add_subplot(gs[3, 1])
        self._create_statistics_panel(ax7)
        
        # Add overall title
        fig.suptitle('Vulnerability Scoring System Comparison Dashboard', 
                    fontsize=24, y=0.98)
        
        # Adjust layout
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        
        # Save if path provided
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            
        return fig
    
    def _create_score_comparison_panel(self, ax):
        """Create bar chart comparing vulnerability scores."""
        vulnerability_ids = [r['id'] for r in self.comparator.results]
        x = np.arange(len(vulnerability_ids))
        
        # Extract scores
        try:
            cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
            ivss_scores = [r['standalone_ivss']['score'] for r in self.comparator.results]
            hybrid_scores = [r['hybrid_ivss']['score'] for r in self.comparator.results]
            
            bar_width = 0.25
            
            # Create bars
            ax.bar(x - bar_width, cvss_scores, bar_width, label='CVSS (Pure IT)', 
                  color=self.colours['cvss'], alpha=0.8)
            ax.bar(x, ivss_scores, bar_width, label='IVSS (Pure ICS)', 
                  color=self.colours['ivss'], alpha=0.8)
            ax.bar(x + bar_width, hybrid_scores, bar_width, label='Hybrid (CVSS+IVSS)', 
                  color=self.colours['hybrid'], alpha=0.8)
        except (KeyError, TypeError):
            # Fallback for different data structures
            ax.text(0.5, 0.5, "Unable to display scores - incompatible data format", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Vulnerability Scoring Comparison', fontweight='bold')
            return
        
        # Configure axes
        ax.set_xlabel('Vulnerability ID', fontweight='bold')
        ax.set_ylabel('Score', fontweight='bold')
        ax.set_title('Vulnerability Scoring Comparison', fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(vulnerability_ids, rotation=45, ha='right')
        ax.legend()
        
        # Add severity threshold lines
        ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5, label='Critical')
        ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5, label='High')
        ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5, label='Medium')
        
        # Add grid for readability
        ax.grid(axis='y', alpha=0.3)
    
    def _create_score_distribution_panel(self, ax):
        """Create histogram of score distributions."""
        try:
            cvss_scores = [r['cvss']['score'] for r in self.comparator.results]
            ivss_scores = [r['standalone_ivss']['score'] for r in self.comparator.results]
            hybrid_scores = [r['hybrid_ivss']['score'] for r in self.comparator.results]
            
            # Cap at 10.0 for display
            ivss_scores = [min(s, 10.0) for s in ivss_scores]
            hybrid_scores = [min(h, 10.0) for h in hybrid_scores]
            
            bins = np.linspace(0, 10, 11)
            ax.hist(cvss_scores, bins=bins, alpha=0.5, label='CVSS', color=self.colours['cvss'])
            ax.hist(ivss_scores, bins=bins, alpha=0.5, label='IVSS', color=self.colours['ivss'])
            ax.hist(hybrid_scores, bins=bins, alpha=0.5, label='Hybrid', color=self.colours['hybrid'])
        except (KeyError, TypeError):
            # Fallback for errors
            ax.text(0.5, 0.5, "Unable to display distribution - incompatible data format", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Score Distribution', fontweight='bold')
            return
            
        # Add severity threshold lines
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.7)
        
        ax.set_xlabel('Score', fontweight='bold')
        ax.set_ylabel('Frequency', fontweight='bold')
        ax.set_title('Distribution of Scores', fontweight='bold')
        ax.legend()
    
    def _create_severity_shifts_panel(self, ax):
        """Create visualization of severity category shifts."""
        # Get analysis results
        analysis = self.comparator.analyse_results()
        
        if 'error' in analysis:
            ax.text(0.5, 0.5, f"Analysis error: {analysis['error']}", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Severity Category Shifts', fontweight='bold')
            ax.axis('off')
            return
            
        # Get severity shifts
        if 'severity_shifts' in analysis and 'cvss_to_standalone' in analysis['severity_shifts']:
            shifts = analysis['severity_shifts']['cvss_to_standalone']
        else:
            ax.text(0.5, 0.5, "No severity shift data available", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Severity Category Shifts', fontweight='bold')
            ax.axis('off')
            return
            
        # Create pie chart
        if shifts:
            labels = list(shifts.keys())
            sizes = list(shifts.values())
            
            # Create colormap
            colours = plt.cm.Paired(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=labels, 
                autopct='%1.1f%%',
                startangle=90,
                colors=colours,
                wedgeprops={'edgecolor': 'w', 'linewidth': 1}
            )
            
            # Equal aspect ratio for circle
            ax.axis('equal')
            
            ax.set_title('CVSS vs IVSS Severity Shifts', fontweight='bold')
        else:
            ax.text(0.5, 0.5, "No severity shifts detected", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Severity Category Shifts', fontweight='bold')
            ax.axis('off')
    

    def _create_correlation_panel(self, ax, x_score_type, y_score_type):
        """Create scatter correlation plot between scoring methods."""
        # Map score types to readable labels
        label_map = {
            'cvss': 'CVSS Score',
            'standalone_ivss': 'IVSS Score',
            'hybrid_ivss': 'Hybrid Score'
        }
        
        # Extract scores
        x_scores = []
        y_scores = []
        
        try:
            for result in self.comparator.results:
                # Get x score
                if x_score_type in result and 'score' in result[x_score_type]:
                    x_score = result[x_score_type]['score']
                elif x_score_type == 'standalone_ivss' and 'ivss' in result and 'score' in result['ivss']:
                    # Legacy format support
                    x_score = result['ivss']['score']
                elif x_score_type == 'hybrid_ivss' and 'hybrid' in result and 'score' in result['hybrid']:
                    # Legacy format support
                    x_score = result['hybrid']['score']
                else:
                    continue
                
                # Get y score
                if y_score_type in result and 'score' in result[y_score_type]:
                    y_score = result[y_score_type]['score']
                elif y_score_type == 'standalone_ivss' and 'ivss' in result and 'score' in result['ivss']:
                    # Legacy format support
                    y_score = result['ivss']['score']
                elif y_score_type == 'hybrid_ivss' and 'hybrid' in result and 'score' in result['hybrid']:
                    # Legacy format support
                    y_score = result['hybrid']['score']
                else:
                    continue
                
                x_scores.append(x_score)
                y_scores.append(y_score)
        except (KeyError, TypeError, AttributeError):
            # Handle errors
            ax.text(0.5, 0.5, "Unable to display correlation - incompatible data format", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Score Correlation', fontweight='bold')
            ax.axis('off')
            return
            
        # Set labels
        x_label = label_map.get(x_score_type, x_score_type)
        y_label = label_map.get(y_score_type, y_score_type)
        title = f'{x_label} vs {y_label} Correlation'
        
        # Create scatter plot if we have data
        if x_scores and y_scores:
            cmap = plt.cm.get_cmap('coolwarm')
            
            scatter = ax.scatter(
                x_scores, 
                y_scores, 
                c=np.abs(np.array(x_scores) - np.array(y_scores)), 
                cmap=cmap,
                s=80,
                alpha=0.7,
                edgecolors='darkgray',
                linewidths=0.5
            )
            
            # Add color bar
            cbar = plt.colorbar(scatter, ax=ax)
            cbar.set_label('Score Difference', fontsize=10)
            
            # Add reference line
            ax.plot([0, 11], [0, 11], color='gray', linestyle='--', alpha=0.5)
            
            # Labels and title
            ax.set_xlabel(x_label, fontweight='bold')
            ax.set_ylabel(y_label, fontweight='bold')
            ax.set_title(title, fontweight='bold')
            
            # Set grid, limits, and aspect
            ax.grid(True, linestyle='--', alpha=0.6)
            ax.set_aspect('equal')
            ax.set_xlim(0, 11)
            ax.set_ylim(0, 11)
            
            # Add threshold lines
            threshold_style = {'linestyle': '--', 'color': 'gray', 'alpha': 0.5}
            ax.axhline(y=9.0, **threshold_style)
            ax.axhline(y=7.0, **threshold_style)
            ax.axhline(y=4.0, **threshold_style)
            
            ax.axvline(x=9.0, **threshold_style)
            ax.axvline(x=7.0, **threshold_style)
            ax.axvline(x=4.0, **threshold_style)
        else:
            ax.text(0.5, 0.5, "No correlation data available", 
                   ha='center', va='center', fontsize=12)
            ax.set_title(title, fontweight='bold')
            ax.axis('off')
    
    def _create_statistics_panel(self, ax):
        """Create statistics text summary panel."""
        # Get analysis results
        analysis = self.comparator.analyse_results()
        
        ax.axis('off')
        
        if 'error' in analysis:
            ax.text(0.5, 0.5, f"Analysis error: {analysis['error']}", 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Statistics', fontweight='bold')
            return
            
        # Create statistics text
        stats_text = (
            "ANALYSIS SUMMARY\n\n"
            f"Total Vulnerabilities: {analysis.get('total_vulnerabilities', 'N/A')}\n\n"
            "Average Scores:\n"
        )
        
        # Extract average scores
        avg_scores = analysis.get('average_scores', {})
        cvss_avg = avg_scores.get('cvss', 'N/A')
        ivss_avg = avg_scores.get('standalone_ivss', avg_scores.get('ivss', 'N/A'))
        hybrid_avg = avg_scores.get('hybrid_ivss', avg_scores.get('hybrid', 'N/A'))
        
        if isinstance(cvss_avg, (int, float)):
            stats_text += f" CVSS: {cvss_avg:.2f}\n"
        else:
            stats_text += f" CVSS: {cvss_avg}\n"
            
        if isinstance(ivss_avg, (int, float)):
            stats_text += f" IVSS: {ivss_avg:.2f}\n"
        else:
            stats_text += f" IVSS: {ivss_avg}\n"
            
        if isinstance(hybrid_avg, (int, float)):
            stats_text += f" Hybrid: {hybrid_avg:.2f}\n\n"
        else:
            stats_text += f" Hybrid: {hybrid_avg}\n\n"
        
        # Add average differences
        avg_diffs = analysis.get('average_differences', {})
        if avg_diffs:
            stats_text += "Average Differences:\n"
            
            cvss_ivss_diff = avg_diffs.get('cvss_to_standalone', 'N/A')
            if isinstance(cvss_ivss_diff, (int, float)):
                stats_text += f" CVSS-IVSS: {cvss_ivss_diff:.2f}\n"
            
            cvss_hybrid_diff = avg_diffs.get('cvss_to_hybrid', 'N/A')
            if isinstance(cvss_hybrid_diff, (int, float)):
                stats_text += f" CVSS-Hybrid: {cvss_hybrid_diff:.2f}\n"
            
            ivss_hybrid_diff = avg_diffs.get('standalone_to_hybrid', 'N/A')
            if isinstance(ivss_hybrid_diff, (int, float)):
                stats_text += f" IVSS-Hybrid: {ivss_hybrid_diff:.2f}\n\n"
        
        # Style properties for text box
        props = dict(boxstyle='round', facecolor='white', alpha=0.8)
        
        # Place text in center of axes
        ax.text(0.5, 0.5, stats_text, transform=ax.transAxes, fontsize=10,
               verticalalignment='center', horizontalalignment='center',
               bbox=props, family='monospace')
        
        ax.set_title('Statistics', fontweight='bold')
    
    @staticmethod
    def generate_combined_dashboard(standard_dir, hidden_dir, save_path, save_individual_plots=False):
        """
        Generate a combined dashboard visualization comparing standard and edge/hidden network results.
        
        Args:
            standard_dir: Path to the standard network results directory
            hidden_dir: Path to the edge/hidden network results directory
            save_path: Path where the combined dashboard should be saved
            save_individual_plots: Whether to save individual plots as separate files
            
        Returns:
            Path to the generated dashboard or None if an error occurred
        """
        try:
            from utils.comparator import VulnerabilityComparator
            import logging
            
            # Set up logging
            logger = logging.getLogger("CombinedDashboard")
            logger.info("Generating combined dashboard for standard and edge/hidden networks")
            
            # Create visualizer instance
            vis = VulnerabilityVisualisation()
            
            # Load comparators with data from files
            standard_comparator = _load_comparator_from_results(standard_dir, "standard_network")
            hidden_comparator = _load_comparator_from_results(hidden_dir, "edge_hidden_network")
            
            # Check if we have any results to visualize
            if not standard_comparator.results and not hidden_comparator.results:
                logger.error("No vulnerability data found in either network.")
                return None
            
            # Create figure and set up grid
            fig = plt.figure(figsize=(24, 16))
            gs = plt.GridSpec(3, 3, height_ratios=[1.2, 1, 1], width_ratios=[1, 1, 1], figure=fig)
            
            # Get the base directory for individual plot files if saving them
            if save_individual_plots and save_path:
                base_dir = os.path.dirname(save_path)
                individual_viz_dir = os.path.join(base_dir, "individual_visualizations")
                os.makedirs(individual_viz_dir, exist_ok=True)
                base_name = os.path.splitext(os.path.basename(save_path))[0]
            
            # 1. Score comparison panel
            ax_scores = fig.add_subplot(gs[0, :])
            _create_combined_score_comparison(ax_scores, standard_comparator, hidden_comparator)
            
            # Save individual plot if requested
            if save_individual_plots and save_path:
                _save_individual_panel(
                    _create_combined_score_comparison,
                    standard_comparator, 
                    hidden_comparator,
                    os.path.join(individual_viz_dir, f"{base_name}_score_comparison.png")
                )
            
            # 2. Score distribution panel
            ax_dist = fig.add_subplot(gs[1, 0])
            _create_combined_distribution(ax_dist, standard_comparator, hidden_comparator)
            
            # Save individual plot if requested
            if save_individual_plots and save_path:
                _save_individual_panel(
                    _create_combined_distribution,
                    standard_comparator,
                    hidden_comparator,
                    os.path.join(individual_viz_dir, f"{base_name}_score_distribution.png")
                )
            
            # 3. Severity shifts panel
            ax_shifts = fig.add_subplot(gs[1, 1:])
            _create_combined_severity_shifts(ax_shifts, standard_comparator, hidden_comparator)
            
            # Save individual plot if requested
            if save_individual_plots and save_path:
                _save_individual_panel(
                    _create_combined_severity_shifts,
                    standard_comparator,
                    hidden_comparator,
                    os.path.join(individual_viz_dir, f"{base_name}_severity_shifts.png")
                )
            
            # 4. CVSS vs IVSS correlation panel
            ax_corr_ivss = fig.add_subplot(gs[2, 0])
            _create_correlation_panel(ax_corr_ivss, 'ivss', standard_comparator, hidden_comparator)
            
            # Save individual plot if requested
            if save_individual_plots and save_path:
                _save_individual_panel(
                    lambda ax, sc, hc: _create_correlation_panel(ax, 'ivss', sc, hc),
                    standard_comparator,
                    hidden_comparator,
                    os.path.join(individual_viz_dir, f"{base_name}_cvss_ivss_correlation.png")
                )
            
            # 5. CVSS vs Hybrid correlation panel
            ax_corr_hybrid = fig.add_subplot(gs[2, 1])
            _create_correlation_panel(ax_corr_hybrid, 'hybrid', standard_comparator, hidden_comparator)
            
            # Save individual plot if requested
            if save_individual_plots and save_path:
                _save_individual_panel(
                    lambda ax, sc, hc: _create_correlation_panel(ax, 'hybrid', sc, hc),
                    standard_comparator,
                    hidden_comparator,
                    os.path.join(individual_viz_dir, f"{base_name}_cvss_hybrid_correlation.png")
                )
            
            # 6. Statistics panel
            ax_stats = fig.add_subplot(gs[2, 2])
            _create_combined_statistics(ax_stats, standard_comparator, hidden_comparator)
            
            # Add title and adjust layout
            fig.suptitle('Vulnerability Scoring Systems Comparison: Standard vs Edge/Hidden Networks', 
                        fontsize=22, fontweight='bold', y=0.98)
            plt.tight_layout()
            plt.subplots_adjust(top=0.94, hspace=0.4, wspace=0.3)
            
            # Save the dashboard
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                
            # Log information about individual visualizations if created
            if save_individual_plots and save_path:
                logger.info(f"Individual visualizations saved to: {individual_viz_dir}")
                
            return save_path
                
        except Exception as e:
            import traceback
            logger.error(f"Error generating combined dashboard: {e}")
            logger.error(traceback.format_exc())
            return None

# Helper functions for combined dashboard

def _load_comparator_from_results(results_dir, simulation_name):
    """Load results from directory into a comparator object."""
    from utils.comparator import VulnerabilityComparator
    import json
    import os
    
    comparator = VulnerabilityComparator()
    results_file = os.path.join(results_dir, "assessment_results.json")
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            results = json.load(f)
            
        # Process results into comparator format
        for scenario_name, scenario_data in results.items():
            if 'vulnerability_data' in scenario_data:
                vuln_data = scenario_data['vulnerability_data']
                
                result = {
                    "id": scenario_name,
                    "description": scenario_name,
                    "simulation": simulation_name,
                    "cvss": {
                        "score": vuln_data.get("cvss_score", 0),
                        "probability": vuln_data.get("cvss_probability", 0),
                        "impact": vuln_data.get("cvss_impact", 0),
                        "risk": vuln_data.get("cvss_probability", 0) * vuln_data.get("cvss_impact", 0) / 10
                    },
                    "standalone_ivss": {
                        "score": vuln_data.get("standalone_ivss_score", 0),
                        "probability": vuln_data.get("standalone_ivss_probability", 0),
                        "impact": vuln_data.get("standalone_ivss_impact", 0),
                        "risk": vuln_data.get("standalone_ivss_probability", 0) * vuln_data.get("standalone_ivss_impact", 0) / 10
                    },
                    "hybrid_ivss": {
                        "score": vuln_data.get("hybrid_ivss_score", 0),
                        "probability": vuln_data.get("hybrid_ivss_probability", 0),
                        "impact": vuln_data.get("hybrid_ivss_impact", 0),
                        "risk": vuln_data.get("hybrid_ivss_probability", 0) * vuln_data.get("hybrid_ivss_impact", 0) / 10
                    }
                }
                
                comparator.results.append(result)
    
    return comparator

def _save_individual_panel(plot_function, standard_comparator, hidden_comparator, save_path):
    """Save an individual panel as a separate figure."""
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111)
    plot_function(ax, standard_comparator, hidden_comparator)
    fig.tight_layout()
    fig.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close(fig)
    
def _create_correlation_panel(ax, correlation_type, standard_comparator, hidden_comparator):
    """
    Create a scatter correlation plot for a specific correlation type.
    
    Args:
        ax: The axis to plot on
        correlation_type: 'ivss' for CVSS vs IVSS or 'hybrid' for CVSS vs Hybrid
        standard_comparator: Comparator with standard network results
        hidden_comparator: Comparator with edge/hidden network results
    """
    # Combine results from both comparators
    all_results = standard_comparator.results + hidden_comparator.results
    
    # Collect scores for plotting
    cvss_scores = []
    comparison_scores = []
    network_types = []  # To track which network each point belongs to
    
    for result in all_results:
        if 'cvss' in result and 'score' in result['cvss']:
            cvss_score = result['cvss']['score']
            
            # Get comparison score (IVSS or Hybrid)
            comparison_score = None
            if correlation_type == 'ivss':
                if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                    comparison_score = result['standalone_ivss']['score']
            elif correlation_type == 'hybrid':
                if 'hybrid_ivss' in result and 'score' in result['hybrid_ivss']:
                    comparison_score = result['hybrid_ivss']['score']
            
            if comparison_score is not None:
                cvss_scores.append(cvss_score)
                comparison_scores.append(comparison_score)
                network_types.append('standard' if result.get('simulation') == 'standard_network' else 'edge')
    
    # Set title and labels
    if correlation_type == 'ivss':
        y_label = 'IVSS Score'
        title = 'CVSS vs IVSS Correlation'
    else:
        y_label = 'Hybrid Score'
        title = 'CVSS vs Hybrid Correlation'
    
    # Create scatter plot if we have data
    if cvss_scores and comparison_scores:
        # Create two different markers for standard and edge networks
        standard_indices = [i for i, n in enumerate(network_types) if n == 'standard']
        edge_indices = [i for i, n in enumerate(network_types) if n == 'edge']
        
        # Plot standard network points
        if standard_indices:
            std_cvss = [cvss_scores[i] for i in standard_indices]
            std_comp = [comparison_scores[i] for i in standard_indices]
            
            ax.scatter(
                std_cvss,
                std_comp,
                c='blue',
                marker='o',
                s=80,
                alpha=0.7,
                edgecolors='darkblue',
                linewidths=0.5,
                label='Standard Network'
            )
        
        # Plot edge network points
        if edge_indices:
            edge_cvss = [cvss_scores[i] for i in edge_indices]
            edge_comp = [comparison_scores[i] for i in edge_indices]
            
            ax.scatter(
                edge_cvss,
                edge_comp,
                c='red',
                marker='^',
                s=80,
                alpha=0.7,
                edgecolors='darkred',
                linewidths=0.5,
                label='Edge/Hidden Network'
            )
        
        # Add reference line (y=x)
        ax.plot([0, 11], [0, 11], color='gray', linestyle='--', alpha=0.5)
        
        # Labels and title
        ax.set_xlabel('CVSS Score', fontweight='bold', fontsize=12)
        ax.set_ylabel(y_label, fontweight='bold', fontsize=12)
        ax.set_title(title, fontweight='bold', fontsize=14)
        
        # Set grid, limits, and aspect
        ax.grid(True, linestyle='--', alpha=0.6)
        ax.set_aspect('equal')
        ax.set_xlim(0, 11)
        ax.set_ylim(0, 11)
        
        # Add threshold lines
        threshold_style = {'linestyle': '--', 'color': 'gray', 'alpha': 0.5}
        ax.axhline(y=9.0, **threshold_style)
        ax.axhline(y=7.0, **threshold_style)
        ax.axhline(y=4.0, **threshold_style)
        
        ax.axvline(x=9.0, **threshold_style)
        ax.axvline(x=7.0, **threshold_style)
        ax.axvline(x=4.0, **threshold_style)
        
        # Add legend
        ax.legend()
    else:
        ax.text(0.5, 0.5, f"No {title} data available", 
               ha='center', va='center', fontsize=12)
        ax.set_title(title, fontweight='bold', fontsize=14)
        ax.axis('off')

def _create_combined_distribution(ax, standard_comparator, hidden_comparator):
    """Create a histogram showing score distribution from both networks."""
    # Combine results from both comparators
    standard_results = standard_comparator.results
    hidden_results = hidden_comparator.results
    
    # Collect scores from standard network
    std_cvss = []
    std_ivss = []
    
    for result in standard_results:
        if 'cvss' in result and 'score' in result['cvss']:
            std_cvss.append(result['cvss']['score'])
        
        if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            std_ivss.append(result['standalone_ivss']['score'])
    
    # Collect scores from edge/hidden network
    edge_cvss = []
    edge_ivss = []
    
    for result in hidden_results:
        if 'cvss' in result and 'score' in result['cvss']:
            edge_cvss.append(result['cvss']['score'])
        
        if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            edge_ivss.append(result['standalone_ivss']['score'])
    
    # Create histograms if we have data
    has_data = bool(std_cvss or std_ivss or edge_cvss or edge_ivss)
    
    if has_data:
        bins = np.linspace(0, 10, 11)
        
        # Standard network CVSS
        if std_cvss:
            ax.hist(std_cvss, bins=bins, alpha=0.6, color='blue', 
                   label='Standard CVSS', histtype='step', linewidth=2)
        
        # Standard network IVSS
        if std_ivss:
            ax.hist(std_ivss, bins=bins, alpha=0.6, color='green', 
                   label='Standard IVSS', histtype='step', linewidth=2)
        
        # Edge network CVSS
        if edge_cvss:
            ax.hist(edge_cvss, bins=bins, alpha=0.6, color='red', 
                   label='Edge CVSS', histtype='step', linewidth=2)
        
        # Edge network IVSS
        if edge_ivss:
            ax.hist(edge_ivss, bins=bins, alpha=0.6, color='purple', 
                   label='Edge IVSS', histtype='step', linewidth=2)
        
        # Add severity threshold lines
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.7)
        
        # Labels and title
        ax.set_xlabel('Score', fontweight='bold', fontsize=12)
        ax.set_ylabel('Frequency', fontweight='bold', fontsize=12)
        ax.set_title('Score Distribution', fontweight='bold', fontsize=14)
        ax.legend()
    else:
        ax.text(0.5, 0.5, "No score distribution data available", 
               ha='center', va='center', fontsize=12)
        ax.set_title('Score Distribution', fontweight='bold', fontsize=14)
        ax.axis('off')

def _create_combined_severity_shifts(ax, standard_comparator, hidden_comparator):
    """Create pie charts showing severity shifts from both networks."""
    # Get the current position of the axis
    bbox = ax.get_position()
    ax.set_visible(False)  # Hide the original axis
    
    # Create two side-by-side subplots
    ax1 = ax.figure.add_axes([bbox.x0, bbox.y0, bbox.width/2-0.01, bbox.height])
    ax2 = ax.figure.add_axes([bbox.x0 + bbox.width/2+0.01, bbox.y0, bbox.width/2-0.01, bbox.height])
    
    # Helper function to calculate severity shifts
    def calculate_shifts(results):
        shifts = {}
        for result in results:
            if 'cvss' in result and 'score' in result['cvss'] and \
               'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                cvss_score = result['cvss']['score']
                ivss_score = result['standalone_ivss']['score']
                
                # Determine severity categories
                cvss_category = _get_severity_category(cvss_score)
                ivss_category = _get_severity_category(ivss_score)
                
                # Determine shift type
                if cvss_category == ivss_category:
                    shift = "No Change"
                elif _category_value(cvss_category) < _category_value(ivss_category):
                    shift = f"Increased ({cvss_category} → {ivss_category})"
                else:
                    shift = f"Decreased ({cvss_category} → {ivss_category})"
                
                shifts[shift] = shifts.get(shift, 0) + 1
        return shifts
    
    # Calculate shifts for standard network
    std_shifts = calculate_shifts(standard_comparator.results)
    
    # Calculate shifts for edge/hidden network
    edge_shifts = calculate_shifts(hidden_comparator.results)
    
    # Plot standard network shifts
    _plot_shifts_pie(ax1, std_shifts, 'Standard Network CVSS vs IVSS Shifts')
    
    # Plot edge/hidden network shifts
    _plot_shifts_pie(ax2, edge_shifts, 'Edge/Hidden Network CVSS vs IVSS Shifts')

def _plot_shifts_pie(ax, shifts, title):
    """Helper method to plot a single pie chart for severity shifts."""
    if shifts:
        labels = list(shifts.keys())
        sizes = list(shifts.values())
        
        # Create colormap
        colours = plt.cm.tab10(np.linspace(0, 1, len(labels)))
        
        wedges, texts, autotexts = ax.pie(
            sizes, 
            labels=labels, 
            autopct='%1.1f%%', 
            startangle=90, 
            colors=colours,
            wedgeprops={'edgecolor': 'w', 'linewidth': 1}
        )
        
        # Adjust font size for readability
        for text in texts:
            text.set_fontsize(8)
        
        # Equal aspect ratio for circle
        ax.axis('equal')
        
        ax.set_title(title, fontweight='bold', fontsize=12)
    else:
        ax.text(0.5, 0.5, "No data available", 
              ha='center', va='center', fontsize=10)
        ax.set_title(title, fontweight='bold', fontsize=12)
        ax.axis('off')

def _get_severity_category(score):
    """Get severity category based on score."""
    if score < 0.1:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"

def _category_value(category):
    """Convert severity category to numerical value for comparison."""
    values = {
        "None": 0,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    return values.get(category, 0)

def _create_combined_statistics(ax, standard_comparator, hidden_comparator):
    """Create a statistics summary text box with data from both networks."""
    # Calculate key statistics for standard network
    std_stats = _calculate_network_statistics(standard_comparator.results, "Standard")
    
    # Calculate key statistics for edge/hidden network
    edge_stats = _calculate_network_statistics(hidden_comparator.results, "Edge/Hidden")
    
    # Create combined statistics text
    stats_text = "NETWORK COMPARISON STATISTICS\n\n"
    
    # Add vulnerability counts
    stats_text += f"Total Vulnerabilities:\n"
    stats_text += f"  Standard Network: {std_stats['count']}\n"
    stats_text += f"  Edge/Hidden Network: {edge_stats['count']}\n\n"
    
    # Add average scores
    stats_text += "Average CVSS Scores:\n"
    stats_text += f"  Standard: {std_stats['cvss_avg']:.2f}\n"
    stats_text += f"  Edge/Hidden: {edge_stats['cvss_avg']:.2f}\n"
    stats_text += f"  Difference: {abs(std_stats['cvss_avg'] - edge_stats['cvss_avg']):.2f}\n\n"
    
    stats_text += "Average IVSS Scores:\n"
    stats_text += f"  Standard: {std_stats['ivss_avg']:.2f}\n"
    stats_text += f"  Edge/Hidden: {edge_stats['ivss_avg']:.2f}\n"
    stats_text += f"  Difference: {abs(std_stats['ivss_avg'] - edge_stats['ivss_avg']):.2f}\n\n"
    
    # Key insights
    stats_text += "Key Insights:\n"
    
    # Difference between scoring methods
    cvss_diff = abs(std_stats['cvss_avg'] - edge_stats['cvss_avg'])
    ivss_diff = abs(std_stats['ivss_avg'] - edge_stats['ivss_avg'])
    
    if cvss_diff > ivss_diff:
        stats_text += "• CVSS shows greater variation between networks\n"
    else:
        stats_text += "• IVSS shows greater variation between networks\n"
    
    # Difference in severity shifts
    if std_stats['shift_increased'] > edge_stats['shift_increased']:
        stats_text += "• Standard network has more severity increases\n"
    elif std_stats['shift_increased'] < edge_stats['shift_increased']:
        stats_text += "• Edge network has more severity increases\n"
    
    if std_stats['shift_decreased'] > edge_stats['shift_decreased']:
        stats_text += "• Standard network has more severity decreases\n"
    elif std_stats['shift_decreased'] < edge_stats['shift_decreased']:
        stats_text += "• Edge network has more severity decreases\n"
    
    # Style properties
    props = dict(boxstyle='round', facecolor='white', alpha=0.8)
    
    # Place text in center of axes
    ax.text(0.5, 0.5, stats_text, transform=ax.transAxes, fontsize=10,
           verticalalignment='center', horizontalalignment='center',
           bbox=props, family='monospace')
    
    ax.set_title('Network Comparison Statistics', fontweight='bold', fontsize=14)
    ax.axis('off')

def _calculate_network_statistics(results, network_name):
    """Calculate statistics for a specific network's results."""
    stats = {
        "name": network_name,
        "count": len(results),
        "cvss_avg": 0,
        "ivss_avg": 0,
        "hybrid_avg": 0,
        "shift_increased": 0,
        "shift_decreased": 0,
        "shift_none": 0
    }
    
    # Calculate average scores
    cvss_scores = []
    ivss_scores = []
    hybrid_scores = []
    
    for result in results:
        # Get CVSS score
        if 'cvss' in result and 'score' in result['cvss']:
            cvss_score = result['cvss']['score']
            cvss_scores.append(cvss_score)
        
        # Get IVSS score
        if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            ivss_score = result['standalone_ivss']['score']
            ivss_scores.append(ivss_score)
        
        # Get Hybrid score
        if 'hybrid_ivss' in result and 'score' in result['hybrid_ivss']:
            hybrid_score = result['hybrid_ivss']['score']
            hybrid_scores.append(hybrid_score)
        
        # Count severity shifts
        if 'cvss' in result and 'score' in result['cvss'] and \
           'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            cvss_cat = _get_severity_category(result['cvss']['score'])
            ivss_cat = _get_severity_category(result['standalone_ivss']['score'])
            
            if cvss_cat == ivss_cat:
                stats["shift_none"] += 1
            elif _category_value(cvss_cat) < _category_value(ivss_cat):
                stats["shift_increased"] += 1
            else:
                stats["shift_decreased"] += 1
    
    # Calculate averages
    if cvss_scores:
        stats["cvss_avg"] = sum(cvss_scores) / len(cvss_scores)
    if ivss_scores:
        stats["ivss_avg"] = sum(ivss_scores) / len(ivss_scores)
    if hybrid_scores:
        stats["hybrid_avg"] = sum(hybrid_scores) / len(hybrid_scores)
    
    return stats

def generate_combined_dashboard(standard_dir, hidden_dir, save_path, save_individual_plots=False):
    """Wrapper function that calls the static method of VulnerabilityVisualisation."""
    return VulnerabilityVisualisation.generate_combined_dashboard(
        standard_dir, hidden_dir, save_path, save_individual_plots
    )

def _create_combined_score_comparison(ax, standard_comparator, hidden_comparator):
    """
    Create a bar chart comparing vulnerability scores across standard and edge networks.
    
    Args:
        ax: The axis to plot on
        standard_comparator: Comparator with standard network results
        hidden_comparator: Comparator with edge/hidden network results
    """
    # Combine results from both comparators
    all_vulns = {}
    
    # Process standard network results
    for result in standard_comparator.results:
        vuln_id = result['id']
        if vuln_id not in all_vulns:
            all_vulns[vuln_id] = {'standard': {}, 'edge': {}}
        
        # Extract scores
        cvss_score = result.get('cvss', {}).get('score', 0)
        ivss_score = result.get('standalone_ivss', {}).get('score', 0)
        hybrid_score = result.get('hybrid_ivss', {}).get('score', 0)
            
        all_vulns[vuln_id]['standard'] = {
            'cvss': cvss_score,
            'ivss': ivss_score,
            'hybrid': hybrid_score
        }
        
    # Process edge/hidden network results
    for result in hidden_comparator.results:
        vuln_id = result['id']
        if vuln_id not in all_vulns:
            all_vulns[vuln_id] = {'standard': {}, 'edge': {}}
            
        # Extract scores
        cvss_score = result.get('cvss', {}).get('score', 0)
        ivss_score = result.get('standalone_ivss', {}).get('score', 0)
        hybrid_score = result.get('hybrid_ivss', {}).get('score', 0)
            
        all_vulns[vuln_id]['edge'] = {
            'cvss': cvss_score,
            'ivss': ivss_score,
            'hybrid': hybrid_score
        }
    
    # Prepare data for plotting
    vuln_ids = list(all_vulns.keys())
    
    # Check if we have any data to plot
    if not vuln_ids:
        ax.text(0.5, 0.5, "No vulnerability data available for comparison", 
               ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Vulnerability Scoring Comparison', fontweight='bold', fontsize=14)
        ax.axis('off')
        return
    
    x = np.arange(len(vuln_ids))
    width = 0.1  # narrower bars for 6 categories
    
    # Extract data arrays
    standard_cvss = [all_vulns[vid]['standard'].get('cvss', 0) for vid in vuln_ids]
    standard_ivss = [all_vulns[vid]['standard'].get('ivss', 0) for vid in vuln_ids]
    standard_hybrid = [all_vulns[vid]['standard'].get('hybrid', 0) for vid in vuln_ids]
    
    edge_cvss = [all_vulns[vid]['edge'].get('cvss', 0) for vid in vuln_ids]
    edge_ivss = [all_vulns[vid]['edge'].get('ivss', 0) for vid in vuln_ids]
    edge_hybrid = [all_vulns[vid]['edge'].get('hybrid', 0) for vid in vuln_ids]
    
    # Plot the bars
    ax.bar(x - width*2.5, standard_cvss, width, label='Standard CVSS', 
          color='blue', alpha=0.9)
    ax.bar(x - width*1.5, standard_ivss, width, label='Standard IVSS', 
          color='green', alpha=0.9)
    ax.bar(x - width*0.5, standard_hybrid, width, label='Standard Hybrid', 
          color='cyan', alpha=0.9)
    
    ax.bar(x + width*0.5, edge_cvss, width, label='Edge CVSS', 
          color='red', alpha=0.7, hatch='/')
    ax.bar(x + width*1.5, edge_ivss, width, label='Edge IVSS', 
          color='purple', alpha=0.7, hatch='/')
    ax.bar(x + width*2.5, edge_hybrid, width, label='Edge Hybrid', 
          color='orange', alpha=0.7, hatch='/')
    
    # Configure axes
    ax.set_xlabel('Vulnerability', fontweight='bold', fontsize=12)
    ax.set_ylabel('Score', fontweight='bold', fontsize=12)
    ax.set_title('Vulnerability Scoring Comparison: Standard vs Edge Networks', 
                fontweight='bold', fontsize=14)
    ax.set_xticks(x)
    
    # Create simplified labels by extracting just the CVE ID if present
    simplified_labels = []
    for vuln_id in vuln_ids:
        if "CVE-" in vuln_id:
            # Extract just the CVE ID
            match = re.search(r'(CVE-\d+-\d+)', vuln_id)
            if match:
                simplified_labels.append(match.group(1))
            else:
                simplified_labels.append(vuln_id)
        else:
            # Use original ID but limit length
            if len(vuln_id) > 15:
                simplified_labels.append(vuln_id[:12] + "...")
            else:
                simplified_labels.append(vuln_id)
    
    ax.set_xticklabels(simplified_labels, rotation=45, ha='right', fontsize=10)
    
    # Add legend with smaller font
    ax.legend(fontsize=9, loc='upper right')
    
    # Add severity threshold lines
    ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5)
    ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5)
    ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5)
    
    # Add grid for better readability
    ax.grid(axis='y', alpha=0.3)

def _create_correlation_panel(ax, correlation_type, standard_comparator, hidden_comparator):
    """
    Create a scatter correlation plot for a specific correlation type.
    
    Args:
        ax: The axis to plot on
        correlation_type: 'ivss' for CVSS vs IVSS or 'hybrid' for CVSS vs Hybrid
        standard_comparator: Comparator with standard network results
        hidden_comparator: Comparator with edge/hidden network results
    """
    # Combine results from both comparators
    all_results = standard_comparator.results + hidden_comparator.results
    
    # Collect scores for plotting
    cvss_scores = []
    comparison_scores = []
    network_types = []  # To track which network each point belongs to
    
    for result in all_results:
        if 'cvss' in result and 'score' in result['cvss']:
            cvss_score = result['cvss']['score']
            
            # Get comparison score (IVSS or Hybrid)
            comparison_score = None
            if correlation_type == 'ivss':
                if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                    comparison_score = result['standalone_ivss']['score']
            elif correlation_type == 'hybrid':
                if 'hybrid_ivss' in result and 'score' in result['hybrid_ivss']:
                    comparison_score = result['hybrid_ivss']['score']
            
            if comparison_score is not None:
                cvss_scores.append(cvss_score)
                comparison_scores.append(comparison_score)
                network_types.append('standard' if result.get('simulation') == 'standard_network' else 'edge')
    
    # Set title and labels
    if correlation_type == 'ivss':
        y_label = 'IVSS Score'
        title = 'CVSS vs IVSS Correlation'
    else:
        y_label = 'Hybrid Score'
        title = 'CVSS vs Hybrid Correlation'
    
    # Create scatter plot if we have data
    if cvss_scores and comparison_scores:
        # Create two different markers for standard and edge networks
        standard_indices = [i for i, n in enumerate(network_types) if n == 'standard']
        edge_indices = [i for i, n in enumerate(network_types) if n == 'edge']
        
        # Plot standard network points
        if standard_indices:
            std_cvss = [cvss_scores[i] for i in standard_indices]
            std_comp = [comparison_scores[i] for i in standard_indices]
            
            ax.scatter(
                std_cvss,
                std_comp,
                c='blue',
                marker='o',
                s=80,
                alpha=0.7,
                edgecolors='darkblue',
                linewidths=0.5,
                label='Standard Network'
            )
        
        # Plot edge network points
        if edge_indices:
            edge_cvss = [cvss_scores[i] for i in edge_indices]
            edge_comp = [comparison_scores[i] for i in edge_indices]
            
            ax.scatter(
                edge_cvss,
                edge_comp,
                c='red',
                marker='^',
                s=80,
                alpha=0.7,
                edgecolors='darkred',
                linewidths=0.5,
                label='Edge/Hidden Network'
            )
        
        # Add reference line (y=x)
        ax.plot([0, 11], [0, 11], color='gray', linestyle='--', alpha=0.5)
        
        # Labels and title
        ax.set_xlabel('CVSS Score', fontweight='bold', fontsize=12)
        ax.set_ylabel(y_label, fontweight='bold', fontsize=12)
        ax.set_title(title, fontweight='bold', fontsize=14)
        
        # Set grid, limits, and aspect
        ax.grid(True, linestyle='--', alpha=0.6)
        ax.set_aspect('equal')
        ax.set_xlim(0, 11)
        ax.set_ylim(0, 11)
        
        # Add threshold lines
        threshold_style = {'linestyle': '--', 'color': 'gray', 'alpha': 0.5}
        ax.axhline(y=9.0, **threshold_style)
        ax.axhline(y=7.0, **threshold_style)
        ax.axhline(y=4.0, **threshold_style)
        
        ax.axvline(x=9.0, **threshold_style)
        ax.axvline(x=7.0, **threshold_style)
        ax.axvline(x=4.0, **threshold_style)
        
        # Add legend
        ax.legend()
    else:
        ax.text(0.5, 0.5, f"No {title} data available", 
               ha='center', va='center', fontsize=12)
        ax.set_title(title, fontweight='bold', fontsize=14)
        ax.axis('off')

def _create_combined_distribution(ax, standard_comparator, hidden_comparator):
    """Create a histogram showing score distribution from both networks."""
    # Combine results from both comparators
    standard_results = standard_comparator.results
    hidden_results = hidden_comparator.results
    
    # Collect scores from standard network
    std_cvss = []
    std_ivss = []
    
    for result in standard_results:
        if 'cvss' in result and 'score' in result['cvss']:
            std_cvss.append(result['cvss']['score'])
        
        if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            std_ivss.append(result['standalone_ivss']['score'])
    
    # Collect scores from edge/hidden network
    edge_cvss = []
    edge_ivss = []
    
    for result in hidden_results:
        if 'cvss' in result and 'score' in result['cvss']:
            edge_cvss.append(result['cvss']['score'])
        
        if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
            edge_ivss.append(result['standalone_ivss']['score'])
    
    # Create histograms if we have data
    has_data = bool(std_cvss or std_ivss or edge_cvss or edge_ivss)
    
    if has_data:
        bins = np.linspace(0, 10, 11)
        
        # Standard network CVSS
        if std_cvss:
            ax.hist(std_cvss, bins=bins, alpha=0.6, color='blue', 
                   label='Standard CVSS', histtype='step', linewidth=2)
        
        # Standard network IVSS
        if std_ivss:
            ax.hist(std_ivss, bins=bins, alpha=0.6, color='green', 
                   label='Standard IVSS', histtype='step', linewidth=2)
        
        # Edge network CVSS
        if edge_cvss:
            ax.hist(edge_cvss, bins=bins, alpha=0.6, color='red', 
                   label='Edge CVSS', histtype='step', linewidth=2)
        
        # Edge network IVSS
        if edge_ivss:
            ax.hist(edge_ivss, bins=bins, alpha=0.6, color='purple', 
                   label='Edge IVSS', histtype='step', linewidth=2)
        
        # Add severity threshold lines
        ax.axvline(x=9.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=7.0, linestyle='--', color='gray', alpha=0.7)
        ax.axvline(x=4.0, linestyle='--', color='gray', alpha=0.7)
        
        # Labels and title
        ax.set_xlabel('Score', fontweight='bold', fontsize=12)
        ax.set_ylabel('Frequency', fontweight='bold', fontsize=12)
        ax.set_title('Score Distribution', fontweight='bold', fontsize=14)
        ax.legend()
    else:
        ax.text(0.5, 0.5, "No score distribution data available", 
               ha='center', va='center', fontsize=12)
        ax.set_title('Score Distribution', fontweight='bold', fontsize=14)
        ax.axis('off')

def _create_combined_severity_shifts(ax, standard_comparator, hidden_comparator):
    """Create pie charts showing severity shifts from both networks."""
    # Get the current position of the axis
    bbox = ax.get_position()
    ax.set_visible(False)  # Hide the original axis
    
    # Create two side-by-side subplots
    ax1 = ax.figure.add_axes([bbox.x0, bbox.y0, bbox.width/2-0.01, bbox.height])
    ax2 = ax.figure.add_axes([bbox.x0 + bbox.width/2+0.01, bbox.y0, bbox.width/2-0.01, bbox.height])
    
    # Helper function to calculate severity shifts
    def calculate_shifts(results):
        shifts = {}
        for result in results:
            if 'cvss' in result and 'score' in result['cvss'] and \
               'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                cvss_score = result['cvss']['score']
                ivss_score = result['standalone_ivss']['score']
                
                # Determine severity categories
                cvss_category = _get_severity_category(cvss_score)
                ivss_category = _get_severity_category(ivss_score)
                
                # Determine shift type
                if cvss_category == ivss_category:
                    shift = "No Change"
                elif _category_value(cvss_category) < _category_value(ivss_category):
                    shift = f"Increased ({cvss_category} → {ivss_category})"
                else:
                    shift = f"Decreased ({cvss_category} → {ivss_category})"
                
                shifts[shift] = shifts.get(shift, 0) + 1
        return shifts
    
    # Calculate shifts for standard network
    std_shifts = calculate_shifts(standard_comparator.results)
    
    # Calculate shifts for edge/hidden network
    edge_shifts = calculate_shifts(hidden_comparator.results)
    
    # Plot standard network shifts
    _plot_shifts_pie(ax1, std_shifts, 'Standard Network CVSS vs IVSS Shifts')
    
    # Plot edge/hidden network shifts
    _plot_shifts_pie(ax2, edge_shifts, 'Edge/Hidden Network CVSS vs IVSS Shifts')


def _create_combined_statistics(ax, standard_comparator, hidden_comparator):
    """Create a statistics summary text box with data from both networks."""
    # Calculate key statistics for standard network
    std_stats = _calculate_network_statistics(standard_comparator.results, "Standard")
    
    # Calculate key statistics for edge/hidden network
    edge_stats = _calculate_network_statistics(hidden_comparator.results, "Edge/Hidden")
    
    # Create combined statistics text
    stats_text = "NETWORK COMPARISON STATISTICS\n\n"
    
    # Add vulnerability counts
    stats_text += f"Total Vulnerabilities:\n"
    stats_text += f"  Standard Network: {std_stats['count']}\n"
    stats_text += f"  Edge/Hidden Network: {edge_stats['count']}\n\n"
    
    # Add average scores
    stats_text += "Average CVSS Scores:\n"
    stats_text += f"  Standard: {std_stats['cvss_avg']:.2f}\n"
    stats_text += f"  Edge/Hidden: {edge_stats['cvss_avg']:.2f}\n"
    stats_text += f"  Difference: {abs(std_stats['cvss_avg'] - edge_stats['cvss_avg']):.2f}\n\n"
    
    stats_text += "Average IVSS Scores:\n"
    stats_text += f"  Standard: {std_stats['ivss_avg']:.2f}\n"
    stats_text += f"  Edge/Hidden: {edge_stats['ivss_avg']:.2f}\n"
    stats_text += f"  Difference: {abs(std_stats['ivss_avg'] - edge_stats['ivss_avg']):.2f}\n\n"
    
    # Key insights
    stats_text += "Key Insights:\n"
    
    # Difference between scoring methods
    cvss_diff = abs(std_stats['cvss_avg'] - edge_stats['cvss_avg'])
    ivss_diff = abs(std_stats['ivss_avg'] - edge_stats['ivss_avg'])
    
    if cvss_diff > ivss_diff:
        stats_text += "• CVSS shows greater variation between networks\n"
    else:
        stats_text += "• IVSS shows greater variation between networks\n"
    
    # Difference in severity shifts
    if std_stats['shift_increased'] > edge_stats['shift_increased']:
        stats_text += "• Standard network has more severity increases\n"
    elif std_stats['shift_increased'] < edge_stats['shift_increased']:
        stats_text += "• Edge network has more severity increases\n"
    
    if std_stats['shift_decreased'] > edge_stats['shift_decreased']:
        stats_text += "• Standard network has more severity decreases\n"
    elif std_stats['shift_decreased'] < edge_stats['shift_decreased']:
        stats_text += "• Edge network has more severity decreases\n"
    
    # Style properties
    props = dict(boxstyle='round', facecolor='white', alpha=0.8)
    
    # Place text in center of axes
    ax.text(0.5, 0.5, stats_text, transform=ax.transAxes, fontsize=10,
           verticalalignment='center', horizontalalignment='center',
           bbox=props, family='monospace')
    
    ax.set_title('Network Comparison Statistics', fontweight='bold', fontsize=14)
    ax.axis('off')

def _create_combined_score_comparison(ax, standard_comparator, hidden_comparator):
    """
    Create a bar chart comparing vulnerability scores across standard and edge networks.
    
    Args:
        ax: The axis to plot on
        standard_comparator: Comparator with standard network results
        hidden_comparator: Comparator with edge/hidden network results
    """
    # Combine results from both comparators
    all_vulns = {}
    
    # Process standard network results
    for result in standard_comparator.results:
        vuln_id = result['id']
        if vuln_id not in all_vulns:
            all_vulns[vuln_id] = {'standard': {}, 'edge': {}}
        
        # Extract scores
        cvss_score = result.get('cvss', {}).get('score', 0)
        ivss_score = result.get('standalone_ivss', {}).get('score', 0)
        hybrid_score = result.get('hybrid_ivss', {}).get('score', 0)
            
        all_vulns[vuln_id]['standard'] = {
            'cvss': cvss_score,
            'ivss': ivss_score,
            'hybrid': hybrid_score
        }
        
    # Process edge/hidden network results
    for result in hidden_comparator.results:
        vuln_id = result['id']
        if vuln_id not in all_vulns:
            all_vulns[vuln_id] = {'standard': {}, 'edge': {}}
            
        # Extract scores
        cvss_score = result.get('cvss', {}).get('score', 0)
        ivss_score = result.get('standalone_ivss', {}).get('score', 0)
        hybrid_score = result.get('hybrid_ivss', {}).get('score', 0)
            
        all_vulns[vuln_id]['edge'] = {
            'cvss': cvss_score,
            'ivss': ivss_score,
            'hybrid': hybrid_score
        }
    
    # Prepare data for plotting
    vuln_ids = list(all_vulns.keys())
    
    # Check if we have any data to plot
    if not vuln_ids:
        ax.text(0.5, 0.5, "No vulnerability data available for comparison", 
               ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Vulnerability Scoring Comparison', fontweight='bold', fontsize=14)
        ax.axis('off')
        return
    
    x = np.arange(len(vuln_ids))
    width = 0.1  # narrower bars for 6 categories
    
    # Extract data arrays
    standard_cvss = [all_vulns[vid]['standard'].get('cvss', 0) for vid in vuln_ids]
    standard_ivss = [all_vulns[vid]['standard'].get('ivss', 0) for vid in vuln_ids]
    standard_hybrid = [all_vulns[vid]['standard'].get('hybrid', 0) for vid in vuln_ids]
    
    edge_cvss = [all_vulns[vid]['edge'].get('cvss', 0) for vid in vuln_ids]
    edge_ivss = [all_vulns[vid]['edge'].get('ivss', 0) for vid in vuln_ids]
    edge_hybrid = [all_vulns[vid]['edge'].get('hybrid', 0) for vid in vuln_ids]
    
    # Plot the bars
    ax.bar(x - width*2.5, standard_cvss, width, label='Standard CVSS', 
          color='blue', alpha=0.9)
    ax.bar(x - width*1.5, standard_ivss, width, label='Standard IVSS', 
          color='green', alpha=0.9)
    ax.bar(x - width*0.5, standard_hybrid, width, label='Standard Hybrid', 
          color='cyan', alpha=0.9)
    
    ax.bar(x + width*0.5, edge_cvss, width, label='Edge CVSS', 
          color='red', alpha=0.7, hatch='/')
    ax.bar(x + width*1.5, edge_ivss, width, label='Edge IVSS', 
          color='purple', alpha=0.7, hatch='/')
    ax.bar(x + width*2.5, edge_hybrid, width, label='Edge Hybrid', 
          color='orange', alpha=0.7, hatch='/')
    
    # Configure axes
    ax.set_xlabel('Vulnerability', fontweight='bold', fontsize=12)
    ax.set_ylabel('Score', fontweight='bold', fontsize=12)
    ax.set_title('Vulnerability Scoring Comparison: Standard vs Edge Networks', 
                fontweight='bold', fontsize=14)
    ax.set_xticks(x)
    
    # Create simplified labels by extracting just the CVE ID if present
    simplified_labels = []
    for vuln_id in vuln_ids:
        if "CVE-" in vuln_id:
            # Extract just the CVE ID
            match = re.search(r'(CVE-\d+-\d+)', vuln_id)
            if match:
                simplified_labels.append(match.group(1))
            else:
                simplified_labels.append(vuln_id)
        else:
            # Use original ID but limit length
            if len(vuln_id) > 15:
                simplified_labels.append(vuln_id[:12] + "...")
            else:
                simplified_labels.append(vuln_id)
    
    ax.set_xticklabels(simplified_labels, rotation=45, ha='right', fontsize=10)
    
    # Add legend with smaller font
    ax.legend(fontsize=9, loc='upper right')
    
    # Add severity threshold lines
    ax.axhline(y=9.0, linestyle='--', color='gray', alpha=0.5)
    ax.axhline(y=7.0, linestyle='--', color='gray', alpha=0.5)
    ax.axhline(y=4.0, linestyle='--', color='gray', alpha=0.5)
    
    # Add grid for better readability
    ax.grid(axis='y', alpha=0.3)