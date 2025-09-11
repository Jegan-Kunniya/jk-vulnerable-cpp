"""
Security Compliance Dashboard

This interactive dashboard displays security findings from the security_compliance_report.xlsx
with correlation analysis and professional visualization.

Cross-platform compatible for Windows, macOS, and Linux.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import re

# Set page configuration
st.set_page_config(
    page_title="Security Compliance Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 0.5rem 0;
    }
    .section-header {
        font-size: 1.5rem;
        font-weight: bold;
        color: #2c3e50;
        margin: 1.5rem 0 1rem 0;
        border-bottom: 2px solid #3498db;
        padding-bottom: 0.5rem;
    }
    .sidebar .sidebar-content {
        background-color: #f1f3f6;
    }
    .stSelectbox label {
        font-weight: bold;
        color: #2c3e50;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_data():
    """Load and process the security compliance data."""
    try:
        # Try to load from the repository root
        excel_path = Path(__file__).parent.parent / "security_compliance_report.xlsx"
        if not excel_path.exists():
            # Fallback to current directory
            excel_path = Path("security_compliance_report.xlsx")
        
        df = pd.read_excel(excel_path, sheet_name='Security_Findings')
        
        # Select only the required fields
        required_fields = [
            'Rule_Name', 'Full_Description', 'Severity', 'CWE_ID', 'CVE_ID', 
            'CVSS_Base_Score', 'Component_Package', 'HIPAA_Rules_Impacted', 
            'GDPR_Articles_Impacted', 'FDA_Premarket_Topic', 'Medical_Tech_Impact', 'Match_Source'
        ]
        
        # Filter to required fields
        df = df[required_fields].copy()
        
        # Clean and standardize data
        df['Severity'] = df['Severity'].fillna('UNKNOWN').str.upper()
        df['Component_Package'] = df['Component_Package'].fillna('Unknown')
        df['Match_Source'] = df['Match_Source'].fillna('Unknown')
        df['CVSS_Score_Numeric'] = df['CVSS_Base_Score'].apply(convert_cvss_to_numeric)
        
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return None

def convert_cvss_to_numeric(score):
    """Convert CVSS scores to numeric values for analysis."""
    if pd.isna(score):
        return 0
    score_str = str(score).lower()
    if 'critical' in score_str:
        return 9.5
    elif 'high' in score_str:
        return 7.5
    elif 'medium' in score_str:
        return 5.0
    elif 'low' in score_str:
        return 2.5
    else:
        # Try to extract numeric value
        try:
            return float(re.findall(r'\d+\.?\d*', score_str)[0])
        except:
            return 5.0

def create_severity_distribution_chart(df):
    """Create severity distribution visualization."""
    severity_counts = df['Severity'].value_counts()
    
    # Define colors for severity levels
    colors = {
        'CRITICAL': '#e74c3c',
        'HIGH': '#f39c12',
        'MEDIUM': '#f1c40f',
        'LOW': '#27ae60',
        'UNKNOWN': '#95a5a6'
    }
    
    color_list = [colors.get(sev, '#95a5a6') for sev in severity_counts.index]
    
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title="Security Findings by Severity Level",
        color_discrete_sequence=color_list
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(
        font=dict(size=12),
        title_x=0.5,
        showlegend=True
    )
    
    return fig

def create_cvss_score_distribution(df):
    """Create CVSS score distribution chart."""
    fig = px.histogram(
        df, 
        x='CVSS_Score_Numeric',
        nbins=10,
        title="CVSS Score Distribution",
        labels={'CVSS_Score_Numeric': 'CVSS Score', 'count': 'Number of Findings'},
        color_discrete_sequence=['#3498db']
    )
    
    fig.update_layout(
        xaxis_title="CVSS Score",
        yaxis_title="Number of Findings",
        title_x=0.5
    )
    
    return fig

def create_correlation_heatmap(df):
    """Create correlation heatmap for key metrics."""
    # Create numeric encodings for categorical variables
    correlation_data = df.copy()
    
    # Encode categorical variables
    categorical_cols = ['Severity', 'Component_Package', 'Match_Source']
    for col in categorical_cols:
        if col in correlation_data.columns:
            correlation_data[f'{col}_encoded'] = pd.Categorical(correlation_data[col]).codes
    
    # Select numeric columns for correlation
    numeric_cols = ['CVSS_Score_Numeric', 'Severity_encoded', 'Component_Package_encoded', 'Match_Source_encoded']
    correlation_subset = correlation_data[numeric_cols].corr()
    
    fig = px.imshow(
        correlation_subset,
        labels=dict(x="Metrics", y="Metrics", color="Correlation"),
        x=correlation_subset.columns,
        y=correlation_subset.columns,
        color_continuous_scale="RdBu_r",
        title="Correlation Matrix of Key Security Metrics"
    )
    
    fig.update_layout(title_x=0.5)
    return fig

def create_component_analysis(df):
    """Create component package analysis."""
    component_counts = df['Component_Package'].value_counts().head(10)
    
    fig = px.bar(
        x=component_counts.values,
        y=component_counts.index,
        orientation='h',
        title="Top 10 Components by Number of Security Findings",
        labels={'x': 'Number of Findings', 'y': 'Component Package'},
        color_discrete_sequence=['#e74c3c']
    )
    
    fig.update_layout(
        title_x=0.5,
        yaxis={'categoryorder': 'total ascending'}
    )
    
    return fig

def create_compliance_impact_chart(df):
    """Create compliance impact analysis."""
    # Count non-null compliance impacts
    compliance_data = {
        'HIPAA': df['HIPAA_Rules_Impacted'].notna().sum(),
        'GDPR': df['GDPR_Articles_Impacted'].notna().sum(),
        'FDA': df['FDA_Premarket_Topic'].notna().sum()
    }
    
    fig = px.bar(
        x=list(compliance_data.keys()),
        y=list(compliance_data.values()),
        title="Regulatory Compliance Impact",
        labels={'x': 'Regulation', 'y': 'Number of Affected Findings'},
        color_discrete_sequence=['#9b59b6']
    )
    
    fig.update_layout(title_x=0.5)
    return fig

def display_detailed_findings(df, selected_indices=None):
    """Display detailed findings in an expandable format."""
    if selected_indices is not None:
        display_df = df.iloc[selected_indices]
    else:
        display_df = df
    
    for idx, row in display_df.iterrows():
        with st.expander(f"🔍 {row['Rule_Name']} - {row['Severity']}", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Description:** {row['Full_Description']}")
                st.markdown(f"**CWE ID:** {row['CWE_ID']}")
                st.markdown(f"**CVE ID:** {row['CVE_ID']}")
                st.markdown(f"**CVSS Score:** {row['CVSS_Base_Score']}")
                st.markdown(f"**Component:** {row['Component_Package']}")
                st.markdown(f"**Match Source:** {row['Match_Source']}")
            
            with col2:
                st.markdown("**Regulatory Impact:**")
                if pd.notna(row['HIPAA_Rules_Impacted']):
                    st.markdown(f"- **HIPAA:** {row['HIPAA_Rules_Impacted']}")
                if pd.notna(row['GDPR_Articles_Impacted']):
                    st.markdown(f"- **GDPR:** {row['GDPR_Articles_Impacted']}")
                if pd.notna(row['FDA_Premarket_Topic']):
                    st.markdown(f"- **FDA:** {row['FDA_Premarket_Topic']}")
                if pd.notna(row['Medical_Tech_Impact']):
                    st.markdown(f"**Medical Tech Impact:** {row['Medical_Tech_Impact']}")

def main():
    """Main dashboard function."""
    # Header
    st.markdown('<h1 class="main-header">🔒 Security Compliance Dashboard</h1>', unsafe_allow_html=True)
    
    # Load data
    df = load_data()
    if df is None:
        st.error("Failed to load data. Please ensure security_compliance_report.xlsx is available.")
        return
    
    # Sidebar filters
    st.sidebar.markdown('<h2 class="section-header">🎛️ Filters</h2>', unsafe_allow_html=True)
    
    # Severity filter
    severity_options = ['All'] + sorted(df['Severity'].unique().tolist())
    selected_severity = st.sidebar.selectbox("Filter by Severity", severity_options)
    
    # Component filter
    component_options = ['All'] + sorted(df['Component_Package'].unique().tolist())
    selected_component = st.sidebar.selectbox("Filter by Component", component_options)
    
    # Match source filter
    match_source_options = ['All'] + sorted(df['Match_Source'].unique().tolist())
    selected_match_source = st.sidebar.selectbox("Filter by Match Source", match_source_options)
    
    # Apply filters
    filtered_df = df.copy()
    if selected_severity != 'All':
        filtered_df = filtered_df[filtered_df['Severity'] == selected_severity]
    if selected_component != 'All':
        filtered_df = filtered_df[filtered_df['Component_Package'] == selected_component]
    if selected_match_source != 'All':
        filtered_df = filtered_df[filtered_df['Match_Source'] == selected_match_source]
    
    # Key metrics
    st.markdown('<h2 class="section-header">📊 Key Metrics</h2>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Findings",
            value=len(filtered_df),
            delta=f"{len(filtered_df) - len(df)} from total" if len(filtered_df) != len(df) else None
        )
    
    with col2:
        critical_high = len(filtered_df[filtered_df['Severity'].isin(['CRITICAL', 'HIGH'])])
        st.metric(
            label="Critical/High Severity",
            value=critical_high,
            delta=f"{(critical_high/len(filtered_df)*100):.1f}%" if len(filtered_df) > 0 else "0%"
        )
    
    with col3:
        unique_components = filtered_df['Component_Package'].nunique()
        st.metric(
            label="Affected Components",
            value=unique_components
        )
    
    with col4:
        avg_cvss = filtered_df['CVSS_Score_Numeric'].mean()
        st.metric(
            label="Average CVSS Score",
            value=f"{avg_cvss:.1f}" if not pd.isna(avg_cvss) else "N/A"
        )
    
    # Visualizations
    st.markdown('<h2 class="section-header">📈 Visual Analytics</h2>', unsafe_allow_html=True)
    
    # Row 1: Severity and CVSS distribution
    col1, col2 = st.columns(2)
    
    with col1:
        severity_fig = create_severity_distribution_chart(filtered_df)
        st.plotly_chart(severity_fig, use_container_width=True)
    
    with col2:
        cvss_fig = create_cvss_score_distribution(filtered_df)
        st.plotly_chart(cvss_fig, use_container_width=True)
    
    # Row 2: Component analysis and compliance impact
    col1, col2 = st.columns(2)
    
    with col1:
        component_fig = create_component_analysis(filtered_df)
        st.plotly_chart(component_fig, use_container_width=True)
    
    with col2:
        compliance_fig = create_compliance_impact_chart(filtered_df)
        st.plotly_chart(compliance_fig, use_container_width=True)
    
    # Correlation analysis
    st.markdown('<h2 class="section-header">🔗 Correlation Analysis</h2>', unsafe_allow_html=True)
    correlation_fig = create_correlation_heatmap(filtered_df)
    st.plotly_chart(correlation_fig, use_container_width=True)
    
    # Interactive data table
    st.markdown('<h2 class="section-header">📋 Interactive Data Table</h2>', unsafe_allow_html=True)
    
    # Allow user to select specific findings for detailed view
    if len(filtered_df) > 0:
        st.dataframe(
            filtered_df[['Rule_Name', 'Severity', 'CWE_ID', 'CVE_ID', 'Component_Package', 'CVSS_Base_Score']],
            use_container_width=True,
            height=300
        )
        
        # Detailed findings section
        st.markdown('<h2 class="section-header">🔍 Detailed Findings</h2>', unsafe_allow_html=True)
        display_detailed_findings(filtered_df)
    else:
        st.warning("No findings match the selected filters.")
    
    # Footer
    st.markdown("---")
    st.markdown("*Security Compliance Dashboard - Powered by Streamlit*")

if __name__ == "__main__":
    main()