import json
import pandas as pd
import streamlit as st

st.set_page_config(page_title="AttackLens Auto - SOAR Dashboard", layout="wide")
st.title("AttackLens Auto")
st.caption("Automated indicator enrichment, triage and simulated response (SOAR-style playbook)")

@st.cache_data
def load():
    with open("results/response_actions.json") as f:
        decisions = json.load(f)
    with open("results/enriched_findings.json") as f:
        findings = json.load(f)
    df = pd.DataFrame(decisions)
    fdf = pd.DataFrame(findings)
    return df, fdf

df, fdf = load()

SEVERITY_ORDER = ["critical", "high", "medium", "low", "clean"]
SEVERITY_COLOR = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "clean": "✅"}

# Sidebar filter
st.sidebar.header("Filters")
chosen = st.sidebar.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
view = df[df["severity"].isin(chosen)]

# Top metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric("Indicators processed", len(df))
c2.metric("Critical", int((df["severity"] == "critical").sum()))
c3.metric("Auto-approved actions", int(df["auto_approved"].sum()))
c4.metric("Needs analyst review", int((~df["auto_approved"]).sum()))

left, right = st.columns(2)
with left:
    st.subheader("Indicators by severity")
    counts = df["severity"].value_counts().reindex(SEVERITY_ORDER).dropna()
    st.bar_chart(counts)
with right:
    st.subheader("Risk score by indicator")
    chart_df = df.set_index("indicator")["risk_score"]
    st.bar_chart(chart_df)

st.subheader("Pipeline: indicator to response")
for _, row in view.iterrows():
    emoji = SEVERITY_COLOR.get(row["severity"], "⚪")
    with st.expander(f"{emoji} {row['type'].upper()}  {row['indicator']}  —  {row['severity'].upper()}  (score {row['risk_score']})"):
        st.write(f"**Action decided:** {row['action_decided']}")
        st.write(f"**Auto-approved:** {'Yes' if row['auto_approved'] else 'No, flagged for human review'}")
        st.write(f"**Status:** {row['status']}")
        st.write(f"**Decided at:** {row['decided_at']}")
        raw = fdf[fdf["value"] == row["indicator"]]
        if not raw.empty:
            st.write("**Raw enrichment data:**")
            st.json(raw.iloc[0].to_dict())

st.subheader("All decisions")
st.dataframe(view[["type", "indicator", "severity", "risk_score", "action_decided", "auto_approved"]],
             use_container_width=True)
