# CYBERWORLD-X
### AI-Based Network Attack Forecasting from Network Traffic Data
**Problem Statement ID:** 26153  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software  

---

## 1. Executive Summary & Problem Explanation
Conventional Intrusion Detection Systems (IDS) and Security Information and Event Management (SIEM) tools operate predominantly as reactive, static binary classifiers:
$$\text{Network Packet / Flow} \longrightarrow \{\text{Benign}, \text{Malicious}\}$$

This paradigm has a critical flaw: by the time an alert triggers, an adversary may have already achieved initial foothold, escalated privileges, pivoted internally across subnets, and initiated exfiltration.

**CYBERWORLD-X** transforms this reactive approach into a predictive temporal forecasting system:
$$S(t-W+1), \dots, S(t-1), S(t) \xrightarrow{\quad\text{Temporal World Model}\quad} S(t+1), S(t+2), \dots, S(t+K)$$
where each network state $S(t)$ captures the macro-behavioral, structural, and volumetric characteristics of the enterprise network. 

By modeling network behavioral dynamics over time, the system **forecasts future network states**, calculates **escalation risk curves**, and predicts the **likely next attack stage** (Reconnaissance $\to$ Initial Access $\to$ Lateral Movement $\to$ Command & Control $\to$ Exfiltration) before the breach progresses.

---

## 2. Key Capabilities
- **Local-First Architecture**: 100% offline; zero dependencies on OpenAI, Hugging Face, Gemini, or any paid cloud AI API.
- **Privacy-Preserving**: Strips packet payload content; focuses exclusively on flow metadata, TCP flags, packet sizes, and inter-arrival timing dynamics.
- **Flexible Data Ingestion**: Supports CSV network flow logs (with dynamic column auto-mapping) and raw PCAP/PCAPNG packet captures via Scapy.
- **Configurable Temporal Discretization**: Configurable state windows ($5\text{s}, 10\text{s}, 30\text{s}, 60\text{s}$) and forecast horizons ($K = 1, 3, 5, 8, 10$).
- **Deep Temporal World Models**: PyTorch LSTM and Transformer neural world models predicting continuous state vectors, multi-step risk trajectories, and stage transition logits.
- **Baseline Comparative Evaluation**: Logistic Regression baseline providing genuine empirical Precision, Recall, F1, and False Positive Rate metrics without fabricated figures.
- **Explainable AI (SHAP)**: Empirical feature importance quantifying which telemetry metrics drive the current forecast.
- **Framework Alignment**: Direct mapping to MITRE ATT&CK enterprise tactics & techniques, CAPEC attack patterns, and CVE references.
- **Liquid Glass Cyber UI**: Futuristic dark command center aesthetic built with custom glassmorphism CSS, glowing borders, responsive layouts, and interactive Plotly visualizers.

---

## 3. Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend & UI** | Streamlit, HTML5, Vanilla CSS3 (Liquid Glass Design System), Plotly |
| **Machine Learning / AI** | PyTorch (`torch.nn.LSTM`, `nn.TransformerEncoder`), Scikit-learn, SHAP |
| **Network Data Processing** | Scapy, Pandas, NumPy |
| **Threat Intelligence** | MITRE ATT&CK, CAPEC, CVE/NVD References |
| **Deployment** | Streamlit Community Cloud ready, Python 3.10+ |

---

## 4. Project Structure

```
cyberworld-x/
│
├── app.py                         # Main Streamlit web application & router
├── requirements.txt               # Strict production dependencies
├── README.md                      # Comprehensive project documentation
├── .gitignore                     # Git ignore rules
│
├── .streamlit/
│   └── config.toml                # Streamlit dark futuristic theme configuration
│
├── data/
│   ├── sample_network_traffic.csv # Synthetic multi-stage demo network telemetry
│   └── README.md                  # Dataset documentation
│
├── models/
│   ├── lstm_model.py              # PyTorch LSTM World Model & training wrapper
│   ├── transformer_model.py       # PyTorch Transformer temporal world model
│   ├── baseline_model.py          # Logistic Regression baseline classifier
│   └── model_loader.py            # Model factory and lifecycle manager
│
├── preprocessing/
│   ├── feature_extraction.py      # PCAP ingestion & CSV column auto-mapping
│   ├── data_cleaning.py           # Missing value imputation & timestamp parsing
│   ├── normalization.py           # Robust feature scaling & inverse transform
│   └── time_windowing.py          # State S(t) aggregation & rolling sequences
│
├── forecasting/
│   ├── world_model.py             # S(t) -> S(t+K) state rollout orchestrator
│   ├── risk_forecasting.py        # Time-series risk calculation & Plotly chart
│   └── attack_stage_prediction.py # Attack progression & confidence scoring
│
├── explainability/
│   └── shap_explainer.py          # SHAP & sensitivity attribution engine
│
├── security/
│   ├── mitre_mapping.py           # MITRE ATT&CK matrix mappings
│   ├── capec_mapping.py           # CAPEC attack pattern mappings
│   └── cve_mapping.py             # CVE vulnerability references
│
├── utils/
│   ├── helpers.py                 # Liquid Glass UI components & CSS injector
│   ├── constants.py               # Constants, stages, and color tokens
│   └── sample_data.py             # Controlled multi-stage synthetic generator
│
└── assets/
    └── logo.svg                   # CYBERWORLD-X brand vector logo
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Git

### 1. Clone or Open Workspace
```bash
cd CYBERWORLD-X
```

### 2. Create Virtual Environment
On Windows (PowerShell / Command Prompt):
```powershell
python -m venv .venv
.venv\Scripts\activate
```

On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 6. Running Locally

Launch the application:
```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 7. Demo Mode Walkthrough

When you start the application without uploading a custom file:
1. **Instant Out-Of-The-Box Execution**: Demo Mode activates automatically with synthetic network telemetry simulating an enterprise subnet under multi-stage attack.
2. **Prominent Labelling**: All synthetic values are explicitly labelled with `DEMO DATA` badges to prevent misrepresentation of simulated traffic as real-world incidents.
3. **Temporal Progression Simulated**:
   - `Phase 1`: Routine Baseline Operations (HTTP/HTTPS/DNS)
   - `Phase 2`: Reconnaissance (SYN Sweeps across common ports)
   - `Phase 3`: Initial Access (Exploit attempts against DMZ Web Server)
   - `Phase 4`: Lateral Movement (Internal SMB/RDP pivoting)
   - `Phase 5`: Command and Control (Periodic beaconing to external IP)
   - `Phase 6`: Exfiltration (High-volume outbound data transfers)

---

## 8. Uploading Custom Datasets

1. Navigate to **Dataset / Upload** in the sidebar.
2. Select a `.csv`, `.pcap`, or `.pcapng` file.
3. **CSV Ingestion**: The system automatically detects and maps column aliases (e.g., `sport` $\to$ `src_port`, `dur` $\to$ `duration`, `sbytes` $\to$ `bytes`).
4. **PCAP Ingestion**: Scapy extracts IP headers, ports, protocols, packet sizes, and timestamps without logging sensitive payload content.
5. Click **Apply & Analyze** to immediately re-run the temporal world model on your telemetry.

---

## 9. Baseline Model Training & Benchmark

1. Navigate to **Model Performance**.
2. Click **Train / Fine-Tune Baseline on Current Dataset**.
3. The system trains a static Logistic Regression model on the current feature matrix and computes genuine empirical metrics (Precision, Recall, F1 Score, and False Positive Rate).
4. If training has not been initiated, the application displays `"Not evaluated yet"` rather than fabricating performance metrics.

---

## 10. Deployment to Streamlit Community Cloud

1. Push this repository to GitHub:
   ```bash
   git init
   git add .
   git commit -m "feat: CYBERWORLD-X initial release"
   git branch -M main
   git remote add origin https://github.com/<your-username>/cyberworld-x.git
   git push -u origin main
   ```
2. Log into [share.streamlit.io](https://share.streamlit.io).
3. Select your repository and set `Main file path` to `app.py`.
4. Deploy! The application uses standard pip packages and requires zero external API secrets or cloud keys.

---

## 11. Limitations & Future Scope

### Current Limitations:
- **PCAP Parsing Throughput**: High packet capture volumes (>500MB) take several minutes when parsed in pure Python via Scapy; batch flow logging (NetFlow/IPFIX/Zeek) is recommended for production volumes.
- **Class Imbalance**: In real-world enterprise traffic, malicious stages constitute $<0.01\%$ of all records, requiring careful synthetic minority oversampling or cost-sensitive loss.

### Future Scope:
- **FastAPI Sidecar API**: Decouple the PyTorch World Model into a headless microservice for ingestion from distributed Zeek/Suricata sensors.
- **Graph Neural Network (GNN) World Models**: Incorporate Spatio-Temporal Graph Convolutional Networks (ST-GCN) to model internal network topology alongside time dynamics.

---

## 12. Security & Compliance Statement
**CYBERWORLD-X** is designed as a local-first cybersecurity research prototype. It does not transmit enterprise telemetry to external AI services or cloud vendors. All feature normalization, neural inference, and explainability attributions occur entirely within local process memory.
