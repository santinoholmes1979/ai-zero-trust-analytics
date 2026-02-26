\## Zero Trust UEBA Analytics — Architecture



```mermaid

flowchart LR



%% =====================

%% Data Sources

%% =====================

A\[Auth Logs Simulator]

B\[VPN Logs Simulator]

C\[EDR Telemetry Simulator]



A --> D

B --> D

C --> D



%% =====================

%% Data Processing

%% =====================

D\[Raw JSONL Events<br/>data/raw] --> E\[Feature Engineering Pipeline<br/>build\_dataset.py]



E --> F\[Behavioral Baselines<br/>Per-user z-scores]

E --> G\[Security Feature Extraction<br/>Impossible Travel / MFA / Posture]



F --> H

G --> H



%% =====================

%% Detection Layer

%% =====================

H\[Model Training<br/>Isolation Forest] --> I\[Scoring Pipeline<br/>score\_events.py]



%% =====================

%% Storage

%% =====================

I --> J\[Processed Dataset<br/>data/processed]

I --> K\[Trained Model<br/>models/isoforest.joblib]



%% =====================

%% Analyst Experience

%% =====================

J --> L\[Streamlit SOC Dashboard]



L --> M\[Top Risk Surfacing]

L --> N\[Per-User Trend View]

L --> O\[Spike Drill-Down]

L --> P\[Recommended Actions]

L --> Q\[Disposition Workflow]



Q --> R\[Case Log<br/>case\_log.csv]



R --> S\[Case Review Dashboard]

