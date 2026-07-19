# AI-Powered Cybersecurity Threat Detection System

The AI-Powered Cybersecurity Threat Detection System is designed to identify and mitigate cyber threats in real-time. By leveraging Machine Learning (ML) and Artificial Intelligence (AI), the system analyzes network traffic, detects anomalies, and predicts potential security threats before they escalate.

## Project Phases

1️⃣ Data Collection & Cleaning   
2️⃣ AI Model Training  
3️⃣ Model Deployment (API Integration)  
4️⃣ Real-Time Monitoring Dashboard  
5️⃣ Testing & Validation

## 📌 Phase 1 - Data Collection & Cleaning

Clone this repository

```
git clone https://github.com/harikishore2004/ThreatDetectionSystem.git
cd ThreatDetectionSystem
```

Create virtual environment

* For Linux/macOS

```
python3 -m venv cybersecenv
source cybersecenv/bin/activate
```

* For Windows

```
python3 -m venv cybersecenv
cybersecenv\Scripts\activate
```

Install the required python libraries

```
pip3 install -r requirements.txt
```

Connect environment to jupyter notebook

```
python3 -m ipykernel install --user --name cybersecenv
```

Download the Dataset
For this project, we are using the Network Intrusion dataset (CIC-IDS-2017). You can download it manually from [Kaggle](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset).
Unzip the downloaded file into the src/rawdata/ folder of the repository. The file structure will be:

```
.
├── CyberSecurityModel.pkl
├── ModelTraining.ipynb
├── README.md
├── requirements.txt
└── src
    ├── CleanedData.csv
    ├── CombinedDataCleaner.ipynb
    └── rawdata
        ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
        ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
        ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
        ├── Monday-WorkingHours.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
        ├── Tuesday-WorkingHours.pcap_ISCX.csv
        └── Wednesday-workingHours.pcap_ISCX.csv

```

Execute the python code

1. Change to the src Directory

```
cd src/
```

2. Start jupyter notebook

```
jupyter notebook
```

3. Open and Run the CombinedDataCleaner Notebook Open CombinedDataCleaner.ipynb and execute each cell sequentially.

Overview of the code

The program performs the following tasks:

* Feature Selection: Selecting the most relevant attributes from the dataset that are best suited for our specific use case.
* Data Cleaning: Removing rows containing NaN (Not a Number) values and duplicates to reduce errors.
* Normalizing Values: Scaling large values down to a smaller range to improve model performance during training.
* Saves the fitted scaler (`scaler.pkl`) and the final feature column list (`feature_cols.pkl`) alongside `CleanedData.csv` — both are required later for preprocessing new/live data consistently in Phase 3.

## 📌 Phase 2 - AI Model Training

In this phase, we train our Machine Learning model to classify network traffic and identify potential cyber threats. We use the `Random Forest Classifier` due to its robustness and effectiveness in handling complex datasets with high dimensionality.

Steps to Train the Model:

1. Start Jupyter Notebook

```
jupyter notebook  
```

2. Open and Run the Training Notebook Open `ModelTraining.ipynb` and execute each cell sequentially.

What are the steps included in this phase:

* Data Loading: The cleaned and preprocessed dataset is loaded.
* Train-Test Split: The data is divided into training and testing sets to train and evaluate model accuracy.
* Model Training: A Random Forest Classifier is trained to recognize patterns in malicious vs. benign traffic.
* Evaluation: Model performance is assessed using by calculating the accuracy of the model.
* Model Export: The trained model is saved as CyberSecurityModel.pkl for later use in the deployment phase.

## 📌 Phase 3 - Model Deployment (API Integration)

This phase turns the trained model into a live prediction service that can classify network traffic in real time, straight from a `.pcap` file or a live capture — without waiting for an entire file to be converted to CSV first.

### How it works

```
.pcap file / live capture
        │
        ▼
  cicflowmeter (extracts flow-level features per completed flow)
        │  streams each flow as JSON over HTTP
        ▼
  app/predict_server.py (FastAPI)
        │  aligns columns → applies saved scaler.pkl → model.predict()
        │  appends result to app/live_predictions_log.csv
        ▼
  app/tui.py (Textual dashboard, tails the log file live)
```

Flows are scored one at a time as `cicflowmeter` produces them, so predictions appear live instead of requiring the whole pcap to be converted to a CSV and loaded into memory first — important given pcap files here can be several GB.

### 1. Install app dependencies

All Phase 3/4 dependencies (FastAPI, Textual, cicflowmeter, etc.) are listed in `app/requirements.txt`:

```
cd app/
pip3 install -r requirements.txt --break-system-packages
```

### 2. File structure for this phase

```
.
├── CyberSecurityModel.pkl
├── src/
│   ├── scaler.pkl              # produced by CombinedDataCleaner.ipynb (Phase 1)
│   └── feature_cols.pkl        # produced by CombinedDataCleaner.ipynb (Phase 1)
└── app/
    ├── requirements.txt
    ├── predict_server.py       # FastAPI service — preprocesses + predicts each flow
    ├── tui.py                  # live dashboard
    └── live_predictions_log.csv  # generated at runtime, one row per predicted flow
```

`predict_server.py` expects `../CyberSecurityModel.pkl` (repo root) and `../src/scaler.pkl` / `../src/feature_cols.pkl` — run it from `app/`.

### 3. Run the pipeline

Three terminals, all from the `app/` directory:

**Terminal 1 — start the prediction server**

```
uvicorn predict_server:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — start the live dashboard**

```
python tui.py
```

**Terminal 3 — start the flow stream**

```
cicflowmeter -f path/to/capture.pcap -u http://127.0.0.1:8000/predict
```

`predict_server.py` logs each prediction to the console and to `live_predictions_log.csv`, and exposes a running tally at `http://127.0.0.1:8000/summary`.

### Known caveats

* This project uses [hieulw/cicflowmeter](https://github.com/hieulw/cicflowmeter) to convert raw packets into the same flow-level statistical features used in training.
* `cicflowmeter`'s JSON field names may not exactly match the original CIC-IDS-2017 CSV column names (e.g. `src_ip` vs `Source IP`). `predict_server.py` tries several common variants automatically — check its console output on the first received flow if `source_ip`/`destination_ip`/`flow_id` show up blank in the dashboard.
* Evaluating on a pcap that was part of the original CIC-IDS-2017 capture set is not a true held-out test, since flows re-derived from it may overlap with training data. Use a separate pcap source for genuine validation.
* This uses CPU-only inference (`RandomForestClassifier` from scikit-learn) — no GPU is used or required.

## 📌 Phase 4 - Real-Time Monitoring Dashboard

`tui.py` is a [Textual](https://textual.textualize.io/)-based terminal dashboard for watching predictions as they happen.

* **Splash screen** — shown until the stream starts: project name in ASCII art, a short description, and a "waiting for stream" indicator. Automatically transitions once `live_predictions_log.csv` receives its first row.
* **Live flow log** (left panel) — scrolling table of time, flow ID, source IP, destination IP, predicted label (color-coded by threat type), and confidence. Capped at the 200 most recent rows on-screen; full history remains in `live_predictions_log.csv`.
* **Threat distribution chart** (right panel) — live-updating bar chart of predicted label counts and percentages.
* **Summary bar** (bottom) — running total and top-3 predicted labels, plus a toast notification every 100 flows processed.

Run with `python tui.py` from `app/`, after `predict_server.py` is running and a stream has been started via `cicflowmeter -u`.

## 📌 Phase 5 - Testing & Validation

*Not yet started.*

## Repository Structure (current)

```
.
├── CyberSecurityModel.pkl
├── ModelTraining.ipynb
├── README.md
├── requirements.txt
├── app
│   ├── requirements.txt
│   ├── predict_server.py
│   ├── tui.py
│   └── live_predictions_log.csv
└── src
    ├── CleanedData.csv
    ├── CombinedDataCleaner.ipynb
    ├── scaler.pkl
    ├── feature_cols.pkl
    └── rawdata
        ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
        ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
        ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
        ├── Monday-WorkingHours.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
        ├── Tuesday-WorkingHours.pcap_ISCX.csv
        └── Wednesday-workingHours.pcap_ISCX.csv
```