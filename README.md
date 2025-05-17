
# Phishing URL Detection AI: A Hybrid Approach for Real-Time Threat Identification

## 📌 Overview

This project aims to detect phishing URLs in real-time using a **hybrid machine learning model** that combines:

- **Handcrafted features** (e.g., URL length, domain entropy, WHOIS age)
- **Learned features** via a CNN encoder
- An **ensemble classifier** (XGBoost) for robust decision-making

The model is trained and evaluated on the **PhishTank** dataset and shows strong performance in both accuracy and false negative rate, making it suitable for real-world deployment.

---


### The Dataset

Use the **UC Irvine dataset**, available here:  
🔗 [https://archive.ics.uci.edu/dataset/327/phishing+websites](https://archive.ics.uci.edu/dataset/327/phishing+websites)


## 🗂️ Code Organization

```
phishing-url-detector/
│
├── data/
│   └── (Placeholder for loading external dataset)
│
├── features/
│   ├── extract_handcrafted_features.py     # URL feature extraction functions
│
├── model/
│   ├── cnn_encoder.py                      # CNN model for learned features
│   ├── xgboost_ensemble.py                 # Ensemble classifier logic
│   └── train.py                            # Training pipeline
│
├── utils/
│   ├── preprocess.py                       # URL cleaning and preprocessing
│   └── evaluation.py                       # Metrics and performance reporting
│
├── main.py                                 # Run end-to-end training and inference
├── requirements.txt                        # List of dependencies
└── README.md                               # This file
```

---


### Clone the Repository

```bash
git clone https://github.com/your-username/phishing-url-detector.git
cd phishing-url-detector
```
