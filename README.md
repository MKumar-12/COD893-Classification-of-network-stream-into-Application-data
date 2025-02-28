# Network Traffic Analysis and Classification Using Transformers

This repository contains the codebase for a project focused on classifying network traffic and identifying applications using different ML classical supervised model. 
The project was developed as part of the COD893 course at IIT Delhi under the supervision of Prof. Vireshwar Kumar and Prof. Tarun Mangla.

## Project Overview
In this project, we propose a Transformer-based approach to classify network traffic and identify applications from encrypted network streams. 
The Transformer model is currently trained and evaluated on the ISCX-VPN-NonVPN dataset & Institute level dataset. 

We're currently working on the process to set ground truth labels for network stream captured within our organization (adv.). 
Also, we'll re-evaluated our model for real-time network stream.

## Key Features

- **Packet-level Metrics**: Average and standard deviation of packet sizes.
- **Flow Statistics**: Flow duration, total data transferred, and total packets.
- **Intra-flow Characteristics**: Mean and standard deviation of inter-arrival time or relative variance.

```python
feature_selection = ["avg_pkt_size", "stddev_pkt_size", "total_size", "flow_duration", "mean_IAT", "stddev_IAT"]
```

## Model Architectures
### Random Forest Classifier
- **Best Parameters**: max_depth=None, max_features='sqrt', min_samples_leaf=1, min_samples_split=2, n_estimators=500
- **Accuracy**: 76%

### XGBoost Classifier
- **Hyperparameters**: n_estimators=500, max_depth=30, learning_rate=0.05, scale_pos_weight=1.5
- **Accuracy**: 75%

### Stratified K-Fold Cross-Validation
- **Mean Accuracy**: 72%

## Results
| Class | Precision | Recall | F1-Score |
|----------------------|------------|--------|----------|
| google_browsing | 0.85 | 0.90 | 0.88 |
| google_drive_upl-dw | 0.46 | 0.48 | 0.47 |
| google_mail | 0.54 | 0.40 | 0.46 |
| streaming_amazon-prime | 0.77 | 0.67 | 0.71 |
| teams_call | 0.59 | 0.41 | 0.48 |
| teams_messaging | 0.36 | 0.29 | 0.32 |
| **Overall Accuracy** | **76%** |

## Dataset
Initially, the model was trained and tested on the ISCX-VPN-NonVPN dataset, which contains a variety of network streams, including both VPN and non-VPN traffic.
Later, we used the dataset procurred from our Institute, labelled the data in some major classes(10, currently).

## References
The project builds upon prior work in the field of network traffic analysis, including deep learning approaches like CNNs, LSTMs, and hybrid models. For more details, please refer to the references listed in the project presentation.

## Contributors
- **Sajal Verma** ([2023MCS2490@iitd.ac.in](mailto:2023MCS2490@iitd.ac.in))
- **Manish Kumar** ([2023MCS2497@iitd.ac.in](mailto:2023MCS2497@iitd.ac.in))
