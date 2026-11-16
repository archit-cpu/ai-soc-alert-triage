# Learning notes: explain the project in an interview

## What is a SOC?
A Security Operations Center monitors alerts, investigates suspicious behavior, and helps respond to security incidents.

## What are our two detection methods?
1. **Rules**: count recent failed logins by source IP and flag suspicious sequences.
2. **Machine learning**: IsolationForest looks for records with unusual combinations of hour, status, and recent failed-login count. It does not know which events are attacks.

## What is MITRE ATT&CK?
A knowledge base of adversary tactics and techniques. The repeated login failures in our *synthetic example* resemble **T1110: Brute Force**, but a detection alone cannot confirm a technique was used.

## Why use Streamlit?
It provides an interactive dashboard directly from Python, without building a separate front end.

## What are the limitations?
- We have no separately labeled hold-out dataset, so don't claim an accuracy, precision, recall, F1, or false-positive rate.
- IsolationForest is trained on the same logs currently analyzed; abnormal events can contaminate the unsupervised baseline.
- Thresholds and nighttime rules are educational heuristics, not production defaults.
- Many alerts can correspond to one incident; future improvement would merge related alerts.
- An IP can be shared by many users, so this isn't definitive attribution.

## Next improvements
1. Add a labeled validation dataset.
2. Compare a rules-only baseline with rules + ML.
3. Cluster repeated alerts into incidents.
4. Add analyst feedback and persist investigations.
