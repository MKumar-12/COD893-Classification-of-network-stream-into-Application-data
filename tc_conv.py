# %%
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import ast

# %%
# Loading the Dataset
file_path = "merged_output.csv"     # Path to the dataset
data = pd.read_csv(file_path)

# %%
data.head()

# %% [markdown]
# ### Preprocessing: convert string array to float

# %%
data.info()

# %%
def get_float(str_array):
    # Remove brackets and split the string by commas
    cleaned_string = str_array.strip("[]")  # Remove [ and ]
    string_list = cleaned_string.split(",")    # Split by commas

    # Convert to a NumPy array of floats
    float_array = np.array(string_list, dtype=float)
    return float_array 

for field in ["sizes", "directions"]:
    print(field)
    data[field] = data[field].apply(lambda x:  get_float(x))
    

# %%
data.head()

# %% [markdown]
# ### Column description
# - index: Index of the row (IGNORE)
# - connection: A tuple describing the connection (source IP, source port, destination IP, destination port, protocol).
# - timestamps: A list of timestamps indicating when packets for the connection were captured.
# - sizes: A list of packet sizes (in bytes) for the connection.
# - directions: A list indicating packet directions (1 for source-to-destination, 0 for destination-to-source).
# - file_names: The name of the PCAP file from which the data was extracted.

# %%
label_col = "label"
data[label_col] = data["file_name"].apply(lambda x: x.replace(".pcap", ""))                # Extract label from the filename

# Dropping Classes with Less Than 5 Instances
class_counts = data[label_col].value_counts()                                               # generate series of class_count
print(class_counts)
data = data[data[label_col].isin(class_counts[class_counts > 5].index)]

le = LabelEncoder()
data["label_encoded"] = le.fit_transform(data["label"])

# %%
data.head(5)

# %%
data.tail(5)

# %%
# Hot encoding for labels
print(dict(zip(le.classes_, range(len(le.classes_)))))

# %%
data["label"].value_counts()

# %%
data = data.drop(columns=["file_name"])

# %%
print(data["sizes"].head(5))

# Check the data type of each entry in the 'sizes' column
print(data["sizes"].apply(type).value_counts())

direction_example = data.loc[1, "directions"]
print(direction_example)

print(len(direction_example))

# %%
def get_avg(x):
    return np.mean(x)

def get_std(x):
    return np.std(x)

def get_sum(x):
    return np.sum(x)

def get_duration(timestamps):
    ts_list = list(map(float, timestamps.split(',')))  # Convert string to list of floats
    return ts_list[-1] - ts_list[0] if len(ts_list) > 1 else 0

def get_total_packets(sizes):
    return len(sizes)

def get_IAT(timestamps):
    ts_list = list(map(float, timestamps.split(',')))  # Convert string to list of floats
    if len(ts_list) > 1:
        return np.diff(ts_list)
    return []           # No IAT for single packet


def get_mean_IAT(timestamps):
    iat = get_IAT(timestamps)
    return np.mean(iat)

def get_std_dev_IAT(timestamps):
    iat = get_IAT(timestamps)
    return np.std(iat)

# %%
# Packet-level: avg, std packet sizes
data["avg_pkt_size"] = data["sizes"].apply(get_avg)
data["stddev_pkt_size"] = data["sizes"].apply(get_std)
data["total_size"] = data["sizes"].apply(get_sum)



# Flow duration, total data, total pkts
data["flow_duration"] = data["timestamps"].apply(get_duration)
data["total_packets"] = data["sizes"].apply(get_total_packets)



# Intra-flow: mean and std of inter-arrival time or relative variance
data["mean_IAT"] = data["timestamps"].apply(get_mean_IAT)
data["stddev_IAT"] = data["timestamps"].apply(get_std_dev_IAT)

data.head(4)

# %%
feature_cols = ["avg_pkt_size", "stddev_pkt_size", "total_size", "flow_duration", "mean_IAT", "stddev_IAT"]  # Feature selection

# Drop values with no data
data_tmp = data.dropna()
features = data_tmp[feature_cols]
labels = data_tmp["label_encoded"]

# %%
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# %%
# Training Model (Random Forest)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# %%
# Model Evalutation
y_pred = clf.predict(X_test)

# Classification Report
print(classification_report(y_test, y_pred, target_names=le.classes_))

# %%
# Confusion Matrix plot
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

# %%
# Identifying Feature Importance
importances = clf.feature_importances_
feature_names = features.columns

plt.figure(figsize=(12, 8))
plt.barh(feature_names, importances, color='skyblue')
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.title("Feature Importance")
plt.show()