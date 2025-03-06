# %%
import pandas as pd
import numpy as np

# %%
# Load dataset
file_path = "merged_output.csv"
data = pd.read_csv(file_path)

# %%
data.columns
# %%
print(type(data["timestamps"]), data["timestamps"][:5])

# %%
print(type(data["timestamps"][0]), data["timestamps"][:5])

# %%
data["ts_split"] = data["timestamps"].apply(lambda x: list(map(float, x.split(','))))
data["flow_duration"] = data["ts_split"].apply(lambda x: max(x) - min(x) if isinstance(x, list) and len(x) > 1 else 0)
print(data["flow_duration"][:5])

# %%
print(data["flow_duration"].value_counts())

# %%
data.info()

# %%
data.describe().T

# %%
def get_float(str_array):
    # Remove brackets and split the string by commas
    cleaned_string = str_array.strip("[]")  # Remove [ and ]
    string_list = cleaned_string.split(",")    # Split by commas

    # Convert to a NumPy array of floats
    float_array = np.array(string_list, dtype=float)
    return float_array 

for field in ["timestamps", "sizes", "directions"]:
    print(field)
    data[field] = data[field].apply(lambda x:  get_float(x))

# %%
def get_IAT(timestamps):
    """Compute Inter-Arrival Time (IAT) for a list of timestamps."""
    if len(timestamps) > 1:
        return np.diff(timestamps)  # Compute differences between consecutive timestamps
    return np.array([])  # Return empty array if there's only one packet

# %%
def compute_flow_features(df):
    flow_features = []
    
    for index, row in df.iterrows():
        ts_list = row['timestamps']
        size_list = row['sizes']
        dir_list = row['directions']

        # Compute Flow Duration
        flow_duration = ts_list[-1] - ts_list[0] if len(ts_list) > 1 else 0

        # Separate Fwd and Bwd packets
        fwd_sizes = [size for size, direction in zip(size_list, dir_list) if direction == 1]
        bwd_sizes = [size for size, direction in zip(size_list, dir_list) if direction == 0]

        fwd_timestamps = [ts for ts, direction in zip(ts_list, dir_list) if direction == 1]
        bwd_timestamps = [ts for ts, direction in zip(ts_list, dir_list) if direction == 0]

        # Compute IATs
        flow_iat = get_IAT(ts_list)
        fwd_iat = get_IAT(fwd_timestamps)
        bwd_iat = get_IAT(bwd_timestamps)

        # Compute Flow Features
        flow_data = {
            'Flow Duration': flow_duration,
            'Avg. Packet Size': np.mean(size_list) if size_list else 0,
            'Std Packet Size': np.std(size_list) if len(size_list) > 1 else 0,
            'Max Packet Size': max(size_list) if size_list else 0,
            'Min Packet Size': min(size_list) if size_list else 0,
            'Total Bytes': sum(size_list),
            'Total Packets': len(size_list),
            'Total Fwd Packets': len(fwd_sizes),
            'Total Backward Packets': len(bwd_sizes),
            'Total Length of Fwd Packets': sum(fwd_sizes) if fwd_sizes else 0,
            'Total Length of Bwd Packets': sum(bwd_sizes) if bwd_sizes else 0,
            'Fwd Packet Length Max': max(fwd_sizes) if fwd_sizes else 0,
            'Fwd Packet Length Min': min(fwd_sizes) if fwd_sizes else 0,
            'Fwd Packet Length Mean': np.mean(fwd_sizes) if fwd_sizes else 0,
            'Fwd Packet Length Std': np.std(fwd_sizes) if len(fwd_sizes) > 1 else 0,
            'Bwd Packet Length Max': max(bwd_sizes) if bwd_sizes else 0,
            'Bwd Packet Length Min': min(bwd_sizes) if bwd_sizes else 0,
            'Bwd Packet Length Mean': np.mean(bwd_sizes) if bwd_sizes else 0,
            'Bwd Packet Length Std': np.std(bwd_sizes) if len(bwd_sizes) > 1 else 0,
            'Flow Bytes/s': (sum(fwd_sizes) + sum(bwd_sizes)) / flow_duration if flow_duration > 0 else 0,
            'Flow Packets/s': (len(fwd_sizes) + len(bwd_sizes)) / flow_duration if flow_duration > 0 else 0,
            'Flow IAT Mean': np.mean(flow_iat) if len(flow_iat) > 0 else 0,
            'Flow IAT Std': np.std(flow_iat) if len(flow_iat) > 1 else 0,
            'Flow IAT Max': np.max(flow_iat) if len(flow_iat) > 0 else 0,
            'Flow IAT Min': np.min(flow_iat) if len(flow_iat) > 0 else 0,
            'Fwd IAT Total': np.sum(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Mean': np.mean(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Std': np.std(fwd_iat) if len(fwd_iat) > 1 else 0,
            'Fwd IAT Max': np.max(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Min': np.min(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Bwd IAT Total': np.sum(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Mean': np.mean(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Std': np.std(bwd_iat) if len(bwd_iat) > 1 else 0,
            'Bwd IAT Max': np.max(bwd_iat) if len(bwd_iat) > 0 else 0,
            'Bwd IAT Min': np.min(bwd_iat) if len(bwd_iat) > 0 else 0,
        }

        flow_features.append(flow_data)

    return pd.DataFrame(flow_features)

# %%
# Apply function
df_features = compute_flow_features(data)
data = pd.concat([data, df_features], axis=1)  # Merge with original dataset
# %%
data.head(5)
# %%
data.describe().T
# %%
from sklearn.preprocessing import StandardScaler, LabelEncoder

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
data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.dropna(inplace=True)
# %%
print(data.describe().T)
# %%
print(data.info())
# %%
print(data.isnull().sum())

# %%
