import pandas as pd

# Load dataset
df = pd.read_csv("ai/features.csv")

# Show first few rows
print("🔎 Preview of dataset:")
print(df.head())

# Count per label
print("\n📊 Label distribution:")
print(df["label"].value_counts())
