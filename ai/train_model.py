import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# -------------------------------
# 1. Load dataset
# -------------------------------
df = pd.read_csv("ai/features.csv")

# -------------------------------
# 2. Feature Engineering
# -------------------------------
df['url_length'] = df['input'].apply(len)
df['num_dots'] = df['input'].apply(lambda x: x.count('.'))
df['has_at'] = df['input'].apply(lambda x: int('@' in x))
df['has_dash'] = df['input'].apply(lambda x: int('-' in x))
df['num_query'] = df['input'].apply(lambda x: x.count('?'))
df['is_https'] = df['input'].apply(lambda x: int(x.startswith('https')))
df['num_digits'] = df['input'].apply(lambda x: sum(c.isdigit() for c in x))

# Map labels to numeric
label_mapping = {"benign": 0, "phishing": 1, "malware": 2}
df['label_num'] = df['label'].map(label_mapping)

# ✅ Drop rows with invalid labels (NaN)
df = df.dropna(subset=['label_num'])
df['label_num'] = df['label_num'].astype(int)  # convert to int

# Features & labels
feature_cols = ['url_length', 'num_dots', 'has_at', 'has_dash', 'num_query', 'is_https', 'num_digits']
X = df[feature_cols]
y = df['label_num']

# -------------------------------
# 3. Train/Test Split
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# -------------------------------
# 4. Train RandomForest
# -------------------------------
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# -------------------------------
# 5. Evaluate
# -------------------------------
y_pred = model.predict(X_test)

print("✅ Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=label_mapping.keys()))

print("✅ Confusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))

# -------------------------------
# 6. Save trained model
# -------------------------------
joblib.dump(model, "ai/url_classifier.pkl")
print("\n🎯 Model saved as 'ai/url_classifier.pkl'")

# -------------------------------
# 7. Optional: Save feature-engineered CSV
# -------------------------------
df.to_csv("ai/features_ml.csv", index=False)
print("🎯 Feature-engineered dataset saved as 'ai/features_ml.csv'")
