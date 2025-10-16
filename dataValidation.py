import json
import pandas as pd
from great_expectations.dataset import PandasDataset

# === 1️⃣ Load and flatten the JSON ===
input_path = "data.json"  # change to your file path

with open(input_path, "r") as f:
    data = json.load(f)

# Flatten deeply nested JSON (lists/dicts become dotted paths)
df = pd.json_normalize(data, sep=".")

print(f"\n✅ Loaded {len(df)} records with {len(df.columns)} fields\n")

# === 2️⃣ Wrap it with Great Expectations ===
class MyDataset(PandasDataset):
    pass

my_df = MyDataset(df)

# === 3️⃣ Analyze columns ===
summary = []

for col in df.columns:
    # Expect column values to not be null
    null_result = my_df.expect_column_values_to_not_be_null(col)
    # Expect column values to be unique
    unique_result = my_df.expect_column_values_to_be_unique(col)

    null_ratio = df[col].isna().mean()
    unique_ratio = df[col].nunique() / len(df)

    summary.append({
        "column": col,
        "always_has_value": null_result["success"],
        "is_unique": unique_result["success"],
        "null_ratio": round(null_ratio, 3),
        "unique_ratio": round(unique_ratio, 3)
    })

# === 4️⃣ Display as DataFrame ===
summary_df = pd.DataFrame(summary)
summary_df = summary_df.sort_values(by=["null_ratio", "unique_ratio"], ascending=[True, False])

print("\n📊 Column Summary:\n")
print(summary_df.to_string(index=False))

# === 5️⃣ Optionally save results ===
summary_df.to_csv("json_field_analysis.csv", index=False)
print("\n💾 Saved detailed results to 'json_field_analysis.csv'\n")
