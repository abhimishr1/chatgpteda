from great_expectations.profile.user_configurable_profiler import UserConfigurableProfiler

profiler = UserConfigurableProfiler(profile_dataset=df)
suite = profiler.build_suite()
print(suite.to_json_dict())

import json
import pandas as pd
import great_expectations as gx

# === 1️⃣ Load & flatten your JSON ===
input_path = "data.json"  # or any CSV file

if input_path.endswith(".json"):
    with open(input_path) as f:
        data = json.load(f)
    df = pd.json_normalize(data, sep=".")
else:
    df = pd.read_csv(input_path)

print(f"\n✅ Loaded {len(df)} rows × {len(df.columns)} columns")

# === 2️⃣ Create an in-memory Great Expectations Context ===
context = gx.get_context(mode="ephemeral")

# === 3️⃣ Create a Batch and Validator from the DataFrame ===
validator = context.sources.add_or_update_pandas(name="my_pandas_source") \
    .read_dataframe(name="my_batch", dataframe=df)

# === 4️⃣ Add some general data quality expectations ===
for col in df.columns:
    validator.expect_column_values_to_not_be_null(col)
    validator.expect_column_values_to_be_unique(col)

validator.expect_table_columns_to_match_set(df.columns.tolist())

# Optional: check type consistency
for col in df.columns:
    dtype = str(df[col].dtype)
    validator.expect_column_values_to_be_of_type(col, dtype)

# === 5️⃣ Run validation and summarize ===
results = validator.validate()
print("\n📊 Validation Summary:\n")
for r in results["results"]:
    name = r["expectation_config"]["expectation_type"]
    col = r["expectation_config"]["kwargs"].get("column", "")
    print(f"- {name:<40} {col:<25} success: {r['success']}")

# === 6️⃣ Save full JSON results if needed ===
import json
with open("data_quality_report.json", "w") as f:
    json.dump(results.to_json_dict(), f, indent=2)

print("\n💾 Detailed report saved to 'data_quality_report.json'\n")
