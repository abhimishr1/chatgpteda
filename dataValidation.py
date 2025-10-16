import json
import pandas as pd
from great_expectations.validator.validator import Validator
from great_expectations.core.batch import Batch
from great_expectations.execution_engine.pandas_execution_engine import PandasExecutionEngine

# Load and flatten JSON
with open("data.json") as f:
    data = json.load(f)
df = pd.json_normalize(data, sep=".")

# Create a minimal in-memory Validator
engine = PandasExecutionEngine()
batch = Batch(data=df)
validator = Validator(execution_engine=engine, batches=[batch])

summary = []
for col in df.columns:
    res_not_null = validator.expect_column_values_to_not_be_null(col)
    res_unique = validator.expect_column_values_to_be_unique(col)
    summary.append({
        "column": col,
        "always_has_value": res_not_null.success,
        "is_unique": res_unique.success,
        "null_ratio": df[col].isna().mean(),
        "unique_ratio": df[col].nunique() / len(df)
    })

summary_df = pd.DataFrame(summary)
print(summary_df)
