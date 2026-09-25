import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error


BASE_DIR = Path(__file__).resolve().parents[1]

SOURCE_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "french_bakery"
    / "daily_product_sales.csv"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "results"
    / "french_bakery"
    / "all_product_metrics.json"
)

FEATURES = [
    "weekday",
    "month",
    "lag_1",
    "lag_7",
    "lag_14",
    "average_7_days",
    "average_28_days",
]


def create_features(daily_sales):
    frame = daily_sales.copy()

    frame["weekday"] = frame.index.dayofweek
    frame["month"] = frame.index.month

    frame["lag_1"] = frame["quantity_sold"].shift(1)
    frame["lag_7"] = frame["quantity_sold"].shift(7)
    frame["lag_14"] = frame["quantity_sold"].shift(14)

    previous_sales = frame["quantity_sold"].shift(1)

    frame["average_7_days"] = (
        previous_sales.rolling(7, min_periods=7).mean()
    )

    frame["average_28_days"] = (
        previous_sales.rolling(28, min_periods=28).mean()
    )

    return frame.dropna()


def calculate_metrics(actual, predicted):
    return {
        "mae": round(
            float(mean_absolute_error(actual, predicted)),
            2,
        ),
        "rmse": round(
            float(
                np.sqrt(
                    mean_squared_error(actual, predicted)
                )
            ),
            2,
        ),
    }


def evaluate_product(product_sales):
    first_date = product_sales["date"].min()
    last_date = product_sales["date"].max()

    complete_dates = pd.date_range(
        first_date,
        last_date,
        freq="D",
    )

    daily_sales = (
        product_sales
        .groupby("date")["quantity_sold"]
        .sum()
        .reindex(complete_dates, fill_value=0)
        .to_frame()
    )

    daily_sales.index.name = "date"

    features = create_features(daily_sales)

    if len(features) < 180:
        return None

    test = features.iloc[-90:].copy()
    development = features.iloc[:-90].copy()

    model = RandomForestRegressor(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=2,
    )

    model.fit(
        development[FEATURES],
        development["quantity_sold"],
    )

    test["random_forest"] = model.predict(
        test[FEATURES]
    )

    test["weekly_baseline"] = test["lag_7"]

    random_forest_metrics = calculate_metrics(
        test["quantity_sold"],
        test["random_forest"],
    )

    baseline_metrics = calculate_metrics(
        test["quantity_sold"],
        test["weekly_baseline"],
    )

    average_actual_sales = float(
        test["quantity_sold"].mean()
    )

    if average_actual_sales > 0:
        relative_mae = round(
            (
                random_forest_metrics["mae"]
                / average_actual_sales
            )
            * 100,
            2,
        )
    else:
        relative_mae = None

    return {
        "training_days": int(len(development)),
        "test_days": int(len(test)),
        "test_period": (
            f"{test.index.min().date()} to "
            f"{test.index.max().date()}"
        ),
        "average_daily_sales": round(
            average_actual_sales,
            2,
        ),
        "weekly_baseline": baseline_metrics,
        "random_forest": random_forest_metrics,
        "relative_mae_percent": relative_mae,
        "random_forest_beats_baseline": (
            random_forest_metrics["mae"]
            < baseline_metrics["mae"]
        ),
    }


def main():
    if not SOURCE_FILE.exists():
        raise FileNotFoundError(
            f"Sales data was not found: {SOURCE_FILE}"
        )

    sales = pd.read_csv(
        SOURCE_FILE,
        parse_dates=["date"],
    )

    results = {}

    for product_name in sorted(sales["article"].unique()):
        product_sales = sales[
            sales["article"] == product_name
        ].copy()

        result = evaluate_product(product_sales)

        if result is None:
            continue

        results[product_name] = result

        print(f"\n{product_name}")
        print(
            "Random Forest MAE:",
            result["random_forest"]["mae"],
        )
        print(
            "Random Forest RMSE:",
            result["random_forest"]["rmse"],
        )
        print(
            "Beats weekly baseline:",
            result["random_forest_beats_baseline"],
        )

    report = {
        "dataset": "French bakery daily product sales",
        "evaluation": (
            "The final 90 days were kept separate for testing."
        ),
        "products_tested": len(results),
        "products": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print("\nEvaluation completed.")
    print(f"Products tested: {len(results)}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()