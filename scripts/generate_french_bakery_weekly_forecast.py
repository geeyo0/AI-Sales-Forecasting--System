import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor


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
    / "seven_day_forecast.json"
)

FORECAST_DAYS = 7
PRODUCT_COUNT = 5

FEATURES = [
    "weekday",
    "month",
    "lag_1",
    "lag_7",
    "lag_14",
    "average_7_days",
    "average_28_days",
]


def create_feature_frame(daily_sales):
    frame = daily_sales.to_frame("quantity_sold").copy()

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


def build_daily_series(sales, product_name, history_end):
    product_sales = sales[
        sales["article"] == product_name
    ].copy()

    product_sales = (
        product_sales
        .groupby("date", as_index=False)["quantity_sold"]
        .sum()
        .sort_values("date")
    )

    first_date = product_sales["date"].min()

    all_dates = pd.date_range(
        first_date,
        history_end,
        freq="D",
    )

    return (
        product_sales
        .set_index("date")["quantity_sold"]
        .reindex(all_dates, fill_value=0.0)
        .astype(float)
    )


def predict_next_days(daily_sales, forecast_dates):
    feature_frame = create_feature_frame(daily_sales)

    model = RandomForestRegressor(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=2,
    )

    model.fit(
        feature_frame[FEATURES],
        feature_frame["quantity_sold"],
    )

    history = daily_sales.astype(float).tolist()
    predictions = []

    for forecast_date in forecast_dates:
        values = {
            "weekday": forecast_date.dayofweek,
            "month": forecast_date.month,
            "lag_1": history[-1],
            "lag_7": history[-7],
            "lag_14": history[-14],
            "average_7_days": sum(history[-7:]) / 7,
            "average_28_days": sum(history[-28:]) / 28,
        }

        features = pd.DataFrame(
            [values],
            columns=FEATURES,
        )

        prediction = max(
            0,
            float(model.predict(features)[0]),
        )

        history.append(prediction)

        predictions.append({
            "date": str(forecast_date.date()),
            "quantity": round(prediction, 2),
        })

    return predictions


def demand_level(historical_total, predicted_total):
    if historical_total <= 0:
        return "Normal"

    change = predicted_total / historical_total

    if change >= 1.10:
        return "High"

    if change <= 0.90:
        return "Low"

    return "Normal"


def main():
    if not SOURCE_FILE.exists():
        print("Prepared bakery data was not found.")
        print(f"Expected: {SOURCE_FILE}")
        return

    sales = pd.read_csv(
        SOURCE_FILE,
        parse_dates=["date"],
    )

    sales["article"] = (
        sales["article"]
        .astype(str)
        .str.strip()
    )

    sales["quantity_sold"] = pd.to_numeric(
        sales["quantity_sold"],
        errors="coerce",
    )

    sales = sales[
        sales["date"].notna()
        & sales["quantity_sold"].notna()
        & sales["quantity_sold"].ge(0)
        & sales["article"].str.len().gt(1)
    ].copy()

    history_end = sales["date"].max()

    ranked_products = (
        sales
        .groupby("article", as_index=False)["quantity_sold"]
        .sum()
        .sort_values("quantity_sold", ascending=False)
        .head(PRODUCT_COUNT)
    )

    product_names = ranked_products["article"].tolist()

    if len(product_names) < PRODUCT_COUNT:
        print("Not enough products were found.")
        return

    forecast_dates = pd.date_range(
        history_end + pd.Timedelta(days=1),
        periods=FORECAST_DAYS,
        freq="D",
    )

    history_dates = pd.date_range(
        history_end - pd.Timedelta(days=6),
        history_end,
        freq="D",
    )

    product_forecasts = []
    daily_series_by_product = {}
    predictions_by_product = {}

    for product_name in product_names:
        daily_series = build_daily_series(
            sales,
            product_name,
            history_end,
        )

        predictions = predict_next_days(
            daily_series,
            forecast_dates,
        )

        historical_total = float(
            daily_series.loc[history_dates].sum()
        )

        predicted_total = sum(
            item["quantity"]
            for item in predictions
        )

        daily_series_by_product[product_name] = daily_series
        predictions_by_product[product_name] = predictions

        product_forecasts.append({
            "product": product_name.title(),
            "source_product": product_name,
            "unit": "pieces",
            "historical_7_day_total": round(
                historical_total,
                2,
            ),
            "predicted_demand": round(
                predicted_total,
                2,
            ),
            "demand_level": demand_level(
                historical_total,
                predicted_total,
            ),
            "daily_forecast": predictions,
        })

    actual_chart = []

    for history_date in history_dates:
        total_quantity = sum(
            float(
                daily_series_by_product[
                    product_name
                ].loc[history_date]
            )
            for product_name in product_names
        )

        actual_chart.append({
            "date": str(history_date.date()),
            "quantity": round(total_quantity, 2),
        })

    forecast_chart = []

    for day_index, forecast_date in enumerate(
        forecast_dates
    ):
        total_quantity = sum(
            predictions_by_product[product_name][
                day_index
            ]["quantity"]
            for product_name in product_names
        )

        forecast_chart.append({
            "date": str(forecast_date.date()),
            "quantity": round(total_quantity, 2),
        })

    forecast_quantities = [
        item["quantity"]
        for item in forecast_chart
    ]

    highest_index = forecast_quantities.index(
        max(forecast_quantities)
    )

    lowest_index = forecast_quantities.index(
        min(forecast_quantities)
    )

    primary_product = product_forecasts[0]

    result = {
        "dataset": "French bakery daily sales from Kaggle",
        "unit": "pieces",
        "history_end": str(history_end.date()),
        "forecast_start": str(forecast_dates[0].date()),
        "forecast_end": str(forecast_dates[-1].date()),
        "products": product_forecasts,
        "chart": {
            "actual_sales": actual_chart,
            "forecasted_sales": forecast_chart,
        },
        "summary": {
            "total_predicted_sales": round(
                sum(forecast_quantities),
                2,
            ),
            "average_daily_sales": round(
                sum(forecast_quantities) / FORECAST_DAYS,
                2,
            ),
            "highest_predicted_sales": round(
                max(forecast_quantities),
                2,
            ),
            "highest_sales_date": forecast_chart[
                highest_index
            ]["date"],
            "lowest_predicted_sales": round(
                min(forecast_quantities),
                2,
            ),
            "lowest_sales_date": forecast_chart[
                lowest_index
            ]["date"],
        },
        "primary_forecast": {
            "product": primary_product["product"],
            "quantity": primary_product[
                "daily_forecast"
            ][0]["quantity"],
            "forecast_date": forecast_dates[0].date().isoformat(),
            "history_end": history_end.date().isoformat(),
            "unit": "pieces",
        },
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print("\nSEVEN-DAY FRENCH BAKERY FORECAST CREATED\n")
    print(
        f"Products forecasted: {len(product_forecasts)}"
    )
    print(
        f"Forecast period: "
        f"{forecast_dates[0].strftime('%B %d, %Y')} to "
        f"{forecast_dates[-1].strftime('%B %d, %Y')}"
    )
    print(
        f"Total predicted demand: "
        f"{sum(forecast_quantities):,.0f} pieces"
    )
    print(f"\nCreated: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()