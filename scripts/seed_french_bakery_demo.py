import csv
import os
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import pymysql


BASE_DIR = Path(__file__).resolve().parents[1]

PRODUCTS_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "french_bakery"
    / "french_bakery_products.csv"
)

SALES_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "french_bakery"
    / "daily_product_sales.csv"
)

DEMO_USERNAME = "french_bakery_demo"
DEMO_UNIT = "Piece"
EUR_TO_PHP = Decimal("60")
STARTING_STOCK = 1000

TOP_PRODUCTS = {
    "TRADITIONAL BAGUETTE",
    "CROISSANT",
    "PAIN AU CHOCOLAT",
    "COUPE",
    "BANETTE",
}


def php_price(eur_price):
    return (
        Decimal(str(eur_price))
        * EUR_TO_PHP
    ).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP
    )


def main():
    connection = pymysql.connect(
        host="127.0.0.1",
        user="root",
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database="ai_sales_system",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT b.business_id
                FROM businesses AS b
                INNER JOIN users AS u
                    ON u.user_id = b.user_id
                WHERE u.username = %s
                """,
                (DEMO_USERNAME,)
            )

            business = cursor.fetchone()

            if business is None:
                raise ValueError(
                    "Create the French Bakery Demo account first."
                )

            business_id = business["business_id"]

            cursor.execute(
                """
                SELECT COUNT(*) AS product_count
                FROM products
                WHERE business_id = %s
                """,
                (business_id,)
            )

            if cursor.fetchone()["product_count"] > 0:
                raise ValueError(
                    "This demo account already has products. "
                    "The seed was not run again."
                )

            product_prices = {}

            with PRODUCTS_FILE.open(
                newline="",
                encoding="utf-8"
            ) as file:
                for row in csv.DictReader(file):
                    product_name = row["article"].strip()

                    if product_name in TOP_PRODUCTS:
                        product_prices[product_name] = php_price(
                            row["typical_price_eur"]
                        )

            product_ids = {}

            for product_name, selling_price in product_prices.items():
                cursor.execute(
                    """
                    INSERT INTO products (
                        business_id,
                        product_name,
                        selling_unit,
                        selling_price
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        business_id,
                        product_name.title(),
                        DEMO_UNIT,
                        selling_price,
                    )
                )

                product_id = cursor.lastrowid
                product_ids[product_name] = product_id

                cursor.execute(
                    """
                    INSERT INTO stock_movements (
                        product_id,
                        movement_type,
                        quantity,
                        notes
                    )
                    VALUES (%s, 'Stock In', %s, %s)
                    """,
                    (
                        product_id,
                        STARTING_STOCK,
                        "Demo starting stock. "
                        "The public dataset has no inventory data.",
                    )
                )

            imported_sales = 0

            with SALES_FILE.open(
                newline="",
                encoding="utf-8"
            ) as file:
                for row in csv.DictReader(file):
                    product_name = row["article"].strip()

                    if product_name not in product_ids:
                        continue

                    quantity = int(
                        Decimal(row["quantity_sold"])
                    )

                    selling_price = product_prices[product_name]
                    sales_amount = (
                        Decimal(quantity)
                        * selling_price
                    ).quantize(Decimal("0.01"))

                    cursor.execute(
                        """
                        INSERT INTO daily_sales (
                            product_id,
                            sale_date,
                            quantity_sold,
                            sales_amount
                        )
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            product_ids[product_name],
                            row["date"],
                            quantity,
                            sales_amount,
                        )
                    )

                    imported_sales += 1

        connection.commit()

        print("\nFRENCH BAKERY DEMO DATA IMPORTED\n")
        print(f"Products: {len(product_ids)}")
        print(f"Daily sales records: {imported_sales}")
        print(
            "The demo data belongs only to "
            f"'{DEMO_USERNAME}'."
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    main()