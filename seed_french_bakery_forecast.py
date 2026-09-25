import hashlib
import math
import os
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_UP

import pymysql


DATABASE_NAME = "ai_sales_system"
DEMO_USERNAME = "french_bakery_demo"
HISTORY_DAYS = 365


def deterministic_noise(product_id, sales_date):
    value = (
        f"{product_id}:{sales_date.isoformat()}"
    ).encode("utf-8")

    digest = hashlib.sha256(value).digest()

    return (digest[0] % 5) - 2


def calculate_quantity(product_id, product_index, sales_date, day_index):
    base_demand = 14 + (product_index * 4)

    weekday_adjustment = {
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 6,
        5: 10,
        6: 8,
    }[sales_date.weekday()]

    monthly_pattern = 3 * math.sin(
        (2 * math.pi * sales_date.timetuple().tm_yday) / 365
    )

    gradual_growth = day_index * 0.012

    noise = deterministic_noise(
        product_id,
        sales_date,
    )

    quantity = round(
        base_demand
        + weekday_adjustment
        + monthly_pattern
        + gradual_growth
        + noise
    )

    return max(1, quantity)


def main():
    database = pymysql.connect(
        host="127.0.0.1",
        user="root",
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=DATABASE_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )

    try:
        with database.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    businesses.business_id,
                    businesses.business_name
                FROM businesses
                INNER JOIN users
                    ON users.user_id = businesses.user_id
                WHERE users.username = %s
                """,
                (DEMO_USERNAME,),
            )

            business = cursor.fetchone()

            if business is None:
                raise RuntimeError(
                    'The "french_bakery_demo" account was not found.'
                )

            cursor.execute(
                """
                SELECT
                    product_id,
                    product_name,
                    selling_price
                FROM products
                WHERE business_id = %s
                ORDER BY product_id
                """,
                (business["business_id"],),
            )

            products = cursor.fetchall()

            if not products:
                raise RuntimeError(
                    "French Bakery does not have any products."
                )

            history_end = date.today() - timedelta(days=1)
            history_start = (
                history_end
                - timedelta(days=HISTORY_DAYS - 1)
            )

            for product_index, product in enumerate(products):
                current_date = history_start
                day_index = 0

                while current_date <= history_end:
                    quantity = calculate_quantity(
                        product["product_id"],
                        product_index,
                        current_date,
                        day_index,
                    )

                    sales_amount = (
                        Decimal(str(product["selling_price"]))
                        * Decimal(quantity)
                    ).quantize(
                        Decimal("0.01"),
                        rounding=ROUND_HALF_UP,
                    )

                    cursor.execute(
                        """
                        INSERT INTO daily_sales (
                            product_id,
                            sale_date,
                            quantity_sold,
                            sales_amount
                        )
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            quantity_sold = VALUES(quantity_sold),
                            sales_amount = VALUES(sales_amount)
                        """,
                        (
                            product["product_id"],
                            current_date,
                            quantity,
                            sales_amount,
                        ),
                    )

                    current_date += timedelta(days=1)
                    day_index += 1

            # Ensure every seeded sale has its corresponding
            # stock movement.
            cursor.execute(
                """
                INSERT INTO stock_movements (
                    product_id,
                    sale_id,
                    movement_type,
                    quantity,
                    notes
                )
                SELECT
                    daily_sales.product_id,
                    daily_sales.sale_id,
                    'Sold',
                    daily_sales.quantity_sold,
                    'Automatically recorded from demo sales.'
                FROM daily_sales
                INNER JOIN products
                    ON products.product_id = daily_sales.product_id
                WHERE products.business_id = %s
                  AND daily_sales.sale_date BETWEEN %s AND %s
                  AND daily_sales.quantity_sold > 0
                ON DUPLICATE KEY UPDATE
                    product_id = VALUES(product_id),
                    movement_type = 'Sold',
                    quantity = VALUES(quantity),
                    notes = VALUES(notes)
                """,
                (
                    business["business_id"],
                    history_start,
                    history_end,
                ),
            )

            # Create enough stock so the demonstration account does
            # not show a negative stock balance.
            for product in products:
                cursor.execute(
                    """
                    SELECT COALESCE(
                        SUM(quantity_sold),
                        0
                    ) AS total_quantity
                    FROM daily_sales
                    WHERE product_id = %s
                    """,
                    (product["product_id"],),
                )

                total_quantity = int(
                    cursor.fetchone()["total_quantity"]
                )

                required_stock = total_quantity + 200

                cursor.execute(
                    """
                    SELECT movement_id
                    FROM stock_movements
                    WHERE product_id = %s
                      AND sale_id IS NULL
                      AND notes = %s
                    LIMIT 1
                    """,
                    (
                        product["product_id"],
                        "French Bakery demo opening stock.",
                    ),
                )

                opening_movement = cursor.fetchone()

                if opening_movement:
                    cursor.execute(
                        """
                        UPDATE stock_movements
                        SET
                            movement_type = 'Stock In',
                            quantity = %s
                        WHERE movement_id = %s
                        """,
                        (
                            required_stock,
                            opening_movement["movement_id"],
                        ),
                    )

                else:
                    cursor.execute(
                        """
                        INSERT INTO stock_movements (
                            product_id,
                            sale_id,
                            movement_type,
                            quantity,
                            notes
                        )
                        VALUES (
                            %s,
                            NULL,
                            'Stock In',
                            %s,
                            %s
                        )
                        """,
                        (
                            product["product_id"],
                            required_stock,
                            "French Bakery demo opening stock.",
                        ),
                    )

        database.commit()

        print(
            f"Added {HISTORY_DAYS} days of demonstration "
            f"history for {len(products)} French Bakery products."
        )

    except Exception:
        database.rollback()
        raise

    finally:
        database.close()


if __name__ == "__main__":
    main()