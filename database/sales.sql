USE ai_sales_system;

CREATE TABLE IF NOT EXISTS daily_sales (
    sale_id INT AUTO_INCREMENT PRIMARY KEY,

    product_id INT NOT NULL,
    sale_date DATE NOT NULL,

    quantity_sold INT NOT NULL,
    sales_amount DECIMAL(12, 2) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_daily_sale_product
        FOREIGN KEY (product_id)
        REFERENCES products(product_id)
        ON DELETE RESTRICT,

    CONSTRAINT unique_product_sale_date
        UNIQUE (product_id, sale_date),

    CONSTRAINT valid_sales_quantity
        CHECK (quantity_sold >= 0),

    CONSTRAINT valid_sales_amount
        CHECK (
            sales_amount >= 0
            AND (quantity_sold > 0 OR sales_amount = 0)
        )
);