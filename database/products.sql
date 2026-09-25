USE ai_sales_system;

CREATE TABLE IF NOT EXISTS products (
    product_id INT AUTO_INCREMENT PRIMARY KEY,
    business_id INT NOT NULL,

    product_name VARCHAR(100) NOT NULL,

    category ENUM(
        'Bread',
        'Pastry',
        'Beverage',
        'Meal',
        'Snack',
        'Dessert',
        'Other'
    ) NOT NULL DEFAULT 'Other',

    selling_unit VARCHAR(40) NOT NULL,
    selling_price DECIMAL(10, 2) NOT NULL,

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_product_business
        FOREIGN KEY (business_id)
        REFERENCES businesses(business_id)
        ON DELETE RESTRICT,

    CONSTRAINT unique_business_product
        UNIQUE (business_id, product_name),

    CONSTRAINT nonnegative_product_price
        CHECK (selling_price >= 0)
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_unit_setup (
    business_id INT PRIMARY KEY,

    CONSTRAINT fk_unit_setup_business
        FOREIGN KEY (business_id)
        REFERENCES businesses(business_id)
        ON DELETE CASCADE
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_units (
    unit_id INT AUTO_INCREMENT PRIMARY KEY,
    business_id INT NOT NULL,
    name VARCHAR(40) NOT NULL,

    CONSTRAINT unique_business_unit
        UNIQUE (business_id, name),

    CONSTRAINT fk_product_unit_business
        FOREIGN KEY (business_id)
        REFERENCES businesses(business_id)
        ON DELETE CASCADE
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;