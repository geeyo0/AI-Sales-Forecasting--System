USE ai_sales_system;

ALTER TABLE users
    DROP INDEX one_admin_only,
    DROP COLUMN admin_slot;

ALTER TABLE users
    MODIFY role ENUM('Admin', 'Business', 'Cashier') NOT NULL,
    ADD COLUMN admin_slot TINYINT
        GENERATED ALWAYS AS (
            CASE
                WHEN role = 'Admin' THEN 1
                ELSE NULL
            END
        ) STORED,
    ADD UNIQUE KEY one_admin_only (admin_slot);

CREATE TABLE IF NOT EXISTS business_cashiers (
    business_cashier_id INT AUTO_INCREMENT PRIMARY KEY,
    business_id INT NOT NULL,
    user_id INT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_business_cashier_business
        FOREIGN KEY (business_id)
        REFERENCES businesses(business_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_business_cashier_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE RESTRICT,

    INDEX idx_business_cashiers_business (business_id, is_active)
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;
