CREATE DATABASE IF NOT EXISTS ai_sales_system
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE ai_sales_system;

CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    role ENUM('Admin', 'Business') NOT NULL,

    admin_slot TINYINT
        GENERATED ALWAYS AS (
            CASE
                WHEN role = 'Admin' THEN 1
                ELSE NULL
            END
        ) STORED,

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY one_admin_only (admin_slot)
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS businesses (
    business_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,

    business_name VARCHAR(100) NOT NULL,

    business_type ENUM(
        'Bakery',
        'Carinderia',
        'Food Stall'
    ) NOT NULL,

    location_latitude DECIMAL(9, 6) NULL,
    location_longitude DECIMAL(9, 6) NULL,
    location_name VARCHAR(150) NULL,
    location_accuracy_m INT UNSIGNED NULL,
    location_updated_at DATETIME NULL,

    created_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_business_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE RESTRICT
) ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci;