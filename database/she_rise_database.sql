-- ============================================================
-- SHE RISE / WOMEN EMPOWERMENT PLATFORM
-- COMPLETE DATABASE - FRESH INSTALLATION
-- ============================================================
--
-- This is the single database file for the complete project:
--   Authentication / Users
--   Seller Portal
--   Buyer Portal
--   Mentor / Mentorship
--   Admin Portal
--   Buyer AI support / AI usage logging
--   Orders, payments, returns, reviews and custom requests
--
-- Database: women_empowerment
--
-- Run this file on a newly created/empty women_empowerment
-- database. It does NOT drop the database, so rerunning it is
-- safe with respect to existing rows where unique keys are used.
-- ============================================================

-- ============================================================
-- 0. DATABASE + USERS
-- ============================================================

CREATE DATABASE IF NOT EXISTS women_empowerment
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE women_empowerment;

-- Main authentication table used by the Flask application.
-- The application reads/writes: id, full_name, email, mobile,
-- password and role. Passwords are stored as Werkzeug hashes.
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    mobile VARCHAR(10) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'buyer', 'seller', 'mentor') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_role (role),
    INDEX idx_users_mobile (mobile)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_attempts (
    email VARCHAR(255) NOT NULL PRIMARY KEY,
    failed_attempts INT NOT NULL DEFAULT 0,
    first_failed_at DATETIME NULL,
    last_failed_at DATETIME NULL,
    locked_until DATETIME NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_login_attempts_locked (locked_until)
) ENGINE=InnoDB;

-- Create an administrator with the interactive `flask --app app create-admin` command after importing this schema.




-- ============================================================
-- REGISTRATION OTP VERIFICATION
-- ============================================================
-- OTP is used ONLY during registration. Login remains password-only.
-- Store only a password hash of the OTP, never the raw OTP.
-- ============================================================

CREATE TABLE IF NOT EXISTS otp_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    purpose VARCHAR(30) NOT NULL DEFAULT 'register',
    otp_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NULL,
    mobile VARCHAR(20) NULL,
    password_hash VARCHAR(255) NULL,
    role VARCHAR(30) NULL,
    verification_method VARCHAR(10) NOT NULL DEFAULT 'email',
    expires_at DATETIME NOT NULL,
    last_sent_at DATETIME NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_otp_email_purpose (email, purpose),
    INDEX idx_otp_expires (expires_at)
) ENGINE=InnoDB;


-- ============================================================
-- SELLER FEATURES
-- ============================================================

-- =========================================================
-- CATEGORIES TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- PRODUCTS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,

    seller_id INT NOT NULL,
    category_id INT NOT NULL,

    name VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,

    price DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,

    image_url VARCHAR(500),

    status ENUM('active', 'inactive') DEFAULT 'active',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (category_id)
        REFERENCES categories(id)
);


-- =========================================================
-- INSERT DEFAULT CATEGORIES
-- =========================================================

INSERT INTO categories (name, description)
VALUES
('Fashion', 'Clothing, dresses, accessories and fashion products'),
('Jewellery', 'Handmade and fashion jewellery'),
('Food', 'Homemade food and food products'),
('Handmade', 'Handcrafted and handmade products'),
('Beauty', 'Beauty, skincare and personal care products'),
('Home Decor', 'Decorative and handmade home products')
ON DUPLICATE KEY UPDATE
    description = VALUES(description);


-- =========================================================
-- END OF SELLER FEATURE SECTION
-- =========================================================

-- ============================================================
-- BUYER FEATURES
-- ============================================================

CREATE TABLE IF NOT EXISTS buyer_addresses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    address_line TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_buyer_address_user
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS wishlist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    product_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_wishlist_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_wishlist_product
        FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT unique_buyer_product
        UNIQUE (buyer_id, product_id)
);

CREATE TABLE IF NOT EXISTS cart (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_cart_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT unique_buyer_cart
        UNIQUE (buyer_id)
);

CREATE TABLE IF NOT EXISTS cart_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cart_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,

    CONSTRAINT fk_cart_item_cart
        FOREIGN KEY (cart_id)
        REFERENCES cart(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_cart_item_product
        FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT unique_cart_product
        UNIQUE (cart_id, product_id),

    CONSTRAINT check_cart_quantity
        CHECK (quantity > 0)
);

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    shipping_address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_order_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    seller_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    fulfillment_status VARCHAR(30) NOT NULL DEFAULT 'pending',

    CONSTRAINT fk_order_item_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_order_item_product
        FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,

    CONSTRAINT fk_order_item_seller
        FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,

    CONSTRAINT check_order_quantity
        CHECK (quantity > 0)
);


CREATE TABLE IF NOT EXISTS payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    payment_method VARCHAR(30) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_status VARCHAR(30) NOT NULL DEFAULT 'pending',
    transaction_id VARCHAR(150),
    gateway_order_id VARCHAR(255) NULL,
    paid_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_payment_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,

    CONSTRAINT unique_payment_order
        UNIQUE (order_id)
);


CREATE TABLE IF NOT EXISTS custom_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    seller_id INT NULL,
    product_name VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    budget DECIMAL(10,2),
    quotation_amount DECIMAL(10,2),
    seller_response TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_custom_request_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_custom_request_seller
        FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
);


CREATE TABLE IF NOT EXISTS reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    product_id INT NOT NULL,
    order_id INT NOT NULL,
    rating INT NOT NULL,
    review_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_review_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_review_product
        FOREIGN KEY (product_id)
        REFERENCES products(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_review_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT check_review_rating
        CHECK (rating BETWEEN 1 AND 5),

    CONSTRAINT unique_buyer_product_order
        UNIQUE (buyer_id, product_id, order_id)
);


-- ============================================================
-- BUYER FEATURE ADDITIONS
-- Existing base buyer tables above are preserved.
-- ============================================================

-- ============================================================
-- 2. ORDER STATUS / TRACKING HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS order_status_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    status VARCHAR(50) NOT NULL,
    note VARCHAR(500) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_order_status_history_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE CASCADE,

    INDEX idx_order_status_history_order
        (order_id),

    INDEX idx_order_status_history_created
        (created_at)
);

-- ============================================================
-- 3. BUYER RETURN REQUESTS
-- ============================================================

CREATE TABLE IF NOT EXISTS return_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    buyer_id INT NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'requested',
    seller_response TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_return_requests_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_return_requests_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_return_requests_order
        (order_id),

    INDEX idx_return_requests_buyer
        (buyer_id),

    INDEX idx_return_requests_status
        (status)
);

-- ============================================================
-- 4. BUYER AI SUPPORT CONVERSATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS ai_support_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_id INT NOT NULL,
    sender_type VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ai_support_buyer
        FOREIGN KEY (buyer_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_ai_support_buyer
        (buyer_id),

    INDEX idx_ai_support_created
        (created_at)
);

-- ============================================================
-- 5. ADD OPTIONAL PAYMENT GATEWAY COLUMNS
-- ============================================================
--
-- The existing checkout already uses:
--     order_id
--     payment_method
--     amount
--     payment_status
--
-- Legacy gateway metadata columns are retained for compatibility
-- with databases created by older versions; COD checkout does not use them.
--
-- The procedure checks information_schema first so the script
-- can safely be run more than once.
-- ============================================================

DROP PROCEDURE IF EXISTS add_buyer_payment_columns;

DELIMITER $$

CREATE PROCEDURE add_buyer_payment_columns()
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'payments'
          AND COLUMN_NAME = 'transaction_id'
    ) THEN
        ALTER TABLE payments
            ADD COLUMN transaction_id VARCHAR(255) NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'payments'
          AND COLUMN_NAME = 'gateway_order_id'
    ) THEN
        ALTER TABLE payments
            ADD COLUMN gateway_order_id VARCHAR(255) NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'payments'
          AND COLUMN_NAME = 'paid_at'
    ) THEN
        ALTER TABLE payments
            ADD COLUMN paid_at DATETIME NULL;
    END IF;

END$$

DELIMITER ;

CALL add_buyer_payment_columns();

DROP PROCEDURE IF EXISTS add_buyer_payment_columns;

-- ============================================================
-- 6. ADD OPTIONAL QUOTATION / RESPONSE FIELDS TO
--    custom_requests
-- ============================================================
--
-- The existing seller custom-request page already works with:
--     seller_id
--     quotation_amount
--     seller_response
--     status
--
-- The following checks only add missing fields. Existing values
-- and seller-side records are preserved.
-- ============================================================

DROP PROCEDURE IF EXISTS add_buyer_custom_request_columns;

DELIMITER $$

CREATE PROCEDURE add_buyer_custom_request_columns()
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'custom_requests'
          AND COLUMN_NAME = 'seller_id'
    ) THEN
        ALTER TABLE custom_requests
            ADD COLUMN seller_id INT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'custom_requests'
          AND COLUMN_NAME = 'quotation_amount'
    ) THEN
        ALTER TABLE custom_requests
            ADD COLUMN quotation_amount DECIMAL(10,2) NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'custom_requests'
          AND COLUMN_NAME = 'seller_response'
    ) THEN
        ALTER TABLE custom_requests
            ADD COLUMN seller_response TEXT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'custom_requests'
          AND COLUMN_NAME = 'status'
    ) THEN
        ALTER TABLE custom_requests
            ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'pending';
    END IF;

END$$

DELIMITER ;

CALL add_buyer_custom_request_columns();

DROP PROCEDURE IF EXISTS add_buyer_custom_request_columns;

-- ============================================================
-- 7. BASIC INDEXES FOR EXISTING BUYER QUERIES
-- ============================================================
--
-- These are optional performance improvements. Each index is
-- created only if it does not already exist.
-- ============================================================

DROP PROCEDURE IF EXISTS add_buyer_indexes;

DELIMITER $$

CREATE PROCEDURE add_buyer_indexes()
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'payments'
          AND INDEX_NAME = 'idx_payments_order_id'
    ) THEN
        CREATE INDEX idx_payments_order_id
            ON payments(order_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'orders'
          AND INDEX_NAME = 'idx_orders_buyer_id'
    ) THEN
        CREATE INDEX idx_orders_buyer_id
            ON orders(buyer_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'order_items'
          AND INDEX_NAME = 'idx_order_items_order_id'
    ) THEN
        CREATE INDEX idx_order_items_order_id
            ON order_items(order_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'custom_requests'
          AND INDEX_NAME = 'idx_custom_requests_buyer_id'
    ) THEN
        CREATE INDEX idx_custom_requests_buyer_id
            ON custom_requests(buyer_id);
    END IF;

END$$

DELIMITER ;

CALL add_buyer_indexes();

DROP PROCEDURE IF EXISTS add_buyer_indexes;

-- ============================================================
-- 8. INITIAL ORDER TRACKING RECORDS
-- ============================================================
--
-- Existing orders receive one tracking entry using their current
-- status. New orders can receive additional entries from the
-- application code.
-- ============================================================

INSERT INTO order_status_history
(
    order_id,
    status,
    note
)
SELECT
    o.id,
    o.status,
    'Initial order status'
FROM orders AS o
LEFT JOIN order_status_history AS h
    ON h.order_id = o.id
WHERE h.id IS NULL;

-- ============================================================
-- END OF BUYER FEATURE DATABASE SCRIPT
-- ============================================================

-- ============================================================
-- MENTOR FEATURES
-- ============================================================

-- ============================================================
-- SHE RISE / WOMEN EMPOWERMENT PLATFORM
-- MENTOR FEATURE DATABASE
-- ============================================================
--
-- Covers:
-- FR-54  Mentor profile
-- FR-55  Admin approve/reject mentor
-- FR-56  Browse mentors by expertise
-- FR-57  Mentorship requests
-- FR-58  Mentor accept/reject requests
-- FR-59  Mentorship session records
-- FR-60  Post-session feedback
--
-- This script adds only Mentor-related tables.
-- It does NOT modify or recreate existing users, seller,
-- buyer, product, order, or admin tables.
-- ============================================================

-- ============================================================
-- 1. MENTOR PROFILES
-- ============================================================

CREATE TABLE IF NOT EXISTS mentor_profiles (

    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    expertise VARCHAR(255) NULL,

    bio TEXT NULL,

    experience_years INT NULL DEFAULT 0,

    availability VARCHAR(255) NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'pending',

    review_note TEXT NULL,

    reviewed_by INT NULL,

    reviewed_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_mentor_profiles_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentor_profiles_reviewer
        FOREIGN KEY (reviewed_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    UNIQUE KEY uq_mentor_profiles_user (user_id),

    INDEX idx_mentor_profiles_expertise (expertise),

    INDEX idx_mentor_profiles_status (status),

    INDEX idx_mentor_profiles_created (created_at)
);

-- ============================================================
-- 2. MENTORSHIP REQUESTS
-- ============================================================

CREATE TABLE IF NOT EXISTS mentorship_requests (

    id INT AUTO_INCREMENT PRIMARY KEY,

    mentor_id INT NOT NULL,

    entrepreneur_id INT NOT NULL,

    subject VARCHAR(255) NOT NULL,

    message TEXT NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'pending',

    mentor_response TEXT NULL,

    scheduled_at DATETIME NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_mentorship_requests_mentor
        FOREIGN KEY (mentor_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentorship_requests_entrepreneur
        FOREIGN KEY (entrepreneur_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_mentorship_requests_mentor (mentor_id),

    INDEX idx_mentorship_requests_entrepreneur (entrepreneur_id),

    INDEX idx_mentorship_requests_status (status),

    INDEX idx_mentorship_requests_scheduled (scheduled_at),

    INDEX idx_mentorship_requests_created (created_at)
);

-- ============================================================
-- 3. MENTORSHIP SESSIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS mentorship_sessions (

    id INT AUTO_INCREMENT PRIMARY KEY,

    request_id INT NOT NULL,

    mentor_id INT NOT NULL,

    entrepreneur_id INT NOT NULL,

    scheduled_at DATETIME NULL,

    duration_minutes INT NULL DEFAULT 60,

    notes TEXT NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'scheduled',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_mentorship_sessions_request
        FOREIGN KEY (request_id)
        REFERENCES mentorship_requests(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentorship_sessions_mentor
        FOREIGN KEY (mentor_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentorship_sessions_entrepreneur
        FOREIGN KEY (entrepreneur_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_mentorship_sessions_request (request_id),

    INDEX idx_mentorship_sessions_mentor (mentor_id),

    INDEX idx_mentorship_sessions_entrepreneur (entrepreneur_id),

    INDEX idx_mentorship_sessions_status (status),

    INDEX idx_mentorship_sessions_scheduled (scheduled_at)
);

-- ============================================================
-- 4. MENTORSHIP FEEDBACK
-- ============================================================

CREATE TABLE IF NOT EXISTS mentorship_feedback (

    id INT AUTO_INCREMENT PRIMARY KEY,

    session_id INT NOT NULL,

    mentor_id INT NOT NULL,

    entrepreneur_id INT NOT NULL,

    rating TINYINT NOT NULL,

    feedback_text TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mentorship_feedback_session
        FOREIGN KEY (session_id)
        REFERENCES mentorship_sessions(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentorship_feedback_mentor
        FOREIGN KEY (mentor_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_mentorship_feedback_entrepreneur
        FOREIGN KEY (entrepreneur_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    UNIQUE KEY uq_mentorship_feedback_session (session_id),

    INDEX idx_mentorship_feedback_mentor (mentor_id),

    INDEX idx_mentorship_feedback_entrepreneur (entrepreneur_id),

    INDEX idx_mentorship_feedback_rating (rating),

    INDEX idx_mentorship_feedback_created (created_at)
);

-- ============================================================
-- 5. INITIAL MENTOR PROFILE RECORDS
-- ============================================================
--
-- Existing users whose role is "mentor" receive a pending
-- mentor profile if one does not already exist.
--
-- Existing users are NOT changed.
-- ============================================================

INSERT INTO mentor_profiles
(
    user_id,
    status
)
SELECT
    u.id,
    'pending'
FROM users AS u
LEFT JOIN mentor_profiles AS mp
    ON mp.user_id = u.id
WHERE u.role = 'mentor'
  AND mp.id IS NULL;

-- ============================================================
-- 6. END OF MENTOR FEATURE DATABASE SCRIPT
-- ============================================================

-- ============================================================
-- ADMIN FEATURES
-- ============================================================

-- ============================================================
-- SHE RISE / WOMEN EMPOWERMENT PLATFORM
-- ADMIN DATABASE
-- ============================================================

-- ============================================================
-- 1. SELLER APPROVALS
-- ============================================================

CREATE TABLE IF NOT EXISTS seller_approvals (

    id INT AUTO_INCREMENT PRIMARY KEY,

    seller_id INT NOT NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'pending',

    account_status VARCHAR(30) NOT NULL DEFAULT 'active',

    reviewed_by INT NULL,

    review_note TEXT NULL,

    reviewed_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_seller_approvals_seller
        FOREIGN KEY (seller_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_seller_approvals_reviewer
        FOREIGN KEY (reviewed_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    UNIQUE KEY uq_seller_approval_seller (seller_id),

    INDEX idx_seller_approvals_status (status),

    INDEX idx_seller_approvals_seller (seller_id),

    INDEX idx_seller_approvals_created (created_at)
);

-- ============================================================
-- 2. COMPLAINTS
-- ============================================================

CREATE TABLE IF NOT EXISTS complaints (

    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    order_id INT NULL,

    title VARCHAR(255) NOT NULL,

    description TEXT NOT NULL,

    complaint_type VARCHAR(100) NOT NULL DEFAULT 'general',

    priority VARCHAR(30) NOT NULL DEFAULT 'medium',

    status VARCHAR(30) NOT NULL DEFAULT 'open',

    admin_response TEXT NULL,

    assigned_admin INT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    resolved_at TIMESTAMP NULL,

    CONSTRAINT fk_complaints_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_complaints_order
        FOREIGN KEY (order_id)
        REFERENCES orders(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_complaints_admin
        FOREIGN KEY (assigned_admin)
        REFERENCES users(id)
        ON DELETE SET NULL,

    INDEX idx_complaints_user (user_id),

    INDEX idx_complaints_order (order_id),

    INDEX idx_complaints_status (status),

    INDEX idx_complaints_priority (priority),

    INDEX idx_complaints_type (complaint_type),

    INDEX idx_complaints_created (created_at)
);

-- ============================================================
-- 3. AI USAGE LOGS
-- ============================================================

CREATE TABLE IF NOT EXISTS ai_usage_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NULL,

    user_role VARCHAR(30) NULL,

    feature VARCHAR(100) NOT NULL,

    request_text TEXT NULL,

    response_status VARCHAR(30) NOT NULL DEFAULT 'success',

    response_time_ms INT NULL,

    response_text TEXT NULL,

    error_message TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ai_usage_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,

    INDEX idx_ai_usage_user (user_id),

    INDEX idx_ai_usage_role (user_role),

    INDEX idx_ai_usage_feature (feature),

    INDEX idx_ai_usage_status (response_status),

    INDEX idx_ai_usage_created (created_at)
);

-- ============================================================
-- 4. ADMIN ACTIVITY LOG
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_activity_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,

    admin_id INT NOT NULL,

    action VARCHAR(100) NOT NULL,

    target_type VARCHAR(50) NULL,

    target_id INT NULL,

    description TEXT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_admin_activity_admin
        FOREIGN KEY (admin_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_admin_activity_admin (admin_id),

    INDEX idx_admin_activity_action (action),

    INDEX idx_admin_activity_target (
        target_type,
        target_id
    ),

    INDEX idx_admin_activity_created (created_at)
);

-- ============================================================
-- 5. BASIC PERFORMANCE INDEXES
-- ============================================================

DROP PROCEDURE IF EXISTS add_admin_indexes;

DELIMITER $$

CREATE PROCEDURE add_admin_indexes()

BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'products'
          AND INDEX_NAME = 'idx_products_seller_id'
    ) THEN

        CREATE INDEX idx_products_seller_id
            ON products(seller_id);

    END IF;


    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'products'
          AND INDEX_NAME = 'idx_products_category_id'
    ) THEN

        CREATE INDEX idx_products_category_id
            ON products(category_id);

    END IF;


    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'products'
          AND INDEX_NAME = 'idx_products_created_at'
    ) THEN

        CREATE INDEX idx_products_created_at
            ON products(created_at);

    END IF;


    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'orders'
          AND INDEX_NAME = 'idx_orders_created_at'
    ) THEN

        CREATE INDEX idx_orders_created_at
            ON orders(created_at);

    END IF;


    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'orders'
          AND INDEX_NAME = 'idx_orders_status'
    ) THEN

        CREATE INDEX idx_orders_status
            ON orders(status);

    END IF;

END$$

DELIMITER ;

CALL add_admin_indexes();

DROP PROCEDURE IF EXISTS add_admin_indexes;

-- ============================================================
-- 6. INITIAL SELLER APPROVAL RECORDS
-- ============================================================

INSERT INTO seller_approvals
(
    seller_id,
    status
)

SELECT
    u.id,
    'pending'

FROM users AS u

LEFT JOIN seller_approvals AS sa
    ON sa.seller_id = u.id

WHERE u.role = 'seller'

AND sa.id IS NULL;

-- ============================================================
-- 7. END OF ADMIN DATABASE SCRIPT
-- ============================================================

DROP PROCEDURE IF EXISTS add_workflow_columns;

DELIMITER $$

CREATE PROCEDURE add_workflow_columns()
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'order_items'
          AND COLUMN_NAME = 'fulfillment_status'
    ) THEN
        ALTER TABLE order_items
            ADD COLUMN fulfillment_status VARCHAR(30) NOT NULL DEFAULT 'pending';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'seller_approvals'
          AND COLUMN_NAME = 'account_status'
    ) THEN
        ALTER TABLE seller_approvals
            ADD COLUMN account_status VARCHAR(30) NOT NULL DEFAULT 'active';
    END IF;
END$$

DELIMITER ;

CALL add_workflow_columns();
DROP PROCEDURE IF EXISTS add_workflow_columns;

-- ============================================================
-- END OF COMPLETE FEATURE DATABASE
-- ============================================================
