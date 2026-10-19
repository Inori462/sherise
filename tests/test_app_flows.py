import unittest
from unittest.mock import MagicMock, patch

import app
from werkzeug.security import generate_password_hash


class ApplicationFlowTests(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True)
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-csrf-token"
            session["user_id"] = 7
            session["role"] = "seller"
            session["full_name"] = "Test Seller"

    def post_json(self, path, payload):
        return self.client.post(
            path,
            json=payload,
            headers={"X-CSRF-Token": "test-csrf-token"}
        )

    def test_all_business_assistant_categories_build_distinct_guidance(self):
        categories = {
            "pricing", "inventory", "customer_service", "government_schemes",
            "roadmap", "finance", "business_plan", "marketing"
        }
        cursor = MagicMock()
        fake_db = MagicMock()
        fake_db.cursor.return_value = cursor

        with (
            patch.object(app, "seller_required", return_value=True),
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "db", fake_db),
            patch.object(app, "local_ai_answer", return_value=("Practical response", "success")) as generate
        ):
            for category in categories:
                response = self.post_json(
                    "/seller/ai-assistant/chat",
                    {"message": "Help with my shop", "category": category}
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["response"], "Practical response")
                self.assertIn(category, generate.call_args.args[0])

        self.assertEqual(generate.call_count, len(categories))
        self.assertTrue(all(
            call.kwargs["fallback_answer"] is None
            for call in generate.call_args_list
        ))

    def test_all_marketing_formats_use_their_specific_guidance(self):
        output_types = set(app.MARKETING_OUTPUT_GUIDANCE)
        cursor = MagicMock()
        fake_db = MagicMock()
        fake_db.cursor.return_value = cursor

        with (
            patch.object(app, "seller_required", return_value=True),
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "db", fake_db),
            patch.object(app, "local_ai_answer", return_value=("Generated copy", "success")) as generate
        ):
            for output_type in output_types:
                response = self.post_json("/seller/marketing/generate", {
                    "output_type": output_type,
                    "product_name": "Handmade tote",
                    "description": "Cotton tote made by hand.",
                    "price": "",
                    "target_audience": "Local shoppers",
                    "offer": "",
                    "festival": "Diwali",
                    "platform": "Instagram",
                    "tone": "Friendly",
                    "language": "English",
                    "placement": ""
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["content"], "Generated copy")
                self.assertIn(output_type, generate.call_args.args[0])

        self.assertEqual(generate.call_count, len(output_types))
        self.assertTrue(all(
            call.kwargs["fallback_answer"] is None
            for call in generate.call_args_list
        ))

    def test_ai_routes_reject_invalid_inputs_before_generation(self):
        with (
            patch.object(app, "seller_required", return_value=True),
            patch.object(app, "local_ai_answer") as generate
        ):
            invalid_category = self.post_json(
                "/seller/ai-assistant/chat",
                {"message": "Help", "category": "unknown"}
            )
            invalid_format = self.post_json(
                "/seller/marketing/generate",
                {"output_type": "unsupported"}
            )

        self.assertEqual(invalid_category.status_code, 400)
        self.assertEqual(invalid_format.status_code, 400)
        generate.assert_not_called()

    def test_marketing_rejects_oversized_or_missing_product_information(self):
        with (
            patch.object(app, "seller_required", return_value=True),
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "db", MagicMock()),
            patch.object(app, "local_ai_answer") as generate
        ):
            oversized = self.post_json("/seller/marketing/generate", {
                "output_type": "instagram_post",
                "product_name": "x" * 151,
                "description": "Details"
            })
            missing = self.post_json("/seller/marketing/generate", {
                "output_type": "instagram_post",
                "product_name": "",
                "description": ""
            })

        self.assertEqual(oversized.status_code, 400)
        self.assertEqual(missing.status_code, 400)
        generate.assert_not_called()

    def test_business_assistant_reports_local_model_unavailable_without_fallback(self):
        cursor = MagicMock()
        fake_db = MagicMock()
        fake_db.cursor.return_value = cursor

        with (
            patch.object(app, "seller_required", return_value=True),
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "db", fake_db),
            patch("app.requests.post", side_effect=app.requests.ConnectionError("offline"))
        ):
            response = self.post_json(
                "/seller/ai-assistant/chat",
                {"message": "How should I plan inventory?", "category": "inventory"}
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("ollama pull", response.get_json()["error"])
        self.assertEqual(cursor.execute.call_args.args[1][2], "unavailable")

    def test_local_ai_success_and_optional_buyer_faq_fallback(self):
        response = MagicMock()
        response.json.return_value = {"message": {"content": "Locally generated answer"}}
        with app.app.test_request_context("/"):
            with (
                patch.object(app, "OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
                patch("app.requests.post", return_value=response)
            ):
                answer, state = app.local_ai_answer(
                    "Question",
                    "System prompt",
                    fallback_answer=None
                )
            self.assertEqual((answer, state), ("Locally generated answer", "success"))

            with patch("app.requests.post", side_effect=app.requests.ConnectionError("offline")):
                answer, state = app.local_ai_answer("Where is my order?", "System prompt")
            self.assertEqual(state, "faq_fallback")
            self.assertTrue(answer)

    def test_invalid_password_message_is_exact_and_non_specific(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        fake_db = MagicMock()
        fake_db.cursor.return_value = cursor
        with (
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "login_locked", return_value=False),
            patch.object(app, "register_failed_login"),
            patch.object(app, "db", fake_db)
        ):
            response = self.client.post("/login", data={
                "email": "user@example.invalid",
                "password": "wrong-password",
                "_csrf_token": "test-csrf-token"
            })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incorrect email or password.", response.data)
        self.assertNotIn(b"Invalid email or password.", response.data)

    def test_google_callback_validates_state_and_uses_database_role(self):
        with self.client.session_transaction() as session:
            session["google_oauth_state"] = "expected-state"
            session["google_oauth_mode"] = "login"

        token_response = MagicMock()
        token_response.json.return_value = {"access_token": "test-access-token"}
        user_response = MagicMock()
        user_response.json.return_value = {
            "email": "buyer@example.invalid",
            "email_verified": True,
            "name": "Test Buyer"
        }
        cursor = MagicMock()
        cursor.fetchone.return_value = {
            "id": 11,
            "full_name": "Database Buyer",
            "email": "buyer@example.invalid",
            "password": generate_password_hash("not-used"),
            "role": "buyer"
        }
        fake_db = MagicMock()
        fake_db.cursor.return_value = cursor

        with (
            patch.object(app, "ensure_db_connection"),
            patch.object(app, "clear_failed_logins"),
            patch.object(app, "db", fake_db),
            patch("app.requests.post", return_value=token_response),
            patch("app.requests.get", return_value=user_response)
        ):
            response = self.client.get("/google/callback?code=test-code&state=expected-state")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/buyer/dashboard"))
        with self.client.session_transaction() as session:
            self.assertEqual(session["role"], "buyer")
            self.assertEqual(session["user_id"], 11)
            self.assertTrue(session.permanent)

    def test_google_callback_rejects_invalid_state(self):
        with self.client.session_transaction() as session:
            session["google_oauth_state"] = "expected-state"

        with patch("app.requests.post") as provider_request:
            response = self.client.get("/google/callback?code=test-code&state=wrong-state")

        self.assertEqual(response.status_code, 400)
        provider_request.assert_not_called()

    def test_templates_render_latest_tool_results_and_order_items(self):
        with app.app.test_request_context("/"):
            assistant = app.render_template(
                "seller/ai_assistant.html",
                products=[],
                latest_answer="Saved assistant advice"
            )
            marketing = app.render_template(
                "seller/marketing.html",
                products=[],
                latest_output_type="instagram_post",
                latest_content="Saved marketing copy"
            )
            orders = app.render_template("buyer/orders.html", orders=[{
                "id": 19,
                "items": [{
                    "name": "Handmade product",
                    "quantity": 2,
                    "unit_price": 10,
                    "subtotal": 20
                }],
                "status": "pending",
                "total_amount": 20,
                "shipping_address": "Test address",
                "payment_method": "Cash on Delivery",
                "payment_status": "pending",
                "created_at": None
            }])

        self.assertIn("Saved assistant advice", assistant)
        self.assertIn("Saved marketing copy", marketing)
        self.assertIn("Handmade product", orders)
        self.assertIn("Order #19", orders)


if __name__ == "__main__":
    unittest.main()
