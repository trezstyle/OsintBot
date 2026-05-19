"""Tests for the notifier service."""
import pytest
from unittest.mock import MagicMock, patch


class TestNotifier:
    def test_init_bot(self):
        from services.notifier import init_bot
        mock = MagicMock()
        init_bot(mock)

    def test_send_message_before_init(self):
        from services.notifier import send_message_sync
        send_message_sync(123, "hello")

    @patch("services.notifier._bot", None)
    def test_send_message_no_bot(self):
        from services.notifier import send_message_sync
        send_message_sync(123, "hello")

    @patch("services.notifier._bot")
    def test_send_message_success(self, mock_bot):
        from services.notifier import send_message_sync
        send_message_sync(123, "hello", parse_mode="Markdown")
        mock_bot.send_message.assert_called_once_with(
            123, "hello", parse_mode="Markdown", reply_markup=None
        )

    @patch("services.notifier._bot")
    def test_send_message_with_reply_markup(self, mock_bot):
        from services.notifier import send_message_sync
        markup = MagicMock()
        send_message_sync(123, "text", reply_markup=markup)
        mock_bot.send_message.assert_called_once_with(
            123, "text", parse_mode=None, reply_markup=markup
        )

    @patch("services.notifier._bot")
    def test_send_message_error_handled(self, mock_bot):
        from services.notifier import send_message_sync
        mock_bot.send_message.side_effect = Exception("API error")
        send_message_sync(123, "hello")
