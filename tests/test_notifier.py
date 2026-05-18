"""Tests for the notifier service."""
from unittest.mock import MagicMock, patch

import pytest

from services.notifier import init_bot, send_message


class TestNotifier:
    def test_init_bot(self):
        mock = MagicMock()
        init_bot(mock)
        # After init, send_message should use this bot
        assert True  # no crash

    def test_send_message_before_init(self):
        """send_message before init_bot should not crash."""
        send_message(123, "hello")

    @patch("services.notifier._bot", None)
    def test_send_message_no_bot(self):
        send_message(123, "hello")  # should log warning, not crash

    @patch("services.notifier._bot")
    def test_send_message_success(self, mock_bot):
        mock_bot.send_message.return_value = "ok"
        send_message(123, "hello", parse_mode="Markdown")
        mock_bot.send_message.assert_called_once_with(
            123, "hello", parse_mode="Markdown", reply_markup=None
        )

    @patch("services.notifier._bot")
    def test_send_message_with_reply_markup(self, mock_bot):
        markup = MagicMock()
        send_message(123, "text", reply_markup=markup)
        mock_bot.send_message.assert_called_once_with(
            123, "text", parse_mode=None, reply_markup=markup
        )

    @patch("services.notifier._bot")
    def test_send_message_error_handled(self, mock_bot):
        mock_bot.send_message.side_effect = Exception("API error")
        send_message(123, "hello")  # should log exception, not crash
