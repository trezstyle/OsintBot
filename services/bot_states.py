"""FSM states for interactive bot commands."""
from aiogram.fsm.state import State, StatesGroup


class BotStates(StatesGroup):
    waiting_for_ip = State()
    waiting_for_domain = State()
    waiting_for_scan_fast = State()
    waiting_for_scan_full = State()
    waiting_for_fim_path = State()
    waiting_for_package = State()
    waiting_for_hibp_input = State()
    waiting_for_mitre_technique = State()
    waiting_for_from_table = State()
