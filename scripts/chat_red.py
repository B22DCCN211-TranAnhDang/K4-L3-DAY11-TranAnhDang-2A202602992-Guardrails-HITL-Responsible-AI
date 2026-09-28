"""
Interactive CLI chat with Red Agent (default - no guardrails).
Chat trực tiếp với con Red yếu (không có bảo mật).
"""
import sys
import asyncio
from pathlib import Path

# Add src/ directory to path
_SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from core.config import setup_api_key
from agents.agent import create_red_agent_default
from core.utils import chat_with_agent


async def main():
    setup_api_key()
    print("=" * 60)
    print("🔴 CHAT TRỰC TIẾP VỚI RED AGENT (KHÔNG CÓ GUARDRAILS)")
    print("=" * 60)
    print("Mô tả: Con Red này chứa secrets trong System Prompt và KHÔNG có rào chắn.")
    print("Gõ 'exit' hoặc 'quit' để thoát.\n")

    agent, runner = create_red_agent_default()

    while True:
        try:
            user_input = input("You > ")
            if not user_input.strip():
                continue
            if user_input.strip().lower() in ("exit", "quit"):
                print("Tạm biệt!")
                break

            response, _ = await chat_with_agent(agent, runner, user_input)
            print(f"\n🔴 Red Agent > {response}\n")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break


if __name__ == "__main__":
    asyncio.run(main())
