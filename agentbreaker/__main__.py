"""`python -m agentbreaker` launches the control plane (web product entrypoint).

The operator CLI was removed; AgentBreaker Enterprise is driven through the web UI.
Campaigns are launched by the control plane via `python -m agentbreaker.campaign`.
"""
from agentbreaker.control_plane import main

if __name__ == "__main__":
    raise SystemExit(main())
