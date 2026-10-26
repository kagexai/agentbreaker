"""Compatibility shim. The control plane implementation is agentbreaker.control_plane."""

from agentbreaker.control_plane import serve_control_plane


def main() -> None:
    serve_control_plane()


if __name__ == "__main__":
    main()
