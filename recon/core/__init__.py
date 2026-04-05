from recon.core.config_loader import AppConfig, load_config

__all__ = ["AppConfig", "load_config", "PipelineEngine"]


def __getattr__(name: str):
    """Lazy import so `recon.core.logger` (etc.) does not pull `engine` before `registry` is ready."""
    if name == "PipelineEngine":
        from recon.core.engine import PipelineEngine

        return PipelineEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
