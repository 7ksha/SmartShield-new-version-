

from smartshield_files.common.abstracts.imodule import IModule


class AsyncModule(IModule):
    """Abstract async module interface. Modules that need async support inherit this."""

    name = "AsyncModule"
    description = "Async-capable module base"

    async def main(self):
        """Override with async main logic."""

    async def init(self):
        """Override with async init logic."""
