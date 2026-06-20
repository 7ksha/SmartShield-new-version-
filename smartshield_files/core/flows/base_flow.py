 
 
from dataclasses import dataclass, field


@dataclass(kw_only=True)
class BaseFlow:
    """A base class for zeek flows, containing common fields."""

    interface: str = field(default="default")
