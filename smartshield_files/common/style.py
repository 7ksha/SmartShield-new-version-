

class Colorizer:
    """Terminal color utility."""

    @staticmethod
    def green(text: str) -> str:
        return f"\033[92m{text}\033[0m"

    @staticmethod
    def red(text: str) -> str:
        return f"\033[91m{text}\033[0m"

    @staticmethod
    def yellow(text: str) -> str:
        return f"\033[93m{text}\033[0m"

    @staticmethod
    def blue(text: str) -> str:
        return f"\033[94m{text}\033[0m"

    @staticmethod
    def cyan(text: str) -> str:
        return f"\033[96m{text}\033[0m"


def green(text: str) -> str:
    return Colorizer.green(text)


def red(text: str) -> str:
    return Colorizer.red(text)


def yellow(text: str) -> str:
    return Colorizer.yellow(text)


def blue(text: str) -> str:
    return Colorizer.blue(text)


def cyan(text: str) -> str:
    return Colorizer.cyan(text)
