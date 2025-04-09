class APIError(Exception):
    """This exception gets raised whenever a non-200 status code was returned by the Onyphe API."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class ParamError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value
