class AccountAlreadyExistsException(Exception):
    def __init__(self, message="Account already exists"):
        super().__init__(message)


class BadCredentialsException(Exception):
    def __init__(self, message="Bad credentials"):
        super().__init__(message)


class ForbiddenException(Exception):
    def __init__(self, message="Forbidden"):
        super().__init__(message)
