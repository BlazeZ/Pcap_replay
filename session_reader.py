
class SessionReader:

    def __init__(self):
        pass

    def count(self):
        raise NotImplementedError

    def next(self):
        raise NotImplementedError

    def peers(self):
        raise NotImplementedError


