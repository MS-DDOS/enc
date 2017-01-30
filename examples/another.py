from math import ceil

class C(object):
    def __init__(self, x=10):
        self.val = x

    def ceiling_self(self):
        self.val = ceil(self.val)
        return self.val

