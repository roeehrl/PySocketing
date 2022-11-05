#decorators

class lazy_property(object): 
    """creates a decorator taking a return value of the method upon set and creates a property of it to the method object """
    def __init__(self, function):
        self.fget = function
    def __get__(self, obj, cls):
        value = self.fget(obj)
        setattr(obj, self.fget.__name__, value)
        return value