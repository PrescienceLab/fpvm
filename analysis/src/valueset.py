class ValueSet:
    def __init__(self, arr):
        self._set = set(arr)

    def __str__(self):
        _str = []
        for i in self._set:
            _str.append(str(hex(i)))
        return ", ".join(_str)

    def __add__(self, vset):
        set_a = self._set
        set_b = vset._set
        new_arr = []
        for a in set_a:
            for b in set_b:
                new_arr.append(a + b)

        return ValueSet(new_arr)

    def __mul__(self, vset):
        set_a = self._set
        set_b = vset._set
        new_arr = []
        for a in set_a:
            for b in set_b:
                new_arr.append(a * b)

        return ValueSet(new_arr)

    def __or__(self, vset):

        return ValueSet(list(self._set | vset._set))
