"""Functions used by multiple modules."""

def empty_or_non_array(dict_parent, array_child_name):
    """Is the str the name of a non-empty array within the dict parent?"""
    if array_child_name is None:
        return True
    try:
        return _empty(dict_parent, array_child_name)
    except TypeError:
        return True

def _empty(dict_parent, array_child_name):
    """Is the str the name of a non-empty array within the dict parent?

    Raises a TypeError if the str is the name of a non-array element.
    """
    assert isinstance(array_child_name, str)
    return (array_child_name not in dict_parent or
            len(dict_parent[array_child_name]) == 0)

def iter_items(dict_parent, array_child_name):
    """Get the iterable list of items in the array if they exist."""
    if not empty_or_non_array(dict_parent, array_child_name):
        return dict_parent[array_child_name]
    else:
        return []
