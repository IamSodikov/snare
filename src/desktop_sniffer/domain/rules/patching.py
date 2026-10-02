"""Versioned JSON edits. None means no edit, never a JSON value sentinel."""

import copy

FORMAT_KEY = "__snare_patch__"


def deep_diff(original, edited):
    operations = []

    def visit(before, after, path):
        if isinstance(before, dict) and isinstance(after, dict):
            for key in before.keys() - after.keys():
                operations.append({"op": "remove", "path": path + [key]})
            for key, value in after.items():
                if key not in before:
                    operations.append(
                        {"op": "set", "path": path + [key], "value": value}
                    )
                else:
                    visit(before[key], value, path + [key])
        elif type(before) is not type(after) or before != after:
            operations.append({"op": "set", "path": path, "value": after})

    visit(original, edited, [])
    return {FORMAT_KEY: 2, "operations": operations} if operations else None


def apply_patch(obj, patch):
    if isinstance(patch, dict) and patch.get(FORMAT_KEY) == 2:
        result = copy.deepcopy(obj)
        for operation in patch["operations"]:
            path = operation["path"]
            if not path:
                result = copy.deepcopy(operation["value"])
                continue
            target = result
            for key in path[:-1]:
                if not isinstance(target, dict):
                    raise ValueError("Patch yo‘li object ichida bo‘lishi kerak")
                target = target.setdefault(key, {})
            if not isinstance(target, dict):
                raise ValueError("Patch uchun mos JSON object topilmadi")
            if operation["op"] == "remove":
                target.pop(path[-1], None)
            else:
                target[path[-1]] = copy.deepcopy(operation["value"])
        return result
    # Compatibility with rules created before patch format 2.
    if isinstance(patch, dict) and isinstance(obj, dict):
        result = copy.deepcopy(obj)
        for key, value in patch.items():
            if value == "__SNARE_DELETE_FIELD__":
                result.pop(key, None)
            else:
                result[key] = apply_patch(result.get(key), value)
        return result
    return copy.deepcopy(patch)
